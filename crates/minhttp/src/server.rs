// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`Server`]-related things

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use futures::{FutureExt, Stream, StreamExt};
use hyper::body::{Body, Incoming};
use hyper::server::conn::http1;
use hyper::service::{service_fn, HttpService};
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::select;
use tokio::sync::{watch, Semaphore};
use tokio::time::sleep;
use tracing::{error, info, info_span, warn, Instrument, Span};

use crate::nursery::Nursery;
use crate::response::GenericResponse;

/// Errors that can occur while serving a connection
#[derive(thiserror::Error, Debug)]
pub enum ConnectionError {
    /// Indicates the server was unable to accept a connection.
    #[error("could not accept connection: {0}")]
    Accept(#[from] std::io::Error),
    /// Indicates the server could not properly handle a new connection due to it having too many
    /// ongoing requests.
    #[error("too overloaded to serve {peer_addr}")]
    Overloaded {
        /// Connection's peer IP address and port
        peer_addr: SocketAddr,
    },
    /// Indicates the server encountered an error while attempting to serve HTTP to a request.
    #[error("error serving {peer_addr} connection: {source}")]
    Http {
        /// Connection's peer IP address and port
        peer_addr: SocketAddr,
        /// Underlying cause
        source: hyper::Error,
    },
}

/// Serves HTTP connections while allowing for graceful shutdowns.
pub struct Server {
    concurrent_requests: Arc<Semaphore>,
    shutdown: watch::Sender<bool>,
}

impl Server {
    /// Create a new [`Server`].
    ///
    /// `max_connections` is the maximum number of simultaneous connections that may be handled
    /// across all [`serve`](Self::serve) calls before they start responding with 503s.
    pub fn new(max_connections: usize) -> Self {
        let concurrent_requests = Arc::new(Semaphore::new(max_connections));
        let (shutdown, _) = watch::channel(false);
        Self {
            concurrent_requests,
            shutdown,
        }
    }

    /// Serve incoming `connections` with `responder`.
    ///
    /// `connections` is a stream of connection-like objects, and `responder` maps HTTP requests
    /// to responses. Each connection is handled in its own asynchronous task.
    /// [`serve`](Self::serve) will resolve after [`graceful_shutdown`](Self::graceful_shutdown)
    /// has been called (or `connections` is exhausted) and this invocation has no ongoing
    /// connections.
    ///
    /// If the [`Server`] is already at its `max_connections` limit (see [`new`](Self::new)),
    /// new connections will be served with a single minimal 503 response.
    ///
    /// If [`graceful_shutdown`](Self::graceful_shutdown) is called, `connections` will be
    /// dropped before waiting for in-progress connections to finish up.
    ///
    /// # Cancel Safety
    ///
    /// Cancellation will be propagated to all connections handled by this call to
    /// [`serve`](Self::serve) and will block until they all terminate. Connections handled
    /// by other [`serve`](Self::serve) calls are unaffected. Canceling a connection
    /// typically means abruptly closing it, and usually shouldn't take long.
    pub async fn serve<P, C, R, F>(&self, connections: P, responder: R)
    where
        P: Stream<Item = std::io::Result<(C, SocketAddr)>>,
        C: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        R: Fn(Request<Incoming>, SocketAddr) -> F + Clone + Send + Sync + 'static,
        F: Future<Output = GenericResponse> + Send + Sync,
    {
        self.with_callbacks()
            .respond(responder)
            .serve(connections)
            .await
    }

    /// Configure additional callbacks before serving connections.
    ///
    /// This is like [`serve`](Server::serve) except it returns a [`Callbacks`] builder that
    /// allows configuring additional callbacks to assist with metrics/monitoring:
    ///
    /// * [`respond`](Callbacks::respond) is the same as the `responder` argument of
    ///   [`Server::serve`].
    /// * [`connected`](Callbacks::connected) is called at the start of new connections.
    /// * [`failed`](Callbacks::failed) is called when a connection fails.
    /// * [`disconnected`](Callbacks::disconnected) is called when a connection ends.
    pub fn with_callbacks(&self) -> Callbacks {
        Callbacks {
            server: self,
            respond: MissingResponder,
            connected: drop,
            failed: drop,
            disconnected: drop,
        }
    }

    /// Gracefully shuts down server.
    ///
    /// New calls to [`serve`](Self::serve) resolve immediately without handling new connections.
    /// Existing calls to [`serve`](Self::serve) drop their stream of connections, then wait for
    /// their ongoing connections finish before resolving. All connections terminate as soon as
    /// their current request finishes (idle connections are terminated immediately).
    /// [`graceful_shutdown`](Self::graceful_shutdown) resolves as soon all current calls to
    /// [`serve`](Self::serve) are resolved or aborted.
    ///
    /// # Cancel Safety
    ///
    /// After this has been polled, canceling does not stop the shutdown.
    pub async fn graceful_shutdown(&self) {
        // Inform all requests that a graceful shutdown has been requested
        self.shutdown.send_replace(true);
        // Ensures we exit all serve() calls, not just finish requests.
        self.shutdown.closed().await;
    }
}

/// Cheaply responds to an HTTP 1 connection with a minimal 503.
async fn respond_with_temporarily_unavailable(
    mut connection: impl AsyncWriteExt + Unpin,
) -> std::io::Result<()> {
    // If we're overloaded, I really don't want to spend memory spinning up any more tasks.
    // In order to avoid being bogged down by a slow client, we'll skip parsing the request
    // and just preemptively supply a minimal response, which I think is allowed by RFC 9110
    // section 7.5, and we don't wait long for the response to finish; hopefully it'll be
    // small enough to fit in a single buffer/packet/whatever.
    let write_response = async {
        let msg = b"HTTP/1.1 503 Service Unavailable\r\n\
                    Content-Type: text/plain;charset=utf-8\r\n\
                    Content-Length: 22\r\n\
                    \r\n\
                    Too many connections!\n";
        connection.write_all(msg).await?;
        connection.shutdown().await
    };
    select! {
         result = write_response => result,
         _ = sleep(Duration::from_secs(1)) => Err(std::io::ErrorKind::TimedOut.into()),
    }
}

/// Gracefully terminate `connection` if `want_shutdown` resolves.
async fn with_graceful_shutdown<I, S, B>(
    connection: http1::Connection<I, S>,
    want_shutdown: impl Future,
) -> Result<(), hyper::Error>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + 'static,
    S: HttpService<Incoming, ResBody = B>,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    B: Body + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    // Sadly, both polling a connection and gracefully shutting it down require exclusive
    // access, so we have to manually call them in poll_fn.
    let mut connection = pin!(connection);
    let mut want_shutdown = pin!(want_shutdown.fuse());
    std::future::poll_fn(|cx| {
        if want_shutdown.as_mut().poll(cx).is_ready() {
            connection.as_mut().graceful_shutdown();
        }
        connection.as_mut().poll(cx)
    })
    .await
}

// Small enough code that I don't want to bother pulling in scopeguard
struct Guard<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> Drop for Guard<F> {
    fn drop(&mut self) {
        if let Some(callback) = self.0.take() {
            callback();
        }
    }
}

/// Indicates that [`Callbacks::respond`] wasn't set.
///
/// If you stumble across this, it probably means you attempted to use [`Server::with_callbacks`]
/// but forgot to use [`Callbacks::respond`] before [`Callbacks::serve`].
#[derive(Clone)] // Satisfying Clone simplifies error messages
pub struct MissingResponder;

/// Holds setup for serving a connection with additional callbacks.
pub struct Callbacks<
    'a,
    R = MissingResponder,
    C = fn(SocketAddr),
    F = fn(ConnectionError),
    D = fn(()),
> {
    server: &'a Server,
    respond: R,
    connected: C,
    failed: F,
    disconnected: D,
}

impl<'a, R, C, F, D> Callbacks<'a, R, C, F, D> {
    /// Set request handler.
    pub fn respond<NewR, RFut>(self, respond: NewR) -> Callbacks<'a, NewR, C, F, D>
    where
        NewR: Fn(Request<Incoming>, SocketAddr) -> RFut + Clone + Send + Sync + 'static,
        RFut: Future<Output = GenericResponse> + Send,
    {
        Callbacks {
            server: self.server,
            respond,
            connected: self.connected,
            failed: self.failed,
            disconnected: self.disconnected,
        }
    }

    /// Set connection callback.
    ///
    /// This is called as soon as a connection is established, and its return value will be held
    /// for the duration of the connection, then passed to the
    /// [`disconnected`](Callbacks::disconnected) callback.
    ///
    /// *Beware that setting this clears [`disconnected`](Callbacks::disconnected).*
    pub fn connected<NewC, G>(self, connected: NewC) -> Callbacks<'a, R, NewC, F, fn(G)>
    where
        NewC: FnMut(SocketAddr) -> G,
        G: Send + 'static,
    {
        Callbacks {
            server: self.server,
            respond: self.respond,
            connected,
            failed: self.failed,
            disconnected: drop,
        }
    }

    /// Set connection failure callback.
    ///
    /// This is called when a connection failure occurs. Note that if an error occurs while
    /// accepting a connection, this may be called without the [`connected`](Callbacks::connected)
    /// callback ever being invoked.
    pub fn failed<NewF>(self, failed: NewF) -> Callbacks<'a, R, C, NewF, D>
    where
        NewF: FnOnce(ConnectionError) + Clone + Send + 'static,
    {
        Callbacks {
            server: self.server,
            respond: self.respond,
            connected: self.connected,
            failed,
            disconnected: self.disconnected,
        }
    }

    /// Set disconnection callback.
    ///
    /// This is called as soon as a connection ends, ans is passed the value returned from the
    /// [`connected`](Callbacks::connected) callback.
    ///
    /// *Beware that setting [`connected`](Callbacks::connected) clears this.*
    pub fn disconnected<NewD, G>(self, disconnected: NewD) -> Callbacks<'a, R, C, F, NewD>
    where
        C: FnMut(SocketAddr) -> G,
        NewD: FnOnce(G) + Clone + Send + 'static,
    {
        Callbacks {
            server: self.server,
            respond: self.respond,
            connected: self.connected,
            failed: self.failed,
            disconnected,
        }
    }

    /// Serve `connections`.
    ///
    /// This returns a future that will begin iterating over `connections` and serving them
    /// with the configured callbacks. See [`Server::serve`] for more details.
    pub async fn serve<ConnS, Conn, RFut, G>(self, connections: ConnS)
    where
        ConnS: Stream<Item = std::io::Result<(Conn, SocketAddr)>>,
        Conn: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        R: Fn(Request<Incoming>, SocketAddr) -> RFut + Clone + Send + Sync + 'static,
        RFut: Future<Output = GenericResponse> + Send,
        C: FnMut(SocketAddr) -> G,
        F: FnOnce(ConnectionError) + Clone + Send + 'static,
        D: FnOnce(G) + Clone + Send + 'static,
        G: Send + 'static,
    {
        let Self {
            server,
            respond,
            mut connected,
            failed,
            disconnected,
        } = self;

        let respond = move |request: Request<_>, peer_addr| {
            let respond = respond.clone();
            async move {
                info!("Request: {} {}", request.method(), request.uri());
                let response = respond(request, peer_addr).await;
                info!("Response: {}", response.status());
                response
            }
        };

        // This shutdown receiver is what keeps graceful_shutdown from returning so
        // we need it to be the first thing created so it's the last thing destroyed.
        let mut shutdown_receiver = server.shutdown.subscribe();
        let mut was_shutdown = pin!(shutdown_receiver.wait_for(|&done| done).map(|_| None));

        async fn either<T>(f1: impl Future<Output = T>, f2: impl Future<Output = T>) -> T {
            select! {
                biased; // necessary to guarantee we don't handle connections if already shut down
                x1 = f1 => x1,
                x2 = f2 => x2,
            }
        }

        let mut nursery = Nursery::new();

        info!("Started serving");

        // scope is only to force `connections` to  be dropped
        {
            let mut connections = pin!(connections);
            while let Some(accepted) = either(&mut was_shutdown, connections.next()).await {
                let (connection, peer_addr) = match accepted {
                    Ok(a) => a,
                    Err(err) => {
                        let err = ConnectionError::from(err);
                        error!("Couldn't accept connection: {err}");
                        failed.clone()(err);
                        continue;
                    }
                };

                let connection_span = info_span!("connection", addr=%peer_addr);
                async {
                    info!("Connected.");
                    let log_guard = Guard(Some(|| info!("Disconnected.")));
                    let connection_metric = connected(peer_addr);
                    let disconnected = disconnected.clone();
                    let metric_guard = Guard(Some(|| disconnected(connection_metric)));

                    let permit = match server.concurrent_requests.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            warn!("Too overloaded; sending minimal 503.");
                            let _ = respond_with_temporarily_unavailable(connection).await;
                            let err = ConnectionError::Overloaded { peer_addr };
                            failed.clone()(err);
                            return;
                        }
                    };

                    let failed = failed.clone();
                    let respond = respond.clone();
                    let service =
                        service_fn(move |r| respond(r, peer_addr).map(Ok::<_, Infallible>));
                    let mut shutdown_receiver = server.shutdown.subscribe();
                    let connection_task = async move {
                        let wants_shutdown = shutdown_receiver.wait_for(|&done| done);
                        let _permit = permit;
                        let _log_guard = log_guard;
                        let _metric_guard = metric_guard;

                        let http_connection = http1::Builder::new()
                            .half_close(true) // Might be useful for streaming stuff?
                            // TODO: header read timeouts
                            .serve_connection(TokioIo::new(connection), service);
                        let http_connection =
                            with_graceful_shutdown(http_connection, wants_shutdown);

                        if let Err(err) = http_connection.await {
                            error!("Error serving: {err}");
                            let err = ConnectionError::Http {
                                peer_addr,
                                source: err,
                            };
                            failed(err);
                        }
                    };
                    tokio::task::spawn(
                        nursery
                            .chaperone(connection_task)
                            .instrument(Span::current()),
                    );
                }
                .instrument(connection_span.or_current())
                .await;
            }
        }

        nursery.finish().await;
        info!("Stopped serving");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;
    use std::task::Poll;

    use http_body_util::BodyExt;
    use hyper::Response;
    use tokio::io::AsyncReadExt;
    use tokio::sync::mpsc::{self, error::TryRecvError};

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn smoke_test() {
        let (connections_tx, mut connections_rx) = mpsc::channel(4);
        let connections = futures::stream::poll_fn(|cx| connections_rx.poll_recv(cx));
        let new_connection = || async {
            let (client, server) = tokio::io::duplex(1024);
            let address = SocketAddr::from(([0, 0, 0, 0], 8080));
            connections_tx.send(Ok((server, address))).await.unwrap();
            client
        };

        let max_connections = 2;
        let server = Server::new(max_connections);

        let run = server.serve(connections, |request, _| async {
            let body = request.into_body().map_err(|err| err.into()).boxed();
            Response::new(body)
        });

        let tests = async {
            // Start to send one request...
            let mut client0 = new_connection().await;
            let msg1 = b"POST / HTTP/1.1\r\nHost: foo.com\r\nContent-Length: 23\r\n\r\n";
            let msg2 = b"This is a slow message.";
            client0.write_all(msg1).await.unwrap();

            // Start to send a second...
            let mut client1 = new_connection().await;
            let msg =
                b"POST / HTTP/1.1\r\nHost: foo.com\r\nContent-Length: 13\r\n\r\nHello, world!\r\n";
            client1.write_all(msg).await.unwrap();
            client1.shutdown().await.unwrap();
            let mut response = String::new();
            client1.read_to_string(&mut response).await.unwrap();
            dbg!(&response);
            assert!(response.starts_with("HTTP/1.1 200 "));
            assert!(response.ends_with("\r\n\r\nHello, world!"));

            // Finish sending the first.
            client0.write_all(msg2).await.unwrap();
            client0.shutdown().await.unwrap();
            let mut response = String::new();
            client0.read_to_string(&mut response).await.unwrap();
            dbg!(&response);
            assert!(response.starts_with("HTTP/1.1 200 "));
            assert!(response.ends_with("\r\n\r\nThis is a slow message."));
        };

        tokio::select! {
            _ = run => {}
            _ = tests => {}
        }
    }

    // We want graceful shutdown to cause a server to stop listening for new connections ASAP,
    // so a new server can immediately start serving the same address/port, minimizing downtime.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn connections_are_dropped_early_in_graceful_shutdown() {
        let (connections_tx, mut connections_rx) = mpsc::channel(4);
        let connections = futures::stream::poll_fn(move |cx| connections_rx.poll_recv(cx));

        let max_connections = 2;
        let server = Server::new(max_connections);
        let run = async {
            server
                .serve(connections, |_, _| futures::future::pending())
                .await;
            panic!("Graceful shutdown shouldn't complete in this test");
        };

        let test = async {
            let conn_buf_size = 4; // tiny to force the server to read what we send it
            let (mut client_connection, server_connection) = tokio::io::duplex(conn_buf_size);
            let address = SocketAddr::from(([0, 0, 0, 0], 8080));
            connections_tx
                .send(Ok((server_connection, address)))
                .await
                .unwrap();

            client_connection
                .write_all(b"GET / HTTP/1.1\r\n")
                .await
                .unwrap();

            assert!(!connections_tx.is_closed());
            assert!(
                server.graceful_shutdown().now_or_never().is_none(),
                "Graceful shutdown shouldn't complete due to the in-progress request"
            );
            tokio::task::yield_now().await; // give server a chance to start cleanup
            assert!(connections_tx.is_closed());
        };

        tokio::select! {
            // We want the server to make as much progress as possible between yields of the
            // `test` async block, so we make this biased.
            biased;
            _ = run => {}
            _ = test => {}
        };
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn shutdown_servers_do_not_accept_connections() {
        let dummy_connection = Cursor::new(vec![]);
        let address = SocketAddr::from(([0, 0, 0, 0], 8080));
        let mut connection_accepted = false;
        let connections = futures::stream::once(async {
            connection_accepted = true;
            Ok((dummy_connection, address))
        });

        let max_connections = 2;
        let server = Server::new(max_connections);
        server.graceful_shutdown().await;

        server
            .serve(connections, |_, _| async { unimplemented!() })
            .await;
        assert!(!connection_accepted);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn overloaded_servers_respond_with_503() {
        let (c0, s0) = tokio::io::duplex(1024);
        let (c1, s1) = tokio::io::duplex(1024);
        let (c2, s2) = tokio::io::duplex(1024);
        let mut client_conns = [c0, c1, c2];
        let server_conns = [s0, s1, s2];

        for c in &mut client_conns {
            let msg = b"GET / HTTP/1.1\r\nHost: foo.com\r\n\r\n";
            c.write_all(msg).await.unwrap();
            c.shutdown().await.unwrap();
        }

        let address = SocketAddr::from(([0, 0, 0, 0], 8080));
        let connections = futures::stream::iter(server_conns.map(|c| Ok((c, address))));

        let tests = async {
            assert!(
                client_conns[0]
                    .read_to_string(&mut String::new())
                    .now_or_never()
                    .is_none(),
                "First connection's response is still pending"
            );

            assert!(
                client_conns[1]
                    .read_to_string(&mut String::new())
                    .now_or_never()
                    .is_none(),
                "Second connection's response is still pending"
            );

            let mut response = String::new();
            client_conns[2].read_to_string(&mut response).await.unwrap();
            dbg!(&response);
            assert!(
                response.starts_with("HTTP/1.1 503"),
                "Third connection got 503 response"
            );
        };

        let max_connections = 2;
        let server = Server::new(max_connections);

        tokio::select! {
            _ = server.serve(connections, |_, _| futures::future::pending()) => {}
            _ = tests => {}
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn connections_errors_shouldnt_panic() {
        type Connection = Cursor<Vec<u8>>;
        let connections = futures::stream::once(async {
            Err::<(Connection, _), _>(std::io::ErrorKind::ConnectionAborted.into())
        });

        let max_connections = 2;
        let server = Server::new(max_connections);
        server
            .serve(connections, |_, _| futures::future::pending())
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn graceful_shutdown_halts_connections_between_requests() {
        let all = async {
            let conn_buf_size = 4; // tiny to force the server to read what we send it
            let (client_conn, server_conn) = tokio::io::duplex(conn_buf_size);
            let connections = futures::stream::once(async {
                let address = SocketAddr::from(([0, 0, 0, 0], 8080));
                Ok((server_conn, address))
            });

            let max_connections = 2;
            let server = Server::new(max_connections);

            let run = server.serve(connections, |request, _| async {
                let body = request.into_body().map_err(|err| err.into()).boxed();
                Response::new(body)
            });

            let (mut reader, mut writer) = tokio::io::split(client_conn);

            let writing_tests = async {
                writer.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
                assert!(server.graceful_shutdown().now_or_never().is_none());
                // Still in the middle of a request, so graceful shutdown shouldn't complete.

                // ...finishing the request and...
                writer.write_all(b"Host: foo.com\r\n\r\n").await.unwrap();

                // ...now that the request is over, the server should have ended the connection
                let err = writer
                    .write_all(b"GET / HTTP/1.1\r\nHost: foo.com\r\n\r\n")
                    .await
                    .unwrap_err();
                assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
            };

            let reading_tests = async {
                let mut responses = String::new();
                reader.read_to_string(&mut responses).await.unwrap();

                dbg!(&responses);
                assert_eq!(responses.matches("HTTP/1.1 ").count(), 1);
            };

            tokio::join!(run, writing_tests, reading_tests);
        };

        // This is important. This test depends on the client and server being interleaved
        // in order to force the server to be polled multiple times, so it has a chance to
        // detect graceful shutdown before the first request finishes. However, the function
        // annotated with #[tokio::test] counts against the blocking thread limit, not the
        // worker thread limit, so we need to put everything inside a spawned task if we
        // want to force interleaving.
        tokio::task::spawn(all).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn connection_established_metric_matches_connection_lifetime() {
        let (sender, mut receiver) = mpsc::channel(10);

        let address0 = SocketAddr::from(([0, 0, 0, 0], 8080));
        let (mut client_conn0, server_conn0) = tokio::io::duplex(16);
        let address1 = SocketAddr::from(([1, 1, 1, 1], 8181));
        let (mut client_conn1, server_conn1) = tokio::io::duplex(16);

        let sender2 = sender.clone();
        let mut connections = [(server_conn0, address0), (server_conn1, address1)].into_iter();
        let connections = futures::stream::poll_fn(move |_cx| {
            let next = connections.next();
            if let Some((_s, addr)) = next.as_ref() {
                sender2.try_send(("connected", *addr)).unwrap();
            }
            Poll::Ready(next.map(Ok))
        });

        let max_connections = 2;
        let server = Server::new(max_connections);

        let sender2 = sender.clone();
        let service = server
            .with_callbacks()
            .respond(|_, _| futures::future::pending())
            .connected(|addr| {
                sender.try_send(("logged connection", addr)).unwrap();
                addr
            })
            .disconnected(move |addr| {
                sender2.try_send(("logged disconnection", addr)).unwrap();
            })
            .serve(connections);

        let tests = async {
            assert_eq!(receiver.recv().await, Some(("connected", address0)));
            assert_eq!(receiver.recv().await, Some(("logged connection", address0)));
            assert_eq!(receiver.recv().await, Some(("connected", address1)));
            assert_eq!(receiver.recv().await, Some(("logged connection", address1)));
            assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
            client_conn1.shutdown().await.unwrap();
            assert_eq!(
                receiver.recv().await,
                Some(("logged disconnection", address1))
            );
            assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
            client_conn0.shutdown().await.unwrap();
            assert_eq!(
                receiver.recv().await,
                Some(("logged disconnection", address0))
            );
            assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
            server.graceful_shutdown().await;
        };

        tokio::join!(service, tests);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn connection_failed_metric_is_notified_of_accept_errors() {
        type Connection = Cursor<Vec<u8>>;
        let connections = futures::stream::once(async {
            Err::<(Connection, _), _>(std::io::ErrorKind::ConnectionAborted.into())
        });

        let max_connections = 2;
        let server = Server::new(max_connections);

        let (err_sender, mut err_receiver) = mpsc::channel(2);
        server
            .with_callbacks()
            .respond(|_, _| futures::future::pending())
            .failed(move |err| {
                err_sender.try_send(err).unwrap();
            })
            .serve(connections)
            .await;

        let io_err = match err_receiver.recv().await.unwrap() {
            ConnectionError::Accept(err) => err,
            _ => panic!("didn't get Accept err"),
        };
        assert_eq!(io_err.kind(), std::io::ErrorKind::ConnectionAborted);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn connection_failed_metric_is_notified_of_overload_errors() {
        let mut conn_ids = 0..3;
        let mut clients = vec![]; // hold to prevent closing connections
        let connections = futures::stream::poll_fn(|_cx| {
            Poll::Ready(conn_ids.next().map(|i| {
                let addr = SocketAddr::from(([i, i, i, i], 8080));
                let (client_conn, server_conn) = tokio::io::duplex(256);
                clients.push(client_conn);
                Ok((server_conn, addr))
            }))
        });

        let max_connections = 2;
        let server = Server::new(max_connections);

        let (err_sender, mut err_receiver) = mpsc::channel(2);
        let service = server
            .with_callbacks()
            .respond(|_, _| futures::future::pending())
            .failed(move |err| {
                err_sender.try_send(err).unwrap();
            })
            .serve(connections);

        let tests = async {
            let peer_addr = match err_receiver.recv().await.unwrap() {
                ConnectionError::Overloaded { peer_addr } => peer_addr,
                _ => panic!("didn't get Overloaded err"),
            };
            assert_eq!(peer_addr, SocketAddr::from(([2, 2, 2, 2], 8080)));
            server.graceful_shutdown().await;
        };

        tokio::join!(service, tests);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn connection_failed_metric_is_notified_of_http_errors() {
        let connections = futures::stream::once(async {
            let connection = Cursor::new(b"invalid request\r\n".to_vec());
            let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
            Ok((connection, addr))
        });

        let max_connections = 2;
        let server = Server::new(max_connections);

        let (err_sender, mut err_receiver) = mpsc::channel(2);
        server
            .with_callbacks()
            .respond(|_, _| futures::future::pending())
            .failed(move |err| {
                err_sender.try_send(err).unwrap();
            })
            .serve(connections)
            .await;

        let (peer_addr, source) = match err_receiver.recv().await.unwrap() {
            ConnectionError::Http { peer_addr, source } => (peer_addr, source),
            _ => panic!("didn't get Http err"),
        };
        assert_eq!(peer_addr, SocketAddr::from(([0, 0, 0, 0], 8080)));
        assert!(source.is_parse());
    }
}
