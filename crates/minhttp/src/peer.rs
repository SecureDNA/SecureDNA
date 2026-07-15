// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::net::SocketAddr;
use std::pin::pin;
use std::time::{Duration, Instant};

use futures::FutureExt;
use hyper::body::{Body, Incoming};
use hyper::server::conn::http1;
use hyper::service::HttpService;
use tokio::sync::watch;
use tracing::warn;

use crate::server::ConnectionError;

// Unfortunately, this is tightly integrated with `tokio`, but that makes it a LOT easier to test
// without needing to create my own dependency injection for time.

/// Handle that request handlers can use to talk about an incoming connection.
#[derive(Clone)]
pub struct Peer {
    timeouts: watch::Sender<Deadlines>,
    addr: SocketAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Deadlines {
    soft: Deadline,
    hard: Deadline,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Deadline {
    /// The timeout should occur ASAP. With hard timeouts, this should immediately cause the
    /// connection to stop scheduling further execution time to the response handler.
    /// Note that once a timeout is `Now`, it cannot be changed, so that graceful shutdowns
    /// and disconnects cannot be canceled by `Peer::relax_timeouts`.
    Now,
    /// Timeout is disabled.
    Never,
    /// Timeout is enabled.
    When(Instant),
}

impl Peer {
    pub(crate) fn new(addr: SocketAddr) -> Self {
        let (timeouts, _) = watch::channel(Deadlines {
            soft: Deadline::Never,
            hard: Deadline::Never,
        });
        Self { timeouts, addr }
    }

    /// Address of incoming connection.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Sets timeouts.
    ///
    /// This can be used to shorten timeouts.
    ///
    /// Note that `None` disables a timeout entirely (but still sets it).
    pub fn set_timeouts(&self, timeouts: Timeouts) {
        let [soft, hard] = timeouts.to_soft_and_hard_instants();
        self.timeouts
            .send_if_modified(|old| old.soft.set(soft) | old.hard.set(hard));
    }

    /// Extends timeouts to be at least as long as the ones given.
    ///
    /// Each timeout (soft vs hard) is relaxed independently, so e.g. if the soft timeout is
    /// shorter than the existing timeout, but the hard timeout is longer, then only the hard
    /// timeout will be updated.
    ///
    /// Note that `None` disables a timeout entirely (but still sets it).
    pub fn relax_timeouts(&self, timeouts: Timeouts) {
        let [soft, hard] = timeouts.to_soft_and_hard_instants();
        self.timeouts
            .send_if_modified(|old| old.soft.relax(soft) | old.hard.relax(hard));
    }

    /// Gracefully shut down the connection (immediately trigger soft timeout).
    ///
    /// This cannot be undone.
    pub fn graceful_shutdown(&self) {
        self.timeouts.send_modify(|old| old.soft = Deadline::Now);
    }

    /// Disconnect the connection (immediately trigger hard timeout).
    ///
    /// This cannot be undone.
    pub fn disconnect(&self) {
        self.timeouts.send_modify(|old| old.hard = Deadline::Now);
    }

    pub(crate) async fn apply_timeouts<I, S>(
        &self,
        connection: http1::Connection<I, S>,
    ) -> Result<(), ConnectionError>
    where
        I: hyper::rt::Read + hyper::rt::Write + Unpin + 'static,
        S: HttpService<Incoming, Error: Into<BoxedErr>>,
        S::ResBody: Body<Error: Into<BoxedErr>> + 'static,
    {
        let soft_timeout = sleep_adjustably(self.timeouts.subscribe(), |t| &t.soft);
        let hard_timeout = sleep_adjustably(self.timeouts.subscribe(), |t| &t.hard);

        let mut soft_timeout = pin!(soft_timeout.fuse());
        let mut connection = pin!(connection);
        let mut soft_timeout_actually_hit = false;
        let connection = std::future::poll_fn(|cx| {
            if soft_timeout.as_mut().poll(cx).is_ready() {
                connection.as_mut().graceful_shutdown();
                soft_timeout_actually_hit = true;
            }
            connection.as_mut().poll(cx)
        });

        let peer_addr = self.addr;
        tokio::select! {
            biased;
            _ = hard_timeout => {
                match self.timeouts.borrow().hard.clone() {
                    Deadline::Now => warn!("Connection killed by server."),
                    _ => warn!("Connection killed by hard timeout."),
                }
                Err(ConnectionError::HardTimeout { peer_addr })
            }
            result = connection => {
                if soft_timeout_actually_hit {
                    match self.timeouts.borrow().soft.clone() {
                        Deadline::Now => warn!("Connection ended after graceful shutdown."),
                        _ => warn!("Connection ended after soft timeout."),
                    }
                }
                result.map_err(|source| ConnectionError::Http { peer_addr, source })
            }
        }
    }
}

async fn sleep_adjustably(
    mut updates: watch::Receiver<Deadlines>,
    get_timeout: impl Fn(&Deadlines) -> &Deadline,
) {
    let mut last_timeout = get_timeout(&updates.borrow_and_update()).clone();
    loop {
        last_timeout = tokio::select! {
            biased;
            Ok(t) = updates.wait_for(|t| *get_timeout(t) != last_timeout) => {
                get_timeout(&t).clone()
            }
            () = async {
                match last_timeout {
                    Deadline::Now => {}
                    Deadline::When(t) => tokio::time::sleep_until(t.into()).await,
                    Deadline::Never => std::future::pending().await,
                }
            } => return,
        };
    }
}

impl Deadline {
    fn set(&mut self, when: Option<Instant>) -> bool {
        // Reminder: Disconnects are permanent; `Now` cannot be changed.
        if let Self::Now = self {
            return false;
        }
        *self = when.into();
        true
    }

    fn relax(&mut self, when: Option<Instant>) -> bool {
        // Reminder: Disconnects are permanent; `Now` cannot be changed.
        match (&self, when) {
            (Self::Now | Self::Never, _) => false,
            (Self::When(t1), Some(t2)) if *t1 >= t2 => false,
            _ => {
                *self = when.into();
                true
            }
        }
    }
}

impl From<Option<Instant>> for Deadline {
    fn from(when: Option<Instant>) -> Self {
        match when {
            Some(time) => Self::When(time),
            None => Self::Never,
        }
    }
}

/// Timeouts for HTTP connection
///
/// The reason for the distinction between `soft`/`hard` timeouts is that it's nicer if the server
/// ends connections *between* requests, instead of mid-request; the `soft` timeout is when the
/// server begins looking for polite opportunities to draw the connection to a close, and the
/// `hard` timeout is when the server gets fed up and tosses the client out. (In other words, the
/// `hard` timeout catches anyone who tries to evade the `soft` timeout by idling mid-request)
///
/// You probably want the `soft` timeout to be shorter than the `hard` timeout,
/// unless you're ok with the server terminating connections without warning.
#[derive(Copy, Clone, Debug)]
pub struct Timeouts {
    /// How long before the server refrains from serving further requests on the connection.
    pub soft: Option<Duration>,
    /// How long before the server abruptly kills the connection.
    pub hard: Option<Duration>,
}

impl Timeouts {
    fn to_soft_and_hard_instants(self) -> [Option<Instant>; 2] {
        // Although we generally work with `std::time::Instant`, we rely on `tokio` to determine
        // the current time because it provides infrastructure for controlling that in tests.
        let now = Instant::from(tokio::time::Instant::now());
        let Timeouts { soft, hard } = self;
        [soft.map(|d| now + d), hard.map(|d| now + d)]
    }
}

type BoxedErr = Box<dyn std::error::Error + Send + Sync>;

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use futures::stream::StreamExt;
    use http::header::CONTENT_LENGTH;
    use http_body_util::{BodyExt, StreamBody};
    use hyper::body::{Frame, Incoming};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::{TokioIo, TokioTimer};
    use tokio::io::{AsyncWriteExt, DuplexStream};

    use super::*;

    /// Time in minutes to complete a request/response
    const REQUEST_AND_RESPONSE: u64 = 16;

    // NOTE: These times have an additional minute tacked on so they don't race with other events,
    // allowing the tests to be deterministic.

    /// Time in minutes for server to write first half of body (after getting full request)
    const SERVER_SENT_PARTIAL_BODY: u64 = 13;

    // Intended to be used with http_server(); takes 16 minutes/request
    // For each request:
    // * Wait 2 minutes then send first half of headers.
    // * Wait 2 minutes then send second half of headers.
    // * Wait 2 minutes then send first half of body.
    // * Wait 2 minutes then send second half of body.
    // * The server takes 6 minutes to respond.
    // * Wait 2 more minutes for good measure.
    async fn http_client(
        mut connection: DuplexStream,
        num_requests: usize,
    ) -> (Vec<String>, std::io::Result<()>) {
        let mut responses = vec![];
        for _ in 0..num_requests {
            let chunks = [
                b"POST / HTTP/1.1\r\nHost: foo.com\r\n".as_slice(),
                b"Content-Length: 28\r\n\r\n",
                b"Ahoy there!\n",
                b"Fare thee well!\n",
            ];
            for chunk in chunks {
                tokio::time::sleep(Duration::from_mins(2)).await;
                if let Err(err) = connection.write_all(chunk).await {
                    return (responses, Err(err));
                }
            }
            let mut response = Vec::<u8>::new();
            tokio::select! {
                res = tokio::io::copy(&mut connection, &mut response) => {
                    res.unwrap();
                }
                () = tokio::time::sleep(Duration::from_mins(8)) => {}
            }
            responses.push(String::from_utf8(response).unwrap());
        }
        (responses, Ok(()))
    }

    // Intended to be used with http_client()
    // For each request:
    // * Wait for entire request to be sent.
    // * Wait 2 minutes before returning headers.
    // * Wait 2 minutes before returning first half of body.
    // * Wait 2 minutes before returning second half of body.
    async fn http_server(connection: DuplexStream, peer: Peer) -> Result<(), ConnectionError> {
        let service = service_fn(async |request: Request<Incoming>| {
            // The current `hyper` (1.7) seems to disable keepalive if bidirectional streaming
            // occurs. Therefore, to be able to properly test whether a connection has or hasn't
            // been gracefully shutdown (i.e. whether keepalive was disabled due to timeouts),
            // we need to consume the request body BEFORE returning a response.
            request.into_body().collect().await.unwrap();
            tokio::time::sleep(Duration::from_mins(2)).await;
            let chunks = ["Hello world!\n", "Goodbye world!\n"];
            let stream = futures::stream::iter(chunks).then(async |chunk| {
                tokio::time::sleep(Duration::from_mins(2)).await;
                Ok::<_, Infallible>(Frame::data(chunk.as_bytes()))
            });
            let mut response = Response::new(StreamBody::new(stream));
            // Prevent chunked encoding, making it easier to check raw response.
            response.headers_mut().insert(CONTENT_LENGTH, 28.into());
            Ok::<_, Infallible>(response)
        });
        let http_conn = http1::Builder::new()
            .half_close(true)
            .header_read_timeout(None)
            .timer(TokioTimer::new())
            .serve_connection(TokioIo::new(connection), service);
        peer.apply_timeouts(http_conn).await
    }

    // Note: client_status errors out if a request can't be sent; in that case, the previous
    // response may be partial.
    async fn run_client_and_server(
        num_requests: usize,
        peer: Peer,
    ) -> (
        Vec<String>,
        std::io::Result<()>,
        Result<(), ConnectionError>,
    ) {
        let (client_conn, server_conn) = tokio::io::duplex(1024);
        let client = http_client(client_conn, num_requests);
        let server = http_server(server_conn, peer);
        let ((responses, client_status), server_status) = tokio::join!(client, server);
        (responses, client_status, server_status)
    }

    #[tokio::test]
    async fn normal_operation() {
        tokio::time::pause();

        let num_requests = 3;
        let peer_addr = ([1, 2, 3, 4], 80).into();
        let peer = Peer::new(peer_addr);
        peer.set_timeouts(Timeouts {
            soft: Some(Duration::from_hours(1)),
            hard: Some(Duration::from_hours(1)),
        });
        let (responses, client_status, server_status) =
            run_client_and_server(num_requests, peer).await;

        client_status.unwrap();
        server_status.unwrap();
        assert_eq!(responses.len(), num_requests);
        for response in responses {
            assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(response.ends_with("\r\n\r\nHello world!\nGoodbye world!\n"));
        }
    }

    #[tokio::test]
    async fn fixed_hard_timeout() {
        tokio::time::pause();

        let num_requests = 3;
        let hard_timeout = REQUEST_AND_RESPONSE + SERVER_SENT_PARTIAL_BODY;
        let peer_addr = ([1, 2, 3, 4], 80).into();
        let peer = Peer::new(peer_addr);
        peer.set_timeouts(Timeouts {
            soft: None,
            hard: Some(Duration::from_mins(hard_timeout)),
        });
        let (responses, client_status, server_status) =
            run_client_and_server(num_requests, peer).await;

        client_status.unwrap_err();
        let Err(ConnectionError::HardTimeout { .. }) = server_status else {
            panic!("Server status wasn't HardTimeout: {server_status:?}");
        };
        assert_eq!(responses.len(), 2);
        assert!(responses[0].starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(responses[0].ends_with("\r\n\r\nHello world!\nGoodbye world!\n"));
        assert!(responses[1].starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(responses[1].ends_with("\r\n\r\nHello world!\n"));
    }

    #[tokio::test]
    async fn shrunk_hard_timeout() {
        tokio::time::pause();

        let num_requests = 3;
        let hard_timeout = REQUEST_AND_RESPONSE + SERVER_SENT_PARTIAL_BODY;
        let peer_addr = ([1, 2, 3, 4], 80).into();
        let peer = Peer::new(peer_addr);
        let run = run_client_and_server(num_requests, peer.clone());

        let adjust_timeouts = async {
            tokio::time::sleep(Duration::from_mins(hard_timeout - 3)).await;
            peer.set_timeouts(Timeouts {
                soft: None,
                hard: Some(Duration::from_mins(3)),
            });
        };

        let ((responses, client_status, server_status), ()) = tokio::join!(run, adjust_timeouts);

        client_status.unwrap_err();
        let Err(ConnectionError::HardTimeout { .. }) = server_status else {
            panic!("Server status wasn't HardTimeout: {server_status:?}");
        };
        assert_eq!(responses.len(), 2);
        assert!(responses[0].starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(responses[0].ends_with("\r\n\r\nHello world!\nGoodbye world!\n"));
        assert!(responses[1].starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(responses[1].ends_with("\r\n\r\nHello world!\n"));
    }

    #[tokio::test]
    async fn stretched_hard_timeout() {
        tokio::time::pause();

        let num_requests = 3;
        let hard_timeout = REQUEST_AND_RESPONSE + SERVER_SENT_PARTIAL_BODY;
        let peer_addr = ([1, 2, 3, 4], 80).into();
        let peer = Peer::new(peer_addr);
        peer.set_timeouts(Timeouts {
            soft: None,
            hard: Some(Duration::from_mins(5)),
        });
        let run = run_client_and_server(num_requests, peer.clone());

        let adjust_timeouts = async {
            tokio::time::sleep(Duration::from_mins(3)).await;
            peer.relax_timeouts(Timeouts {
                soft: None,
                hard: Some(Duration::from_mins(hard_timeout - 3)),
            });
        };

        let ((responses, client_status, server_status), ()) = tokio::join!(run, adjust_timeouts);

        client_status.unwrap_err();
        let Err(ConnectionError::HardTimeout { .. }) = server_status else {
            panic!("Server status wasn't HardTimeout: {server_status:?}");
        };
        assert_eq!(responses.len(), 2);
        assert!(responses[0].starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(responses[0].ends_with("\r\n\r\nHello world!\nGoodbye world!\n"));
        assert!(responses[1].starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(responses[1].ends_with("\r\n\r\nHello world!\n"));
    }

    #[tokio::test]
    async fn disconnected() {
        tokio::time::pause();

        let num_requests = 3;
        let disconnect_time = REQUEST_AND_RESPONSE + SERVER_SENT_PARTIAL_BODY;
        let peer_addr = ([1, 2, 3, 4], 80).into();
        let peer = Peer::new(peer_addr);
        let run = run_client_and_server(num_requests, peer.clone());

        let disconnect = async {
            tokio::time::sleep(Duration::from_mins(disconnect_time)).await;
            peer.disconnect();
        };

        let ((responses, client_status, server_status), ()) = tokio::join!(run, disconnect);

        client_status.unwrap_err();
        let Err(ConnectionError::HardTimeout { .. }) = server_status else {
            panic!("Server status wasn't HardTimeout: {server_status:?}");
        };
        assert_eq!(responses.len(), 2);
        assert!(responses[0].starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(responses[0].ends_with("\r\n\r\nHello world!\nGoodbye world!\n"));
        assert!(responses[1].starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(responses[1].ends_with("\r\n\r\nHello world!\n"));
    }

    #[tokio::test]
    async fn fixed_soft_timeout() {
        tokio::time::pause();

        let num_requests = 3;
        let soft_timeout = REQUEST_AND_RESPONSE + SERVER_SENT_PARTIAL_BODY;
        let peer_addr = ([1, 2, 3, 4], 80).into();
        let peer = Peer::new(peer_addr);
        peer.set_timeouts(Timeouts {
            soft: Some(Duration::from_mins(soft_timeout)),
            hard: None,
        });
        let (responses, client_status, server_status) =
            run_client_and_server(num_requests, peer).await;

        client_status.unwrap_err();
        server_status.unwrap();
        assert_eq!(responses.len(), 2);
        assert!(responses[0].starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(responses[0].ends_with("\r\n\r\nHello world!\nGoodbye world!\n"));
        assert!(responses[1].starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(responses[0].ends_with("\r\n\r\nHello world!\nGoodbye world!\n"));
    }

    #[tokio::test]
    async fn shrunk_soft_timeout() {
        tokio::time::pause();

        let num_requests = 3;
        let soft_timeout = REQUEST_AND_RESPONSE + SERVER_SENT_PARTIAL_BODY;
        let peer_addr = ([1, 2, 3, 4], 80).into();
        let peer = Peer::new(peer_addr);
        let run = run_client_and_server(num_requests, peer.clone());

        let adjust_timeouts = async {
            tokio::time::sleep(Duration::from_mins(soft_timeout - 3)).await;
            peer.set_timeouts(Timeouts {
                soft: Some(Duration::from_mins(3)),
                hard: None,
            });
        };

        let ((responses, client_status, server_status), ()) = tokio::join!(run, adjust_timeouts);

        client_status.unwrap_err();
        server_status.unwrap();
        assert_eq!(responses.len(), 2);
        assert!(responses[0].starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(responses[0].ends_with("\r\n\r\nHello world!\nGoodbye world!\n"));
        assert!(responses[1].starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(responses[0].ends_with("\r\n\r\nHello world!\nGoodbye world!\n"));
    }

    #[tokio::test]
    async fn stretched_soft_timeout() {
        tokio::time::pause();

        let num_requests = 3;
        let soft_timeout = REQUEST_AND_RESPONSE + SERVER_SENT_PARTIAL_BODY;
        let peer_addr = ([1, 2, 3, 4], 80).into();
        let peer = Peer::new(peer_addr);
        peer.set_timeouts(Timeouts {
            soft: Some(Duration::from_mins(5)),
            hard: None,
        });
        let run = run_client_and_server(num_requests, peer.clone());

        let adjust_timeouts = async {
            tokio::time::sleep(Duration::from_mins(3)).await;
            peer.relax_timeouts(Timeouts {
                soft: Some(Duration::from_mins(soft_timeout - 3)),
                hard: None,
            });
        };

        let ((responses, client_status, server_status), ()) = tokio::join!(run, adjust_timeouts);

        client_status.unwrap_err();
        server_status.unwrap();
        assert_eq!(responses.len(), 2);
        assert!(responses[0].starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(responses[0].ends_with("\r\n\r\nHello world!\nGoodbye world!\n"));
        assert!(responses[1].starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(responses[0].ends_with("\r\n\r\nHello world!\nGoodbye world!\n"));
    }

    #[tokio::test]
    async fn graceful_shutdown_requested() {
        tokio::time::pause();

        let num_requests = 3;
        let graceful_shutdown_time = REQUEST_AND_RESPONSE + SERVER_SENT_PARTIAL_BODY;
        let peer_addr = ([1, 2, 3, 4], 80).into();
        let peer = Peer::new(peer_addr);
        let run = run_client_and_server(num_requests, peer.clone());

        let graceful_shutdown = async {
            tokio::time::sleep(Duration::from_mins(graceful_shutdown_time)).await;
            peer.graceful_shutdown();
        };

        let ((responses, client_status, server_status), ()) = tokio::join!(run, graceful_shutdown);

        client_status.unwrap_err();
        server_status.unwrap();
        assert_eq!(responses.len(), 2);
        assert!(responses[0].starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(responses[0].ends_with("\r\n\r\nHello world!\nGoodbye world!\n"));
        assert!(responses[1].starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(responses[0].ends_with("\r\n\r\nHello world!\nGoodbye world!\n"));
    }

    #[tokio::test]
    async fn connection_errors_are_propagated() {
        let (mut client_conn, server_conn) = tokio::io::duplex(1024);
        let msg = b"This is not a valid HTTP request.";
        client_conn.write_all(msg).await.unwrap();
        let peer_addr = ([1, 2, 3, 4], 80).into();
        let peer = Peer::new(peer_addr);
        let server_status = http_server(server_conn, peer).await;
        let Err(ConnectionError::Http { source, .. }) = server_status else {
            panic!("Server status wasn't Hyper error: {server_status:?}");
        };
        assert!(source.is_parse());
    }

    #[tokio::test]
    async fn disconnect_immediately_prevents_further_execution() {
        let (mut client_conn, server_conn) = tokio::io::duplex(1024);
        let msg = b"GET / HTTP/1.1\r\nHost: foo.com\r\n\r\n";
        client_conn.write_all(msg).await.unwrap();

        let peer_addr = ([1, 2, 3, 4], 80).into();
        let peer = Peer::new(peer_addr);

        let peer2 = peer.clone();
        let service = service_fn(async |_request| -> Result<Response<String>, Infallible> {
            peer2.disconnect();
            tokio::task::yield_now().await;
            panic!("Request handler contined to receive execution after disconnect.");
        });
        let http_conn = http1::Builder::new()
            .half_close(true)
            .header_read_timeout(None)
            .timer(TokioTimer::new())
            .serve_connection(TokioIo::new(server_conn), service);

        let server_status = peer.apply_timeouts(http_conn).await;
        let Err(ConnectionError::HardTimeout { .. }) = server_status else {
            panic!("Server status wasn't HardTimeout: {server_status:?}");
        };
    }

    #[tokio::test]
    async fn fixed_soft_and_hard_timeout() {
        tokio::time::pause();

        let num_requests = 3;
        let soft_timeout = REQUEST_AND_RESPONSE + SERVER_SENT_PARTIAL_BODY;
        let hard_timeout = 2 * REQUEST_AND_RESPONSE + 2;
        let peer_addr = ([1, 2, 3, 4], 80).into();
        let peer = Peer::new(peer_addr);
        peer.set_timeouts(Timeouts {
            soft: Some(Duration::from_mins(soft_timeout)),
            hard: Some(Duration::from_mins(hard_timeout)),
        });
        let (responses, client_status, server_status) =
            run_client_and_server(num_requests, peer).await;

        client_status.unwrap_err();
        server_status.unwrap();
        assert_eq!(responses.len(), 2);
        assert!(responses[0].starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(responses[0].ends_with("\r\n\r\nHello world!\nGoodbye world!\n"));
        assert!(responses[1].starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(responses[0].ends_with("\r\n\r\nHello world!\nGoodbye world!\n"));
    }
}
