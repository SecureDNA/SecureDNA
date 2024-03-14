// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tools for preventing child tasks from outliving parents

use std::future::Future;

use tokio::select;
use tokio::sync::{mpsc, watch};

/// Limits lifetimes of async child tasks.
///
/// This is a very minimal implementation of some aspects of the nursery idea from
/// [Nathaniel J. Smith's "Notes on structured concurrency, or: Go statement considered harmful"][1].
/// Its main purpose is to ensure that child tasks do not outlive a parent task, even if
/// the parent task is canceled. If a [`Future`] is wrapped in
/// [`Nursery::chaperone`], then [`Nursery::finish`] (or dropping the [`Nursery`])
/// will block until that [`Future`] no longer exists:
///
/// [1]: https://vorpus.org/blog/notes-on-structured-concurrency-or-go-statement-considered-harmful/
///
/// ```
/// use std::sync::atomic::{AtomicU32, Ordering};
/// use std::sync::Arc;
///
/// use minhttp::nursery::Nursery;
///
/// #[tokio::main]
/// async fn main() {
///     let counter = Arc::new(AtomicU32::new(0));
///
///     let mut nursery = Nursery::new();
///     for _ in 0..7 {
///         let counter = counter.clone();
///         tokio::task::spawn(nursery.chaperone(async move {
///             for _ in 0..11 {
///                 counter.fetch_add(1, Ordering::Relaxed);
///             }
///         }));
///     }
///     nursery.finish().await;
///
///     assert_eq!(counter.load(Ordering::Relaxed), 77);
/// }
/// ```
///
/// Furthermore, dropping a [`Nursery`] will cause chaperoned [`Future`]s
/// to wake their tasks and be canceled when next polled:
///
/// ```
/// use std::sync::Arc;
/// use std::task::Poll;
///
/// use tokio::sync::Semaphore;
///
/// use minhttp::nursery::Nursery;
///
/// #[tokio::main]
/// async fn main() {
///     let semaphore = Arc::new(Semaphore::new(1));
///
///     let mut nursery = Nursery::new();
///     let permit = semaphore.clone().acquire_owned().await.unwrap();
///     tokio::task::spawn(nursery.chaperone(async {
///         let _permit = permit;
///         // Attempt to hold permit forever...
///         let () = std::future::poll_fn(|_| Poll::Pending).await;
///     }));
///     drop(nursery); // ...but this cancels the task, releasing the permit...
///
///     semaphore.try_acquire().unwrap(); // ...so this succeeds
/// }
/// ```
///
/// # Caveats
///
/// **BEWARE:** [`Nursery`] only works with multithreaded [`tokio`] runtimes!
/// The need for multithreaded runtimes is because the [`drop`](Drop::drop) API is
/// synchronous, forcing [`Nursery`] to block the executor in order to delay
/// cancellation until children have finished.
///
/// Panic propagation is not yet implemented.
pub struct Nursery {
    /// Used to indicate the nursery is shutting down quickly and children should cancel themselves ASAP
    canceled: watch::Sender<bool>,
    /// Cloned and passed to children to hold children_receiver open while they exist
    children_sender: Option<mpsc::Sender<()>>,
    /// Allows both sync and async blocking until no children exist
    children_receiver: mpsc::Receiver<()>,
}

// NOTE: Although using an mpsc queue feels hacky, that's the suggested solution in
// https://tokio.rs/tokio/topics/shutdown
// It has the advantage that I don't have to track JoinHandles (and can even defer
// spawning to the user), and it can be blocked on from synchronous code such as
// Drop impls. It's very, VERY tempting to try to indicate cancellation by closing
// the mpsc::Receiver, but that causes recv to ignore outstanding mpsc::Senders,
// defeating the whole purpose of the queue.

/// Indicates a [`Future`] has been canceled by dropping its [`Nursery`].
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Canceled;

impl Nursery {
    /// Constructs a new [`Nursery`].
    pub fn new() -> Self {
        let (canceled, _) = watch::channel(false);
        let (children_sender, children_receiver) = mpsc::channel(1);
        Self {
            canceled,
            children_sender: Some(children_sender),
            children_receiver,
        }
    }

    /// Tracks a [`Future`] as a child of the [`Nursery`].
    ///
    /// The given [`Future`] is wrapped and returned, with the
    /// wrapper ensuring that cancellation of the [`Nursery`] propagates to the wrapped
    /// [`Future`] and that the [`Nursery`] cannot be dropped
    /// until the wrapper ceases to exist.
    ///
    /// See main [`Nursery`] docs for details.
    pub fn chaperone<T: Send>(
        &mut self,
        task: impl Future<Output = T> + Send + 'static,
    ) -> impl Future<Output = Result<T, Canceled>> + Send + 'static {
        let mut canceled = self.canceled.subscribe();
        let children_sender = self
            .children_sender
            .clone()
            .expect("Bug: Nursery's child_sender should only be None during shutdown");
        async move {
            let _children_sender = children_sender; // blocks children_receiver while it exists
            let canceled = canceled.wait_for(|&is_aborted| is_aborted);
            select! {
                // If `task` is always ready (due to e.g. being a series of CPU-bound
                // computations) then unbiased selection would more-or-less correspond to
                // occasionally skipping cancellation checks... that's probably fine, but I
                // figure biased selection kills two birds with one stone: skipping CPU
                // cost of RNG and ensuring cancellation checks happen every time.
                biased;
                _ = canceled => Err(Canceled),
                val = task => Ok(val),
            }
        }
    }

    /// Drops [`Nursery`], gracefully waiting for children to finish.
    ///
    /// # Cancel Safety
    ///
    /// If the [`Future`] returned by [`finish`](Self::finish) is canceled,
    /// the [`Nursery`] will propagate the cancellation to its children and the cancellation
    /// will be blocked until all children finish.
    pub async fn finish(mut self) {
        self.children_sender = None; // Prevent deadlocking recv
        assert!(self.children_receiver.recv().await.is_none());
    }

    /// Drops [`Nursery`], gracefully waiting for children to finish.
    ///
    /// Note that this blocks until complete, and should not be run from within an
    /// async task without informing the executor that the thread may be blocked.
    pub fn block_until_finished(mut self) {
        self.block_until_finished_impl();
    }

    /// Blocks (synchronously) until our children have finished.
    ///
    /// Note: This invalidates the state of the [`Nursery`]. Do not use it after calling this.
    fn block_until_finished_impl(&mut self) {
        self.children_sender = None; // Prevent deadlocking blocking_recv
        assert!(self.children_receiver.blocking_recv().is_none());
    }
}

impl Default for Nursery {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Nursery {
    fn drop(&mut self) {
        // (only accept overhead of block_in_place if necessary)
        if self.canceled.send(true).is_ok() {
            // block_in_place prevents deadlocks when running in async code; it offloads our
            // worker thread's backlog so it doesn't contain any children we're waiting for.
            tokio::task::block_in_place(|| self.block_until_finished_impl());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::pin::pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake};

    struct DebugWaker(AtomicBool);

    impl Wake for DebugWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    impl DebugWaker {
        fn new() -> Arc<Self> {
            Arc::new(Self(AtomicBool::new(false)))
        }

        fn newly_woken(&self) -> bool {
            self.0.swap(false, Ordering::Relaxed)
        }
    }

    async fn hang() {
        std::future::poll_fn(|_| Poll::Pending).await
    }

    #[test]
    fn finish_waits_for_chaperoned_futures_to_end() {
        let waker = DebugWaker::new();
        let cx_waker = waker.clone().into();
        let mut context = Context::from_waker(&cx_waker);

        let mut nursery = Nursery::new();
        let child = nursery.chaperone(async {});
        let mut finish = pin!(nursery.finish());

        // IMPORTANT: DO NOT REMOVE. This prevents assertion failures from deadlocking.
        // In normal code, `finish` wouldn't exist in the same scope as `child`; `child` would
        // be a task running on an executor by the time `finish` is invoked, so there'd be no
        // deadlock because `child` would eventually resolve on its own. However, in this code
        // `child` isn't run on an executor, so that we can control when it finishes, so it's
        // important to ensure that `child` is dropped before `finish` when an assertion fails.
        // Also, this needs to be in a block until the stable version of clippy has
        // https://github.com/rust-lang/rust-clippy/issues/11599
        let child = { child };

        // `finish` should be blocked by the existence of `child`
        assert!(finish.as_mut().poll(&mut context).is_pending());
        assert!(!waker.newly_woken());

        drop(child);

        // Dropping `child` should have notified `waker` and polling `finish` should complete.
        assert!(waker.newly_woken());
        assert_eq!(finish.as_mut().poll(&mut context), Poll::Ready(()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn block_until_finished_waits_for_chaperoned_futures_to_end() {
        let resource = Arc::new(());
        let weak_resource = Arc::downgrade(&resource);

        let mut nursery = Nursery::new();
        tokio::task::spawn(nursery.chaperone(async {
            let _resource = resource;
        }));

        tokio::task::block_in_place(|| {
            nursery.block_until_finished();
        });
        assert!(weak_resource.upgrade().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_nursery_cancels_children() {
        let resource = Arc::new(());
        let weak_resource = Arc::downgrade(&resource);

        let mut nursery = Nursery::new();

        tokio::task::spawn(nursery.chaperone(async {
            let _resource = resource;
            hang().await;
        }));

        assert!(weak_resource.upgrade().is_some());
        drop(nursery);
        assert!(weak_resource.upgrade().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unpolled_finish_propagates_cancellation() {
        let resource = Arc::new(());
        let weak_resource = Arc::downgrade(&resource);

        let mut nursery = Nursery::new();
        tokio::task::spawn(nursery.chaperone(async move {
            let _resource = resource;
            hang().await;
        }));
        let finish = nursery.finish(); // Not awaiting so we can abort.

        assert!(weak_resource.upgrade().is_some());
        drop(finish);
        assert!(weak_resource.upgrade().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn polled_finish_propagates_cancellation() {
        let resource = Arc::new(());
        let weak_resource = Arc::downgrade(&resource);

        let mut nursery = Nursery::new();
        tokio::task::spawn(nursery.chaperone(async move {
            let _resource = resource;
            hang().await;
        }));
        let mut finish = Box::pin(nursery.finish()); // Not awaiting so we can abort.
        select! { // poll `finish` once
            biased;
            _ = &mut finish => panic!("the child should be hung, preventing graceful finish"),
            _ = async {} => {}
        };

        assert!(weak_resource.upgrade().is_some());
        drop(finish);
        assert!(weak_resource.upgrade().is_none());
    }
}
