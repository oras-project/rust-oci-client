//! Runs futures on one background thread. Other threads can wait for the
//! result.
//!
//! The blocking client wraps the asynchronous [`crate::Client`]. Its
//! futures need a Tokio runtime to run.
//!
//! One simple design calls `Runtime::block_on` on the thread that calls
//! the blocking client. This design has a problem. `block_on` panics when
//! that thread is already inside another Tokio runtime. A test that calls
//! the blocking client through [`tokio::task::spawn_blocking`] is one such
//! case.
//!
//! Instead, one background thread owns a single-threaded Tokio runtime.
//! This thread calls `block_on` on its own runtime for as long as the
//! client is alive. Other threads give the background thread futures
//! through [`BackgroundRuntime::block_on`]. This method spawns the future
//! on the background runtime. It then waits for the result on a plain
//! channel, not through a Tokio API. As a result, this wait works even
//! when the calling thread is itself a worker thread of another Tokio
//! runtime.
//!
//! Dropping matters too. When the last clone of a [`BackgroundRuntime`]
//! drops, the *background thread* must drop the Tokio runtime, not the
//! thread that drops the last clone. A Tokio runtime panics when it drops
//! inside another runtime's async context. The thread that drops a
//! [`BackgroundRuntime`] clone can be in exactly that context.
use std::future::Future;
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;

use tokio::runtime;
use tokio::sync::oneshot;

#[derive(Clone)]
pub(super) struct BackgroundRuntime {
    handle: runtime::Handle,
    // Keeps the background thread alive. Its `Drop` impl asks the
    // thread to shut down. Then it waits for the thread to exit.
    _keep_alive: Arc<ShutdownOnDrop>,
}

struct ShutdownOnDrop {
    // `ShutdownOnDrop::drop` is the only reader of these fields. It
    // runs at most once, when the last `Arc` clone goes away. At that
    // point it already has exclusive access through `&mut self`.
    // These fields need no lock of their own.
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl BackgroundRuntime {
    /// Starts the background thread and its runtime.
    pub(super) fn new() -> std::io::Result<Self> {
        let (handle_tx, handle_rx) = mpsc::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let thread = std::thread::Builder::new()
            .name("oci-client-blocking".to_string())
            .spawn(move || {
                let runtime = match runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        // The receiver below still waits. Tell it why
                        // there is no handle.
                        let _ = handle_tx.send(Err(error));
                        return;
                    }
                };
                let _ = handle_tx.send(Ok(runtime.handle().clone()));

                // This keeps the runtime alive. The executor polls
                // every task on the runtime until the client asks this
                // thread to shut down. Then this thread drops the
                // runtime.
                runtime.block_on(async {
                    let _ = shutdown_rx.await;
                });
            })?;

        let handle = match handle_rx.recv() {
            Ok(handle) => handle?,
            Err(_) => {
                // The background thread exited before it sent
                // anything. It most likely panicked.
                let _ = thread.join();
                return Err(std::io::Error::other(
                    "the background thread of the blocking client exited before starting its runtime",
                ));
            }
        };

        Ok(Self {
            handle,
            _keep_alive: Arc::new(ShutdownOnDrop {
                shutdown: Some(shutdown_tx),
                thread: Some(thread),
            }),
        })
    }

    /// Runs `future` on the background runtime. Then it blocks the
    /// calling thread until the future completes.
    pub(super) fn block_on<F>(&self, future: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        self.handle.spawn(async move {
            // `send` fails only when the receiver below no longer
            // exists. That happens only if the calling thread
            // panicked while it waited. In that case, no one is left
            // to receive the result.
            let _ = tx.send(future.await);
        });
        rx.recv().expect(
            "the blocking client's background thread most likely panicked before sending a result",
        )
    }
}

impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            // The receiving end can already be gone if the background
            // thread panicked. That is fine. `join` below still shows
            // that the thread exited.
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BackgroundRuntime;

    #[test]
    fn runs_futures_and_returns_their_result() {
        let rt = BackgroundRuntime::new().expect("failed to start the background runtime");
        assert_eq!(rt.block_on(async { 1 + 1 }), 2);
    }

    /// A Tokio runtime panics when it drops inside another runtime's
    /// async context. See `tokio::runtime::Runtime`'s `Drop` impl for
    /// this. `BackgroundRuntime` must not do that. Its own runtime
    /// must live and die on its background thread, not on the thread
    /// that drops the last clone.
    #[tokio::test]
    async fn dropping_from_an_async_context_does_not_panic() {
        let rt = BackgroundRuntime::new().expect("failed to start the background runtime");
        assert_eq!(rt.block_on(async { "ok" }), "ok");
        drop(rt);
    }

    #[test]
    fn cloning_shares_the_same_background_thread() {
        let rt = BackgroundRuntime::new().expect("failed to start the background runtime");
        let cloned = rt.clone();
        assert_eq!(rt.block_on(async { 1 }), 1);
        assert_eq!(cloned.block_on(async { 2 }), 2);
    }
}
