//! Runs one future to completion on the calling thread.
//!
//! This module is adapted from the `wait` module of the `reqwest`
//! crate, by Sean McArthur and the reqwest contributors:
//! <https://github.com/seanmonstar/reqwest/blob/master/src/blocking/wait.rs>.
//! reqwest is licensed under the MIT License or the Apache License,
//! Version 2.0, at your option. This port keeps the park/unpark loop of
//! the original. It drops the deadline and the `log` calls, and it
//! accepts any future, not only one that returns a `Result`.
//!
//! `reqwest::blocking::Response` polls its response body on the calling
//! thread with this loop. [`super::BlobReader`] does the same. The loop
//! needs no Tokio runtime on the calling thread. It polls the future
//! once, then parks the thread until the future's waker unparks it.

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

/// Polls `future` on the calling thread until it completes.
///
/// The thread parks between polls. The future's waker unparks it.
pub(super) fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(ThreadWaker(thread::current())));
    let mut cx = Context::from_waker(&waker);

    let mut future = std::pin::pin!(future);

    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
        thread::park();
    }
}

struct ThreadWaker(Thread);

impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_the_output_of_a_ready_future() {
        assert_eq!(block_on(async { 1 + 1 }), 2);
    }

    /// A future that another thread wakes later must complete. This
    /// checks that the parked thread wakes up when the waker fires.
    #[test]
    fn waits_for_a_wake_from_another_thread() {
        let (tx, rx) = tokio::sync::oneshot::channel::<&str>();
        thread::spawn(move || {
            thread::sleep(std::time::Duration::from_millis(20));
            tx.send("done").unwrap();
        });

        assert_eq!(block_on(rx), Ok("done"));
    }
}
