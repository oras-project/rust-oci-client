//! Helpers for `Client::pull_blob_read`, `Client::pull_blob`,
//! `Client::push_blob_from_read`, and `Client::push_blob_from_read_chunked`.
//!
//! For a pull, [`BlobReader`] owns the response body stream. Each call
//! to [`std::io::Read::read`] polls that stream on the calling thread,
//! with the [`super::wait`] loop. No chunk crosses a channel. The
//! transport reads from the network only when the reader asks for the
//! next chunk.
//!
//! For a push, the calling thread's [`std::io::Read`] fills a bounded
//! channel. The background thread drains it, and sends the chunks to
//! the registry. Memory use stays at a few chunks, not the whole blob.

use std::io::Read;

use bytes::{Buf, Bytes};
use futures_util::stream::BoxStream;
use futures_util::StreamExt;
use tokio::sync::mpsc;

use crate::errors::*;
use crate::types::{AsLayerDescriptor, LayerDescriptor};

use super::background_runtime::BackgroundRuntime;
use super::wait;

/// The number of blob chunks the channel holds between the calling
/// thread and the background runtime during a push. Bounds the memory
/// `Client::push_blob_from_read` and `Client::push_blob_from_read_chunked`
/// use to about `BLOB_CHANNEL_CAPACITY` chunks, not the whole blob.
pub(super) const BLOB_CHANNEL_CAPACITY: usize = 8;

/// The size of the buffer [`feed_reader_to_channel`] uses to read from
/// the caller's [`std::io::Read`]. Each read fills one buffer, then
/// sends it to the background thread as one chunk.
const READ_CHUNK_SIZE: usize = 64 * 1024;

/// A blob, as a [`std::io::Read`].
///
/// `Client::pull_blob_read` returns this type. It owns the response body
/// stream of [`crate::Client::pull_blob_stream`]. Each call to
/// [`std::io::Read::read`] polls that stream on the calling thread, the
/// same way `reqwest::blocking::Response` reads its body. The digest
/// check happens as the chunks arrive. A mismatch surfaces as an error
/// from the last `read` call, the one that would otherwise return
/// `Ok(0)`.
///
/// A `read` call into a non-empty buffer follows this rule. After one
/// such call returns `Ok(0)`, every later one returns `Ok(0)` too, with
/// no new poll of the stream. After one such call returns an error,
/// every later one returns an error too, again with no new poll. Only
/// the first failing call carries the stream's own error, for example
/// a [`DigestError`]. Each later call returns a generic error that
/// says the stream already failed. The stream drops at the point
/// where it reaches `Ok(0)` or the first error, instead of waiting for
/// this reader to drop; the transport can then release the connection
/// right away.
///
/// A `read` call into an empty buffer returns `Ok(0)` at once, in every
/// state, as the [`Read`](std::io::Read) contract requires. That call
/// says nothing about the state of the stream.
///
/// A `BlobReader` can outlive the `Client` that created it. It holds its
/// own clone of the background runtime, so dropping every clone of the
/// client does not stop the pull.
///
/// Drop a `BlobReader` to stop the pull. This drops the response body,
/// and the transport stops the request. This does not block, unless this
/// reader holds the last clone of the background runtime, for example
/// because every `Client` already dropped. In that case, dropping the
/// reader shuts the background thread down and waits for it to exit.
pub struct BlobReader {
    /// The length of the blob. This comes from the response body or from
    /// the `Content-Length` header. It is `None` when the registry does
    /// not report a length.
    pub content_length: Option<u64>,
    /// The `Digest` header value the registry sent, if any. See
    /// [`crate::client::SizedStream::digest_header_value`] for how the
    /// async client uses this value.
    pub digest_header_value: Option<String>,
    pub(super) state: StreamState,
    pub(super) current: Bytes,
    /// Keeps the background thread alive, and gives `read` a runtime
    /// context for the body stream.
    pub(super) runtime: BackgroundRuntime,
}

/// The state of the response body stream of a [`BlobReader`].
///
/// A stream that already reached its end, or that already reported an
/// error, must not be polled again. Polling most streams again after
/// that point panics, hangs, or, for the registry's digest-verifying
/// stream specifically, finalizes its digest a second time over no
/// bytes and reports a false mismatch. This type remembers that the
/// stream finished, so [`Read::read`](std::io::Read::read) can stop on
/// its own, without relying on the stream to behave a particular way
/// once it is done.
pub(super) enum StreamState {
    /// The stream can still yield more chunks.
    Open(BoxStream<'static, std::io::Result<Bytes>>),
    /// The stream ended cleanly. Every `read` call into a non-empty
    /// buffer, from here on, returns `Ok(0)`.
    Done,
    /// The stream reported an error. Every `read` call into a
    /// non-empty buffer, from here on, returns a generic error. The
    /// stream's own error already went to the call that moved the
    /// reader here.
    Failed,
}

impl std::fmt::Debug for BlobReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BlobReader")
            .field("content_length", &self.content_length)
            .field("digest_header_value", &self.digest_header_value)
            .finish_non_exhaustive()
    }
}

impl Read for BlobReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // A zero-length read returns `Ok(0)` at once, as `Read::read`
        // documents. It must not poll the stream. A poll can wait for
        // the network, and it can consume the error item that a later,
        // real read must see.
        if buf.is_empty() {
            return Ok(0);
        }
        // An empty chunk is not end of stream; loop past it instead of
        // reporting a false `Ok(0)`. Neither `VerifyingStream` nor the
        // default transport sends one today, but `Read::read` must not
        // assume that.
        while self.current.is_empty() {
            let stream = match &mut self.state {
                StreamState::Open(stream) => stream,
                StreamState::Done => return Ok(0),
                StreamState::Failed => {
                    return Err(std::io::Error::other(
                        "the blob stream already reported an error",
                    ))
                }
            };
            // The body stream can create Tokio resources when polled,
            // for example the timer behind `ClientConfig::read_timeout`.
            // Those need a runtime context on this thread. The
            // background thread drives them.
            let _guard = self.runtime.enter();
            match wait::block_on(stream.next()) {
                Some(Ok(bytes)) => self.current = bytes,
                Some(Err(error)) => {
                    // Drop the stream instead of polling it again on a
                    // later `read`. See `StreamState`.
                    self.state = StreamState::Failed;
                    return Err(error);
                }
                None => {
                    self.state = StreamState::Done;
                    return Ok(0);
                }
            }
        }
        let n = buf.len().min(self.current.len());
        buf[..n].copy_from_slice(&self.current[..n]);
        self.current.advance(n);
        Ok(n)
    }
}

/// Converts the [`std::io::Error`] that [`std::io::copy`] over a
/// [`BlobReader`] can return, back into an [`OciDistributionError`].
///
/// [`std::io::Read::read`] must return [`std::io::Error`], so
/// [`BlobReader`] wraps its errors in one. This function reverses that:
/// it recovers a [`DigestError`] or an [`OciDistributionError`] when the
/// `io::Error` carries one, and falls back to
/// [`OciDistributionError::IoError`] for any other error, for example one
/// from the destination [`std::io::Write`] of [`std::io::copy`].
pub(super) fn io_error_to_oci(error: std::io::Error) -> OciDistributionError {
    let error = match error.downcast::<DigestError>() {
        Ok(digest_error) => return OciDistributionError::DigestError(digest_error),
        Err(error) => error,
    };
    match error.downcast::<OciDistributionError>() {
        Ok(oci_error) => oci_error,
        Err(error) => OciDistributionError::IoError(error),
    }
}

/// Wraps a [`mpsc::Receiver`] as a [`futures_util::Stream`].
///
/// This crate does not depend on `tokio-stream`, which gives the same
/// kind of wrapper. `unfold` does the same job for this one use.
pub(super) fn receiver_stream<T: Send + 'static>(
    rx: mpsc::Receiver<T>,
) -> impl futures_util::Stream<Item = T> + Send + 'static {
    futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    })
}

/// Reads `reader` on the calling thread, in fixed-size chunks. Sends each
/// chunk to `tx`. When the channel is full, this function waits. This
/// keeps memory use bounded. `Client::push_blob_from_read` and
/// `Client::push_blob_from_read_chunked` pair this function with
/// [`receiver_stream`] on the background thread.
///
/// A read that fails with [`std::io::ErrorKind::Interrupted`] reads
/// again, as [`std::io::copy`] does. Every other error goes to `tx`,
/// as the last item, on a best-effort basis. The background task can
/// already have dropped its receiver, for example after its own error.
/// In that case, no one reads the error this function sends. The caller
/// still sees the background task's own error, through the result
/// handle's `wait`.
pub(super) fn feed_reader_to_channel<R: Read>(mut reader: R, tx: mpsc::Sender<Result<Bytes>>) {
    let mut buf = vec![0u8; READ_CHUNK_SIZE];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if tx
                    .blocking_send(Ok(Bytes::copy_from_slice(&buf[..n])))
                    .is_err()
                {
                    // The background task stopped reading the stream.
                    // It already failed, or it finished and does not
                    // need the rest of `reader`.
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                // A signal interrupted the read. This is not a real
                // error; read again, as `std::io::copy` does.
                continue;
            }
            Err(error) => {
                let _ = tx.blocking_send(Err(error.into()));
                break;
            }
        }
    }
}

/// An owned [`AsLayerDescriptor`].
///
/// `Client::pull_blob_read` runs on the background thread. Its layer
/// descriptor must be `'static`.
///
/// [`LayerDescriptor`] borrows its fields instead of owning them. This
/// type copies those fields out of the caller's value. It does this
/// copy before the value moves to the background thread.
pub(super) struct OwnedLayerDescriptor {
    digest: String,
    urls: Option<Vec<String>>,
}

impl OwnedLayerDescriptor {
    pub(super) fn new(layer: impl AsLayerDescriptor) -> Self {
        let layer = layer.as_layer_descriptor();
        Self {
            digest: layer.digest.to_string(),
            urls: layer.urls.clone(),
        }
    }
}

impl AsLayerDescriptor for OwnedLayerDescriptor {
    fn as_layer_descriptor(&self) -> LayerDescriptor<'_> {
        LayerDescriptor {
            digest: &self.digest,
            urls: &self.urls,
        }
    }
}

#[cfg(test)]
mod tests {
    use futures_util::stream;
    use rstest::rstest;

    use super::*;

    /// Builds a [`BlobReader`] directly from a stream, bypassing
    /// `Client::pull_blob_read` and its HTTP request. The tests in this
    /// module use this to drive `Read::read` with chunks they control.
    fn reader_from<S>(stream: S) -> BlobReader
    where
        S: futures_util::Stream<Item = std::io::Result<Bytes>> + Send + 'static,
    {
        BlobReader {
            content_length: None,
            digest_header_value: None,
            state: StreamState::Open(Box::pin(stream)),
            current: Bytes::new(),
            runtime: BackgroundRuntime::new().expect("failed to start the background runtime"),
        }
    }

    #[test]
    fn read_spans_chunks_and_copies_partial_buffers() {
        let chunks = vec![
            Ok(Bytes::from_static(b"hello")),
            Ok(Bytes::from_static(b"world")),
        ];
        let mut reader = reader_from(stream::iter(chunks));

        // A 3-byte buffer against two 5-byte chunks forces `read` to
        // split both a chunk across calls and a call across chunks.
        let mut out = Vec::new();
        let mut buf = [0u8; 3];
        loop {
            let n = reader.read(&mut buf).expect("read failed");
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }

        assert_eq!(out, b"helloworld");
    }

    #[test]
    fn read_skips_empty_chunks() {
        let chunks = vec![Ok(Bytes::new()), Ok(Bytes::from_static(b"x"))];
        let mut reader = reader_from(stream::iter(chunks));

        let mut buf = [0u8; 4];
        let n = reader.read(&mut buf).expect("read failed");

        assert_eq!(&buf[..n], b"x");
    }

    #[test]
    fn read_returns_the_error_item_of_the_stream() {
        let chunks = vec![Err(std::io::Error::other("boom"))];
        let mut reader = reader_from(stream::iter(chunks));

        let mut buf = [0u8; 4];
        let error = reader
            .read(&mut buf)
            .expect_err("expected the stream's error to surface");

        assert_eq!(error.to_string(), "boom");
    }

    /// After `read` returns `Ok(0)` at the end of the stream, a later
    /// `read` returns `Ok(0)` again, and it must not poll the stream a
    /// second time. A second poll of a stream that already finished is
    /// what produced the false digest mismatch this test guards
    /// against: the registry's digest-verifying stream finalizes its
    /// digest on every `None` it gives out, and finalizing twice checks
    /// the blob's digest against the digest of nothing the second time.
    #[test]
    fn read_returns_ok_zero_again_after_eof_without_polling_the_stream() {
        let mut polls_after_eof = 0;
        let mut yielded = false;
        let stream = stream::poll_fn(
            move |_| -> std::task::Poll<Option<std::io::Result<Bytes>>> {
                if !yielded {
                    yielded = true;
                    return std::task::Poll::Ready(Some(Ok(Bytes::from_static(b"x"))));
                }
                polls_after_eof += 1;
                assert!(
                    polls_after_eof <= 1,
                    "the stream must not be polled again after it already returned None"
                );
                std::task::Poll::Ready(None)
            },
        );
        let mut reader = reader_from(stream);

        let mut out = Vec::new();
        reader.read_to_end(&mut out).expect("read failed");
        assert_eq!(out, b"x");

        let mut buf = [0u8; 4];
        assert_eq!(reader.read(&mut buf).expect("read failed"), 0);
        assert_eq!(reader.read(&mut buf).expect("read failed"), 0);
    }

    /// After `read` reports the stream's error, a later `read` reports
    /// an error again, without polling the stream a second time.
    #[test]
    fn read_returns_an_error_again_after_a_failure_without_polling_the_stream() {
        let mut polled = false;
        let stream = stream::poll_fn(
            move |_| -> std::task::Poll<Option<std::io::Result<Bytes>>> {
                assert!(
                    !polled,
                    "the stream must not be polled again after it already reported an error"
                );
                polled = true;
                std::task::Poll::Ready(Some(Err(std::io::Error::other("boom"))))
            },
        );
        let mut reader = reader_from(stream);

        let mut buf = [0u8; 4];
        let first = reader
            .read(&mut buf)
            .expect_err("expected the stream's error to surface");
        assert_eq!(first.to_string(), "boom");

        let second = reader
            .read(&mut buf)
            .expect_err("expected an error again, not a poll of the finished stream");
        assert_eq!(
            second.to_string(),
            "the blob stream already reported an error"
        );
    }

    /// A zero-length destination buffer returns `Ok(0)` at once, as the
    /// contract of `Read::read` says. The method must not poll the
    /// stream. A stream that panics when polled proves that.
    #[test]
    fn zero_length_read_does_not_poll_the_stream() {
        let stream = stream::poll_fn(|_| -> std::task::Poll<Option<std::io::Result<Bytes>>> {
            panic!("a zero-length read must not poll the stream")
        });
        let mut reader = reader_from(stream);

        assert_eq!(
            reader
                .read(&mut [])
                .expect("a zero-length read must not fail"),
            0
        );
    }

    /// A body stream can create a Tokio timer when polled. The default
    /// transport does this for `ClientConfig::read_timeout`. `read`
    /// enters the background runtime so that the timer finds a runtime
    /// on the calling thread.
    #[test]
    fn read_polls_a_stream_that_uses_tokio_timers() {
        let stream = stream::once(async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            Ok(Bytes::from_static(b"late"))
        });
        let mut reader = reader_from(stream);

        let mut out = Vec::new();
        reader.read_to_end(&mut out).expect("read failed");

        assert_eq!(out, b"late");
    }

    #[rstest]
    #[case::digest_error(std::io::Error::other(DigestError::MissingAlgorithm), "digest")]
    #[case::wrapped_oci_error(
        std::io::Error::other(OciDistributionError::GenericError(Some("boom".to_string()))),
        "oci"
    )]
    #[case::plain_io_error(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe gone"), "io")]
    fn io_error_to_oci_recovers_the_original_error(
        #[case] error: std::io::Error,
        #[case] expected: &str,
    ) {
        match (io_error_to_oci(error), expected) {
            (OciDistributionError::DigestError(DigestError::MissingAlgorithm), "digest") => {}
            (OciDistributionError::GenericError(Some(message)), "oci") => {
                assert_eq!(message, "boom");
            }
            (OciDistributionError::IoError(io_error), "io") => {
                assert_eq!(io_error.kind(), std::io::ErrorKind::BrokenPipe);
            }
            (other, expected) => panic!("unexpected result {other:?} for case {expected:?}"),
        }
    }

    #[test]
    fn feed_reader_to_channel_splits_at_read_chunk_size() {
        let data = vec![7u8; READ_CHUNK_SIZE + 1];
        let (tx, mut rx) = mpsc::channel::<Result<Bytes>>(BLOB_CHANNEL_CAPACITY);

        feed_reader_to_channel(std::io::Cursor::new(data.clone()), tx);

        let first = rx
            .blocking_recv()
            .expect("expected a first chunk")
            .expect("the first chunk should not be an error");
        let second = rx
            .blocking_recv()
            .expect("expected a second chunk")
            .expect("the second chunk should not be an error");
        assert!(
            rx.blocking_recv().is_none(),
            "expected no more chunks after the reader reached EOF"
        );

        assert_eq!(first.len(), READ_CHUNK_SIZE);
        assert_eq!(second.len(), 1);
        assert_eq!([first, second].concat(), data);
    }

    #[test]
    fn feed_reader_to_channel_sends_a_read_error_as_the_last_item() {
        struct FailingReader {
            yielded: bool,
        }
        impl Read for FailingReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if !self.yielded {
                    self.yielded = true;
                    buf[0] = 1;
                    Ok(1)
                } else {
                    Err(std::io::Error::other("read boom"))
                }
            }
        }
        let (tx, mut rx) = mpsc::channel::<Result<Bytes>>(BLOB_CHANNEL_CAPACITY);

        feed_reader_to_channel(FailingReader { yielded: false }, tx);

        let chunk = rx
            .blocking_recv()
            .expect("expected the first chunk")
            .expect("the first chunk should not be an error");
        assert_eq!(&chunk[..], &[1]);

        let error = rx
            .blocking_recv()
            .expect("expected the error item")
            .expect_err("expected an error");
        assert!(
            matches!(error, OciDistributionError::IoError(_)),
            "{error:?}"
        );

        assert!(
            rx.blocking_recv().is_none(),
            "expected the channel to close after the error"
        );
    }

    /// `std::io::ErrorKind::Interrupted` is not a real failure. It
    /// means a signal arrived during the read. `feed_reader_to_channel`
    /// reads again, the same way `std::io::copy` does, instead of
    /// sending an error and ending the upload.
    #[test]
    fn feed_reader_to_channel_retries_interrupted_reads() {
        struct InterruptedOnceReader {
            calls: usize,
        }
        impl Read for InterruptedOnceReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.calls += 1;
                match self.calls {
                    1 => {
                        buf[0] = 1;
                        Ok(1)
                    }
                    2 => Err(std::io::Error::from(std::io::ErrorKind::Interrupted)),
                    3 => {
                        buf[0] = 2;
                        Ok(1)
                    }
                    _ => Ok(0),
                }
            }
        }
        let (tx, mut rx) = mpsc::channel::<Result<Bytes>>(BLOB_CHANNEL_CAPACITY);

        feed_reader_to_channel(InterruptedOnceReader { calls: 0 }, tx);

        let first = rx
            .blocking_recv()
            .expect("expected the first chunk")
            .expect("the first chunk should not be an error");
        let second = rx
            .blocking_recv()
            .expect("expected the chunk after the interrupted read")
            .expect("the second chunk should not be an error");
        assert!(
            rx.blocking_recv().is_none(),
            "expected a clean end of stream, with no error item for the interrupted read"
        );

        assert_eq!(&first[..], &[1]);
        assert_eq!(&second[..], &[2]);
    }

    #[test]
    fn feed_reader_to_channel_stops_when_the_receiver_is_gone() {
        struct CountingReader {
            calls: usize,
        }
        impl Read for CountingReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.calls += 1;
                buf[0] = 1;
                Ok(1)
            }
        }
        let (tx, rx) = mpsc::channel::<Result<Bytes>>(BLOB_CHANNEL_CAPACITY);
        drop(rx);

        let mut reader = CountingReader { calls: 0 };
        feed_reader_to_channel(&mut reader, tx);

        assert_eq!(
            reader.calls, 1,
            "expected exactly one read before the dropped receiver was noticed"
        );
    }

    #[test]
    fn receiver_stream_yields_items_then_ends_when_the_sender_drops() {
        let rt = BackgroundRuntime::new().expect("failed to start the background runtime");
        let (tx, rx) = mpsc::channel::<u32>(BLOB_CHANNEL_CAPACITY);
        tx.try_send(1).unwrap();
        tx.try_send(2).unwrap();
        tx.try_send(3).unwrap();
        drop(tx);

        let items: Vec<u32> = rt.block_on(async move { receiver_stream(rx).collect().await });

        assert_eq!(items, vec![1, 2, 3]);
    }

    #[test]
    fn owned_layer_descriptor_copies_digest_and_urls() {
        let urls = Some(vec!["https://example.com/blob".to_string()]);
        let descriptor = LayerDescriptor {
            digest: "sha256:abc",
            urls: &urls,
        };

        let owned = OwnedLayerDescriptor::new(&descriptor);
        let copied = owned.as_layer_descriptor();

        assert_eq!(copied.digest, "sha256:abc");
        assert_eq!(copied.urls, &urls);
    }
}
