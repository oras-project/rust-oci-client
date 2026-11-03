//! Helpers for interacting with blobs and their verification
use std::task::Poll;

use futures_util::stream::{BoxStream, Stream};
use futures_util::TryStreamExt;

use crate::digest::Digester;
use crate::errors::DigestError;

/// Stream response of a blob with optional content length if available
pub struct SizedStream {
    /// The length of the stream, taken from the body of the response or from
    /// the `Content-Length` header. If the client cannot find the length,
    /// this field is `None`.
    pub content_length: Option<u64>,
    /// The digest header value if the upstream registry sent a `Digest` header. This should be used
    /// (in addition to the layer digest) for validation when using partial requests as the library
    /// can't validate against the full response.
    pub digest_header_value: Option<String>,
    /// The stream of bytes
    pub stream: BoxStream<'static, Result<bytes::Bytes, std::io::Error>>,
}

impl Stream for SizedStream {
    type Item = Result<bytes::Bytes, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.stream.try_poll_next_unpin(cx)
    }
}

/// The response of a partial blob request
pub enum BlobResponse {
    /// The response is a full blob (for example when partial requests aren't supported)
    Full(SizedStream),
    /// The response is a partial blob as requested
    Partial(SizedStream),
}

pub(crate) struct VerifyingStream {
    stream: BoxStream<'static, Result<bytes::Bytes, std::io::Error>>,
    layer_digester: Digester,
    expected_layer_digest: String,
    header_digester: Option<(Digester, String)>,
    /// `true` once the stream has returned its last item, either `None`
    /// or the digest-mismatch error that takes its place. A `Digester`
    /// resets itself when it finalizes, so finalizing a second time
    /// would check the blob's digest against the digest of an empty
    /// body. This flag stops that: every poll after the first `None`
    /// returns `None` again, with no new finalize.
    done: bool,
}

impl VerifyingStream {
    pub fn new(
        stream: BoxStream<'static, Result<bytes::Bytes, std::io::Error>>,
        layer_digester: Digester,
        expected_layer_digest: String,
        header_digester_and_digest: Option<(Digester, String)>,
    ) -> Self {
        Self {
            stream,
            layer_digester,
            expected_layer_digest,
            header_digester: header_digester_and_digest,
            done: false,
        }
    }
}

impl Stream for VerifyingStream {
    type Item = Result<bytes::Bytes, std::io::Error>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        match futures_util::ready!(this.stream.as_mut().poll_next(cx)) {
            Some(Ok(bytes)) => {
                this.layer_digester.update(&bytes);
                if let Some((digester, _)) = this.header_digester.as_mut() {
                    digester.update(&bytes);
                }
                Poll::Ready(Some(Ok(bytes)))
            }
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => {
                // Now that we've reached the end of the stream, verify
                // the digest(s). This is the last poll that touches
                // either `Digester`; mark the stream done before it
                // runs, so a later poll cannot run it again.
                this.done = true;
                match this.header_digester.as_mut() {
                    Some((digester, expected)) => {
                        // Check the header digester and then the layer digester before returning
                        let digest = digester.finalize();
                        if digest != *expected {
                            return Poll::Ready(Some(Err(std::io::Error::other(
                                DigestError::VerificationError {
                                    expected: expected.clone(),
                                    actual: digest,
                                },
                            ))));
                        }
                        let digest = this.layer_digester.finalize();
                        if digest == this.expected_layer_digest {
                            Poll::Ready(None)
                        } else {
                            Poll::Ready(Some(Err(std::io::Error::other(
                                DigestError::VerificationError {
                                    expected: this.expected_layer_digest.clone(),
                                    actual: digest,
                                },
                            ))))
                        }
                    }
                    None => {
                        let digest = this.layer_digester.finalize();
                        if digest == this.expected_layer_digest {
                            Poll::Ready(None)
                        } else {
                            Poll::Ready(Some(Err(std::io::Error::other(
                                DigestError::VerificationError {
                                    expected: this.expected_layer_digest.clone(),
                                    actual: digest,
                                },
                            ))))
                        }
                    }
                }
            }
        }
    }
}

impl futures_util::stream::FusedStream for VerifyingStream {
    fn is_terminated(&self) -> bool {
        self.done
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bytes::Bytes;
    use futures_util::TryStreamExt;
    use sha2::Digest as _;

    #[tokio::test]
    async fn test_verifying_stream() {
        // Test with correct SHA
        let data = b"Hello, world!";
        let correct_sha = format!("sha256:{}", hex::encode(sha2::Sha256::digest(data)));
        let stream = VerifyingStream::new(
            Box::pin(futures_util::stream::iter(vec![Ok(Bytes::from_static(
                data,
            ))])),
            Digester::new(&correct_sha).unwrap(),
            correct_sha.clone(),
            None,
        );
        stream
            .try_collect::<Vec<_>>()
            .await
            .expect("Should not error with valid data");

        // Test with incorrect SHA
        let incorrect_sha = "sha256:incorrect_hash";
        let stream = VerifyingStream::new(
            Box::pin(futures_util::stream::iter(vec![Ok(Bytes::from_static(
                data,
            ))])),
            Digester::new(incorrect_sha).unwrap(),
            incorrect_sha.to_string(),
            None,
        );

        let err = stream
            .try_collect::<Vec<_>>()
            .await
            .expect_err("Should error with invalid sha");

        let err = err
            .into_inner()
            .expect("Should have inner error")
            .downcast::<DigestError>()
            .expect("Should be a DigestError");
        assert!(
            matches!(*err, DigestError::VerificationError { .. }),
            "Error should be a verification error"
        );

        // Test with correct SHA and header
        let correct_header_sha = format!("sha512:{}", hex::encode(sha2::Sha512::digest(data)));
        let stream = VerifyingStream::new(
            Box::pin(futures_util::stream::iter(vec![Ok(Bytes::from_static(
                data,
            ))])),
            Digester::new(&correct_sha).unwrap(),
            correct_sha.clone(),
            Some((
                Digester::new(&correct_header_sha).unwrap(),
                correct_header_sha.clone(),
            )),
        );
        stream
            .try_collect::<Vec<_>>()
            .await
            .expect("Should not error with valid data");

        // Test with correct layer sha and wrong header sha
        let incorrect_header_sha = "sha512:incorrect_hash";
        let stream = VerifyingStream::new(
            Box::pin(futures_util::stream::iter(vec![Ok(Bytes::from_static(
                data,
            ))])),
            Digester::new(&correct_sha).unwrap(),
            correct_sha.clone(),
            Some((
                Digester::new(incorrect_header_sha).unwrap(),
                incorrect_header_sha.to_string(),
            )),
        );

        let err = stream
            .try_collect::<Vec<_>>()
            .await
            .expect_err("Should error with invalid sha");

        let err = err
            .into_inner()
            .expect("Should have inner error")
            .downcast::<DigestError>()
            .expect("Should be a DigestError");
        assert!(
            matches!(*err, DigestError::VerificationError { .. }),
            "Error should be a verification error"
        );
    }

    /// A poll after `VerifyingStream` has already returned `None`
    /// returns `None` again. It must not run the digest check a second
    /// time. `Digester::finalize` resets its state, so a second run
    /// would check the blob's digest against the digest of an empty
    /// body, and report a mismatch for a blob that already verified.
    #[tokio::test]
    async fn verifying_stream_returns_none_again_after_a_clean_end() {
        use futures_util::StreamExt;

        let data = b"Hello, world!";
        let correct_sha = format!("sha256:{}", hex::encode(sha2::Sha256::digest(data)));
        let mut stream = VerifyingStream::new(
            Box::pin(futures_util::stream::iter(vec![Ok(Bytes::from_static(
                data,
            ))])),
            Digester::new(&correct_sha).unwrap(),
            correct_sha,
            None,
        );

        assert!(stream.next().await.unwrap().is_ok());
        assert!(stream.next().await.is_none());
        assert!(
            stream.next().await.is_none(),
            "a second poll after a clean end must not run the digest check again"
        );
    }

    /// A poll after `VerifyingStream` has already reported a digest
    /// mismatch returns `None`, not a second, different error. The
    /// first poll past the end of the data is the one that runs the
    /// digest check and reports the mismatch; every poll after that
    /// must leave the check alone.
    #[tokio::test]
    async fn verifying_stream_returns_none_after_it_reported_a_mismatch() {
        use futures_util::StreamExt;

        let data = b"Hello, world!";
        let incorrect_sha = "sha256:incorrect_hash";
        let mut stream = VerifyingStream::new(
            Box::pin(futures_util::stream::iter(vec![Ok(Bytes::from_static(
                data,
            ))])),
            Digester::new(incorrect_sha).unwrap(),
            incorrect_sha.to_string(),
            None,
        );

        assert!(stream.next().await.unwrap().is_ok());
        let err = stream
            .next()
            .await
            .expect("expected the mismatch error")
            .expect_err("expected an error");
        let err = err
            .into_inner()
            .expect("Should have inner error")
            .downcast::<DigestError>()
            .expect("Should be a DigestError");
        assert!(
            matches!(*err, DigestError::VerificationError { .. }),
            "Error should be a verification error"
        );

        assert!(
            stream.next().await.is_none(),
            "a poll after the mismatch must not report a second, different error"
        );
    }

    /// When the header digest matches but the layer digest does not,
    /// the error must report the layer's own expected digest, not the
    /// header's. The two can use different algorithms, so reporting
    /// the wrong one is misleading on its own, on top of naming the
    /// wrong digest.
    #[tokio::test]
    async fn verifying_stream_reports_the_layer_digest_when_only_the_layer_mismatches() {
        let data = b"Hello, world!";
        let header_sha = format!("sha512:{}", hex::encode(sha2::Sha512::digest(data)));
        let wrong_layer_sha = "sha256:incorrect_hash";
        let stream = VerifyingStream::new(
            Box::pin(futures_util::stream::iter(vec![Ok(Bytes::from_static(
                data,
            ))])),
            Digester::new(wrong_layer_sha).unwrap(),
            wrong_layer_sha.to_string(),
            Some((Digester::new(&header_sha).unwrap(), header_sha.clone())),
        );

        let err = stream
            .try_collect::<Vec<_>>()
            .await
            .expect_err("Should error with invalid layer sha");
        let err = err
            .into_inner()
            .expect("Should have inner error")
            .downcast::<DigestError>()
            .expect("Should be a DigestError");
        match *err {
            DigestError::VerificationError { expected, .. } => {
                assert_eq!(
                    expected, wrong_layer_sha,
                    "the error must report the layer digest, not the header digest, \
                     as the expected value"
                );
            }
            other => panic!("unexpected error {other:?}"),
        }
    }
}
