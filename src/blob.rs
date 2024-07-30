//! Helpers for interacting with blobs and their verification
use std::task::Poll;

use futures_util::stream::{BoxStream, Stream};
use sha2::Digest;

use crate::errors::{ContentDigestVerificationError, OciDistributionError};

/// Stream response of a blob with optional content length if available
pub struct SizedStream {
    /// The length of the stream if the upstream registry sent a `Content-Length` header
    pub content_length: Option<u64>,
    /// The stream of bytes
    pub stream: BoxStream<'static, Result<bytes::Bytes, std::io::Error>>,
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
    digester: Digester,
    expected_digest: String,
}

impl VerifyingStream {
    pub fn new(
        stream: BoxStream<'static, Result<bytes::Bytes, std::io::Error>>,
        digester: Digester,
        expected_digest: String,
    ) -> Self {
        Self {
            stream,
            digester,
            expected_digest,
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
        match futures_util::ready!(this.stream.as_mut().poll_next(cx)) {
            Some(Ok(bytes)) => {
                this.digester.update(&bytes);
                Poll::Ready(Some(Ok(bytes)))
            }
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => {
                // Now that we've reached the end of the stream, verify the digest
                let digest = this.digester.finalize();
                if digest == this.expected_digest {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        ContentDigestVerificationError {
                            expected: this.expected_digest.clone(),
                            actual: digest,
                        },
                    ))))
                }
            }
        }
    }
}

/// Helper wrapper around various digest algorithms to make it easier to use them with our blob
/// utils. This has to be an enum because the digest algorithms aren't object safe so we can't box
/// dynner them
pub(crate) enum Digester {
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

impl Digester {
    pub fn new(digest: &str) -> crate::errors::Result<Self> {
        let (algo, _) = digest.split_once(':').ok_or_else(|| {
            OciDistributionError::GenericError(Some(format!(
                "Digest header value is not in the expected format: {}",
                digest
            )))
        })?;

        match algo {
            "sha256" => Ok(Digester::Sha256(sha2::Sha256::new())),
            "sha384" => Ok(Digester::Sha384(sha2::Sha384::new())),
            "sha512" => Ok(Digester::Sha512(sha2::Sha512::new())),
            _ => Err(OciDistributionError::GenericError(Some(format!(
                "Unsupported digest algorithm: {}",
                algo
            )))),
        }
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        match self {
            Self::Sha256(d) => d.update(data),
            Self::Sha384(d) => d.update(data),
            Self::Sha512(d) => d.update(data),
        }
    }

    pub fn finalize(&mut self) -> String {
        match self {
            Self::Sha256(d) => format!("sha256:{:x}", d.finalize_reset()),
            Self::Sha384(d) => format!("sha384:{:x}", d.finalize_reset()),
            Self::Sha512(d) => format!("sha512:{:x}", d.finalize_reset()),
        }
    }
}
