//! AWS Smithy HTTP transport using Wreq and the shared BTLS provider.

use std::{
    collections::HashMap,
    sync::{Mutex, PoisonError},
    time::Duration,
};

use aws_smithy_runtime_api::client::{
    http::{
        HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpClient,
        SharedHttpConnector, http_client_fn,
    },
    orchestrator::{HttpRequest, HttpResponse},
    result::ConnectorError,
};
use aws_smithy_types::body::SdkBody;

type Timeouts = (Option<Duration>, Option<Duration>);

#[derive(Debug)]
struct Connector {
    client: Result<wreq::Client, String>,
    read_timeout: Option<Duration>,
}

impl Connector {
    fn new((connect_timeout, read_timeout): Timeouts) -> Self {
        // Smithy's request is already signed. Do not follow redirects or
        // apply browser emulation/decompression to a signed service request.
        let mut builder = wreq::Client::builder()
            .http1_only()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .redirect(wreq::redirect::Policy::none());
        if let Some(timeout) = connect_timeout {
            builder = builder.connect_timeout(timeout);
        }
        Self {
            client: builder.build().map_err(|error| error.to_string()),
            read_timeout,
        }
    }
}

fn transport_error(error: wreq::Error) -> ConnectorError {
    if error.is_timeout() {
        ConnectorError::timeout(Box::new(error))
    } else if error.is_connect() {
        ConnectorError::io(Box::new(error)).never_connected()
    } else if error.is_builder() {
        ConnectorError::user(Box::new(error))
    } else {
        ConnectorError::io(Box::new(error))
    }
}

impl HttpConnector for Connector {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let client = self.client.clone();
        let read_timeout = self.read_timeout;
        HttpConnectorFuture::new(async move {
            let client = client
                .map_err(|error| ConnectorError::user(Box::new(std::io::Error::other(error))))?;
            let request = request
                .try_into_http1x()
                .map_err(|error| ConnectorError::user(Box::new(error)))?
                .map(wreq::Body::wrap);
            let send = client.execute(wreq::Request::from(request));
            let response = if let Some(timeout) = read_timeout {
                tokio::time::timeout(timeout, send)
                    .await
                    .map_err(|error| ConnectorError::timeout(Box::new(error)))?
            } else {
                send.await
            }
            .map_err(transport_error)?;
            let response: http::Response<wreq::Body> = response.into();
            HttpResponse::try_from(response.map(SdkBody::from_body_1_x))
                .map_err(|error| ConnectorError::user(Box::new(error)))
        })
    }
}

/// Create a pooled Smithy HTTP client with Wreq/BTLS instead of Rustls.
///
/// Connector settings are cached by timeout pair, retaining connection reuse
/// while honoring per-operation overrides. Request and response bodies are
/// forwarded as HTTP body frames, without collecting or re-signing them.
#[must_use = "the returned client must be installed in the service configuration"]
pub fn http_client() -> SharedHttpClient {
    let connectors = Mutex::new(HashMap::<Timeouts, SharedHttpConnector>::new());
    http_client_fn(move |settings: &HttpConnectorSettings, _| {
        let timeouts = (settings.connect_timeout(), settings.read_timeout());
        connectors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(timeouts)
            .or_insert_with(|| SharedHttpConnector::new(Connector::new(timeouts)))
            .clone()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use http_body_util::BodyExt as _;
    use tokio::{
        io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
        net::TcpListener,
    };

    #[tokio::test]
    async fn forwards_signed_request_and_response_without_redirect_or_decompression() -> Result<()>
    {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut stream = BufReader::new(stream);
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                if stream.read_line(&mut line).await? == 0 {
                    anyhow::bail!("truncated request headers");
                }
                if line == "\r\n" {
                    break;
                }
                headers.push_str(&line);
            }
            let mut payload = [0; 3];
            stream.read_exact(&mut payload).await?;
            assert_eq!(&payload, b"abc");
            let lower = headers.to_ascii_lowercase();
            assert!(headers.starts_with("PUT /bucket/object%20name HTTP/1.1\r\n"));
            assert!(lower.contains("authorization: aws4-hmac-sha256 test-signature\r\n"));
            assert!(!lower.contains("accept-encoding:"));
            stream.get_mut().write_all(
                b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /other\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\nConnection: close\r\n\r\nxyz"
            ).await?;
            Ok::<_, anyhow::Error>(())
        });
        let connector =
            Connector::new((Some(Duration::from_secs(5)), Some(Duration::from_secs(5))));
        let request = http::Request::put(format!("http://{address}/bucket/object%20name"))
            .header("authorization", "AWS4-HMAC-SHA256 test-signature")
            .header("content-length", "3")
            .body(SdkBody::from("abc"))?;
        let response = connector.call(HttpRequest::try_from(request)?).await?;
        let response = response.try_into_http1x()?;
        assert_eq!(response.status(), http::StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(response.headers()["content-encoding"], "gzip");
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .map_err(anyhow::Error::msg)?
                .to_bytes(),
            "xyz"
        );
        server.await??;
        Ok(())
    }
}
