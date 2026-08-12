use std::borrow::Cow;
use std::io::{BufReader, BufWriter, Cursor};
use std::ops::DerefMut;
use std::path::Path;
use std::sync::Arc;

use async_compression::tokio::bufread::{BrotliDecoder, BrotliEncoder};
use axum::http::uri::{Authority, Scheme};
use axum::http::HeaderMap;
use axum::http::{uri, HeaderValue};
use axum::response::{IntoResponse, Response};
use color_eyre::eyre::{eyre, Context, OptionExt};
use regex::{Captures, Regex};
use reqwest::header::{ACCEPT_ENCODING, CONTENT_ENCODING, HOST, IF_MODIFIED_SINCE, IF_NONE_MATCH};
use reqwest::header::{CONTENT_TYPE, ETAG};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::instrument;

use crate::error::{PropogateRequest, WithStatusCode};
use crate::CacheMode;

#[derive(Clone)]
pub struct HttpCache {
    pub client: reqwest::Client,
    pub regexes: Arc<Regexes>,
}

pub struct Regexes {
    pub content_to_compress: Regex,
    pub jackbox_urls: Regex,
}

#[derive(Deserialize, Serialize)]
struct JBHttpResponse {
    etag: String,
    content_type: Option<String>,
    compressed: bool,
}

impl JBHttpResponse {
    fn from_request(
        value: &reqwest::Response,
        content_to_compress: &Regex,
    ) -> crate::error::Result<Self> {
        Ok(Self {
            etag: value
                .headers()
                .get(ETAG)
                .ok_or_eyre("Etag was not present in response")
                .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?
                .to_str()
                .wrap_err("Etag was not valid UTF-8")
                .with_status_code(StatusCode::UNPROCESSABLE_ENTITY)?
                .to_owned(),
            content_type: {
                if let Some(content_type) = value.headers().get(CONTENT_TYPE) {
                    let content_type = content_type
                        .to_str()
                        .wrap_err("Content-Type was not valid UTF-8")
                        .with_status_code(StatusCode::UNPROCESSABLE_ENTITY)?;

                    Some(content_type.to_owned())
                } else {
                    None
                }
            },
            compressed: value
                .headers()
                .get(CONTENT_TYPE)
                .is_some_and(|ct| content_to_compress.is_match(ct.to_str().unwrap_or_default())),
        })
    }

    fn headers(&self) -> crate::error::Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            ETAG,
            self.etag
                .as_str()
                .try_into()
                .wrap_err("Failed to convert Etag from String to HeaderValue")
                .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?,
        );
        if let Some(ref ct) = self.content_type {
            headers.insert(
                CONTENT_TYPE,
                ct.as_str()
                    .try_into()
                    .wrap_err("Failed to convert Content-Type from String to HeaderValue")
                    .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?,
            );
        }
        Ok(headers)
    }
}

impl HttpCache {
    #[instrument(skip(self, headers, uri))]
    pub async fn get_cached(
        &self,
        mut uri: uri::Uri,
        mut headers: HeaderMap,
        cache_mode: CacheMode,
        accessible_host: &str,
        cache_path: &Path,
    ) -> crate::error::Result<Response> {
        let mut uri_parts = uri.into_parts();
        if uri_parts
            .path_and_query
            .as_ref()
            .map(|pq| pq.path().starts_with("/@"))
            .unwrap_or_default()
        {
            let path = uri_parts.path_and_query.as_ref().unwrap().as_str();

            let path_split = path.split_once('@').unwrap().1;
            let path_split = path_split.split_once('/').unwrap_or((path_split, ""));
            let host = path_split.0;
            if !self.regexes.jackbox_urls.is_match(host) {
                return Err(eyre!("Proxy can only be used with Jackbox services"))
                    .with_status_code(StatusCode::BAD_REQUEST);
            }
            uri_parts.authority = Some(
                host.to_owned()
                    .try_into()
                    .wrap_err_with(|| format!("Failed to convert host `{}` into Authority", host))
                    .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?,
            );
            headers.insert(
                HOST,
                host.to_owned()
                    .try_into()
                    .wrap_err_with(|| format!("Failed to convert host `{}` into HeaderValue", host))
                    .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?,
            );
            let path_and_query = format!("/{}", path_split.1);
            *uri_parts.path_and_query.as_mut().unwrap() = path_and_query
                .as_str()
                .try_into()
                .wrap_err_with(|| {
                    format!(
                        "Failed to convert `{}` to a URI path & query",
                        path_and_query
                    )
                })
                .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?;
        } else {
            uri_parts.authority = Some(Authority::from_static("jackbox.tv"));
            headers.insert(HOST, HeaderValue::from_static("jackbox.tv"));
        }
        uri_parts.scheme = Some(Scheme::HTTPS);
        uri = uri::Uri::from_parts(uri_parts)
            .wrap_err("URI parts did not make a valid URI")
            .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?;

        headers.remove(IF_MODIFIED_SINCE);

        let br = headers
            .get(ACCEPT_ENCODING)
            .as_ref()
            .map(|e| e.to_str())
            .into_iter()
            .flatten()
            .flat_map(|e| e.split(','))
            .any(|s| s.trim() == "br");

        match headers.entry(ACCEPT_ENCODING) {
            reqwest::header::Entry::Occupied(e) => {
                e.remove_entry_mult();
            }
            _ => {}
        }

        let cached_resource_raw = cache_path.join(format!(
            "{}/{}",
            uri.host()
                .ok_or_else(|| eyre!("URI `{}` did not have a host", uri))
                .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?,
            if uri.path() == "/" {
                "index.html"
            } else {
                uri.path()
            }
        ));
        let mut reqwest_resp = if matches!(cache_mode, CacheMode::Offline)
            || (matches!(cache_mode, CacheMode::Oneshot) && cached_resource_raw.exists())
        {
            None
        } else {
            Some(
                self.client
                    .get(format!("{}", uri))
                    .headers(headers.clone())
                    .send()
                    .await
                    .wrap_err_with(|| format!("Failed to acquire resource from `{}`", uri))
                    .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?
                    .propogate_request_if_err()?,
            )
        };
        let mut resp = if let Some(ref resp) = reqwest_resp {
            JBHttpResponse::from_request(resp, &self.regexes.content_to_compress)?
        } else {
            serde_json::from_reader(BufReader::new(
                std::fs::File::open(&cached_resource_raw)
                    .wrap_err_with(|| {
                        format!(
                            "The offline resource `{}` could not be found",
                            cached_resource_raw.display()
                        )
                    })
                    .with_status_code(StatusCode::NOT_FOUND)?,
            ))
            .wrap_err_with(|| {
                format!(
                    "The offline resource `{}` could not be deserialized",
                    cached_resource_raw.display()
                )
            })
            .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?
        };

        let mut cached_resource = if resp.compressed {
            cache_path.join(format!("{}/{}.br", uri.host().unwrap(), resp.etag))
        } else {
            cache_path.join(format!("{}/{}", uri.host().unwrap(), resp.etag))
        };

        let part_path = cached_resource.with_extension("part.br");
        let cached_resource_dir = cached_resource
            .parent()
            .ok_or_else(|| {
                eyre!(
                    "The cached resource `{}` has no parent directory",
                    cached_resource.display()
                )
            })
            .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?;
        tokio::fs::create_dir_all(cached_resource_dir)
            .await
            .wrap_err_with(|| {
                format!(
                    "The directory `{}` could not be created for the cached resource",
                    cached_resource_dir.display()
                )
            })
            .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?;

        if reqwest_resp
            .as_ref()
            .map(|r| r.status() == StatusCode::NOT_MODIFIED)
            .unwrap_or(true)
            && !cached_resource.exists()
        {
            headers.remove(IF_NONE_MATCH);
            reqwest_resp = if matches!(cache_mode, CacheMode::Online) {
                None
            } else {
                Some(
                    self.client
                        .get(format!("{}", uri))
                        .headers(headers.clone())
                        .send()
                        .await
                        .wrap_err_with(|| {
                            format!(
                                "Failed to acquire resource from `{}` (with stripped Etag)",
                                uri
                            )
                        })
                        .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?
                        .propogate_request_if_err()?,
                )
            };
            resp = if let Some(ref resp) = reqwest_resp {
                JBHttpResponse::from_request(resp, &self.regexes.content_to_compress)?
            } else {
                serde_json::from_reader(BufReader::new(
                    std::fs::File::open(&cached_resource_raw)
                        .wrap_err_with(|| {
                            format!(
                                "The offline resource `{}` could not be found (stripped Etag)",
                                cached_resource_raw.display()
                            )
                        })
                        .with_status_code(StatusCode::NOT_FOUND)?,
                ))
                .wrap_err_with(|| {
                    format!(
                        "The offline resource `{}` could not be deserialized (stripped Etag)",
                        cached_resource_raw.display()
                    )
                })
                .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?
            };
            cached_resource = if resp.compressed {
                cache_path.join(format!("{}/{}.br", uri.host().unwrap(), resp.etag))
            } else {
                cache_path.join(format!("{}/{}", uri.host().unwrap(), resp.etag))
            };
        }

        if !cached_resource.exists() {
            let mut part_file = fd_lock::RwLock::new(
                tokio::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(&part_path)
                    .await
                    .wrap_err_with(|| {
                        format!(
                            "Failed to open/create part file for resource `{}`",
                            part_path.display()
                        )
                    })
                    .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?,
            );
            let mut part_file_w = part_file
                .write()
                .wrap_err_with(|| {
                    format!(
                        "Failed to open part file for writing for resource `{}`",
                        part_path.display()
                    )
                })
                .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?;
            if reqwest_resp
                .as_ref()
                .map(|r| r.status() == StatusCode::NOT_MODIFIED)
                .unwrap_or(true)
                || cached_resource.exists()
            {
                drop(part_file_w);
                let _ = tokio::fs::remove_file(&part_path).await;
            } else {
                let response = reqwest_resp
                    .unwrap()
                    .bytes()
                    .await
                    .wrap_err_with(|| {
                        format!("Failed to retreive bytes for URL with path: `{}`", uri)
                    })
                    .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?;

                let mut text = None;
                let response: Cow<'_, [u8]> = if resp
                    .headers()?
                    .get(CONTENT_TYPE)
                    .map(|c| {
                        c == "text/html"
                            || c == "text/javascript"
                            || c == "application.json"
                            || c == "text/css"
                    })
                    .unwrap_or_default()
                {
                    let text = text.get_or_insert(String::from_utf8_lossy(&response));
                    let result = self
                        .regexes
                        .jackbox_urls
                        .replace_all(text, |c: &Captures<'_>| {
                            format!("{}/@{}", accessible_host, c.get_match().as_str())
                        });
                    match result {
                        Cow::Borrowed(s) => Cow::Borrowed(s.as_bytes()),
                        Cow::Owned(s) => Cow::Owned(s.into_bytes()),
                    }
                } else {
                    Cow::Owned(response.into())
                };
                if resp.compressed {
                    let mut stream = BrotliEncoder::with_quality(
                        Cursor::new(response),
                        async_compression::Level::Best,
                    );

                    let mut file = tokio::io::BufWriter::new(part_file_w.deref_mut());

                    tokio::io::copy(&mut stream, &mut file)
                        .await
                        .wrap_err("Failed to copy byte stream to a compressed brotli file")
                        .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?;

                    file.shutdown()
                        .await
                        .wrap_err("Failed to shutdown compressed brotli file stream")
                        .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?;
                } else {
                    let mut stream = Cursor::new(response);
                    let mut file = tokio::io::BufWriter::new(part_file_w.deref_mut());

                    tokio::io::copy(&mut stream, &mut file)
                        .await
                        .wrap_err("Failed to copy byte stream to an uncompressed file")
                        .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?;

                    file.shutdown()
                        .await
                        .wrap_err("Failed to shutdown uncompressed file stream")
                        .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?;
                }
                let cached_resource_raw_dir = cached_resource_raw
                    .parent()
                    .ok_or_else(|| {
                        eyre!(
                            "Raw cached resource `{}` does not have a parent directory",
                            cached_resource_raw.display()
                        )
                    })
                    .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?;
                tokio::fs::create_dir_all(cached_resource_raw_dir)
                    .await
                    .wrap_err_with(|| {
                        format!(
                            "Failed to create directory for raw resource `{}`",
                            cached_resource_raw_dir.display()
                        )
                    })
                    .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?;
                serde_json::to_writer(
                    BufWriter::new(
                        std::fs::File::create(&cached_resource_raw)
                            .wrap_err_with(|| {
                                format!(
                                    "Failed to create file for raw resource `{}`",
                                    cached_resource_raw.display()
                                )
                            })
                            .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?,
                    ),
                    &resp,
                )
                .wrap_err_with(|| {
                    format!(
                        "Failed to serialize raw resource `{}`",
                        cached_resource_raw.display()
                    )
                })
                .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?;
                tokio::fs::rename(&part_path, &cached_resource)
                    .await
                    .wrap_err_with(|| {
                        format!(
                            "Failed to move part file `{}` into it's cached resource path `{}`",
                            part_path.display(),
                            cached_resource.display()
                        )
                    })
                    .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?;
            }
        }

        // let status_code = if headers
        //     .get(IF_NONE_MATCH)
        //     .map(|ct| ct.as_bytes() != resp.etag.as_bytes())
        //     .unwrap_or(true)
        // {
        //     StatusCode::OK
        // } else {
        //     StatusCode::NOT_MODIFIED
        // };

        let status_code = StatusCode::OK;

        let mut resp_headers = resp.headers()?;
        let content_type = resp_headers.get(CONTENT_TYPE).cloned();
        if br {
            if resp.compressed {
                resp_headers.insert(CONTENT_ENCODING, HeaderValue::from_static("br"));
            }
            let mut resp = (
                status_code,
                resp_headers,
                tokio::fs::read(&cached_resource)
                    .await
                    .wrap_err_with(|| {
                        format!(
                            "Failed to read cached resource `{}`",
                            cached_resource.display()
                        )
                    })
                    .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?,
            )
                .into_response();
            if let Some(t) = content_type {
                resp.headers_mut().insert(CONTENT_TYPE, t);
            }
            return Ok(resp);
        } else {
            resp_headers.remove(CONTENT_ENCODING);
            let mut buf = Vec::with_capacity(
                tokio::fs::metadata(&cached_resource)
                    .await
                    .wrap_err_with(|| {
                        format!(
                            "Failed to read metadata for cached resource `{}`",
                            cached_resource.display()
                        )
                    })
                    .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?
                    .len() as usize,
            );
            let mut resp = if resp.compressed {
                (status_code, resp_headers, {
                    BrotliDecoder::new(tokio::io::BufReader::new(
                        tokio::fs::File::open(&cached_resource)
                            .await
                            .wrap_err_with(|| {
                                format!(
                                    "Failed to open cached resource `{}`",
                                    cached_resource.display()
                                )
                            })
                            .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?,
                    ))
                    .read_to_end(&mut buf)
                    .await
                    .wrap_err_with(|| {
                        format!(
                            "Failed to decompress cached resource `{}`",
                            cached_resource.display()
                        )
                    })
                    .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?;
                    buf
                })
                    .into_response()
            } else {
                (status_code, resp_headers, {
                    tokio::io::BufReader::new(
                        tokio::fs::File::open(&cached_resource)
                            .await
                            .wrap_err_with(|| {
                                format!(
                                    "Failed to open cached resource `{}`",
                                    cached_resource.display()
                                )
                            })
                            .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?,
                    )
                    .read_to_end(&mut buf)
                    .await
                    .wrap_err_with(|| {
                        format!(
                            "Failed to read cached resource `{}`",
                            cached_resource.display()
                        )
                    })
                    .with_status_code(StatusCode::INTERNAL_SERVER_ERROR)?;
                    buf
                })
                    .into_response()
            };
            if let Some(t) = content_type {
                resp.headers_mut().insert(CONTENT_TYPE, t);
            }
            return Ok(resp);
        }
    }
}
