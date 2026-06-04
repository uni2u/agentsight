// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::server::assets::FrontendAssets;
use crate::sources::agent_native::{self as agent_native_sessions, SessionCache};
use crate::view::SharedMaterializedView;
use crate::view::types::SnapshotOptions;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, body::Bytes};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use serde_json::Value;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;

pub struct WebServer {
    assets: Arc<FrontendAssets>,
    view: SharedMaterializedView,
    agent_native_sessions: Arc<Mutex<SessionCache>>,
}

impl WebServer {
    pub fn new(
        view: SharedMaterializedView,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let assets = FrontendAssets::new()?;
        Ok(Self {
            assets: Arc::new(assets),
            view,
            agent_native_sessions: Arc::new(Mutex::new(SessionCache::new())),
        })
    }

    pub async fn start(
        &self,
        addr: SocketAddr,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        log::info!("🚀 Frontend server running on http://{}", addr);

        // List embedded assets for debugging
        let all_assets = self.assets.list_all_assets();
        log::info!(
            "📦 Embedded {} assets from frontend/dist:",
            all_assets.len()
        );
        for asset in all_assets.iter().take(10) {
            log::info!("   - {}", asset);
        }
        if all_assets.len() > 10 {
            log::info!("   ... and {} more", all_assets.len() - 10);
        }

        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            let assets = Arc::clone(&self.assets);
            let view = Arc::clone(&self.view);
            let agent_native_sessions = Arc::clone(&self.agent_native_sessions);

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |req| {
                    handle_request(
                        req,
                        assets.clone(),
                        view.clone(),
                        agent_native_sessions.clone(),
                    )
                });

                if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                    log::error!("❌ Error serving connection: {:?}", err);
                }
            });
        }
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    assets: Arc<FrontendAssets>,
    view: SharedMaterializedView,
    agent_native_sessions: Arc<Mutex<SessionCache>>,
) -> std::result::Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path();
    let query = req.uri().query().map(str::to_string);

    log::info!("📨 {} {}", req.method(), path);

    let response = if req.method() == Method::GET
        && let Some(resource) = api_resource_for_path(path)
    {
        serve_view_api(view, agent_native_sessions, query.as_deref(), resource).await?
    } else {
        match (req.method(), path) {
            (&Method::GET, "/api/assets") => serve_assets_list(assets).await?,
            // Serve static assets (catch-all for GET requests)
            (&Method::GET, _) => serve_asset(assets, path).await?,

            // 404 for non-GET methods
            _ => {
                log::info!("❌ 404 Not Found: {} {}", req.method(), path);
                plain_response(StatusCode::NOT_FOUND, "text/plain", b"Not Found".to_vec())
            }
        }
    };

    Ok(response)
}

async fn serve_asset(
    assets: Arc<FrontendAssets>,
    path: &str,
) -> std::result::Result<Response<Full<Bytes>>, Infallible> {
    if let Some(content) = assets.get(path) {
        let content_type = assets.get_content_type(path);
        log::info!("✅ Serving asset: {} ({})", path, content_type);
        Ok(plain_response(StatusCode::OK, &content_type, content.to_vec()))
    } else if is_frontend_route(path) {
        let content = assets
            .get("/")
            .unwrap_or_else(|| Bytes::new().to_vec().into());
        log::info!("✅ Serving frontend route: {}", path);
        Ok(plain_response(StatusCode::OK, "text/html", content.to_vec()))
    } else {
        log::info!("❌ Asset not found: {}", path);
        Ok(plain_response(StatusCode::NOT_FOUND, "text/plain", b"Asset not found".to_vec()))
    }
}

fn is_frontend_route(path: &str) -> bool {
    !path.starts_with("/api/")
        && !path
            .rsplit('/')
            .next()
            .is_some_and(|name| name.contains('.'))
}

#[derive(Debug, Clone, Copy)]
enum ApiResource {
    Snapshot,
    Summary,
    TokenSummary,
    AuditEvents,
    ProcessNodes,
    Sessions,
}

fn api_resource_for_path(path: &str) -> Option<ApiResource> {
    match path {
        "/api/v1/snapshot" => Some(ApiResource::Snapshot),
        "/api/v1/summary" => Some(ApiResource::Summary),
        "/api/v1/token-summary" => Some(ApiResource::TokenSummary),
        "/api/v1/audit-events" => Some(ApiResource::AuditEvents),
        "/api/v1/process-nodes" => Some(ApiResource::ProcessNodes),
        "/api/v1/sessions" => Some(ApiResource::Sessions),
        _ => None,
    }
}

async fn serve_view_api(
    view: SharedMaterializedView,
    agent_native_sessions: Arc<Mutex<SessionCache>>,
    query: Option<&str>,
    resource: ApiResource,
) -> std::result::Result<Response<Full<Bytes>>, Infallible> {
    let audit_limit = query_param_usize(query, "audit_limit").unwrap_or(10_000);
    let group_by = query_param(query, "group_by").unwrap_or_else(|| "model".to_string());

    let result = tokio::task::spawn_blocking(
        move || -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
            let agent_native_rows = agent_native_sessions
                .lock()
                .map_err(|_| std::io::Error::other("agent-native session cache lock poisoned"))?
                .discover_cached(25, Duration::from_secs(2));
            let value = match resource {
                ApiResource::TokenSummary => {
                    let rows = {
                        let mut view = view
                            .lock()
                            .map_err(|_| std::io::Error::other("live view lock poisoned"))?;
                        agent_native_sessions::import_into_view(&mut view, &agent_native_rows);
                        view.token_summary(&group_by)
                    };
                    serde_json::to_value(rows)?
                }
                _ => {
                    let snapshot = {
                        let mut view = view
                            .lock()
                            .map_err(|_| std::io::Error::other("live view lock poisoned"))?;
                        agent_native_sessions::import_into_view(&mut view, &agent_native_rows);
                        view.export_snapshot(SnapshotOptions { audit_limit })
                    };
                    match resource {
                        ApiResource::Snapshot => serde_json::to_value(snapshot)?,
                        ApiResource::Summary => serde_json::to_value(snapshot.summary)?,
                        ApiResource::AuditEvents => serde_json::to_value(snapshot.audit_events)?,
                        ApiResource::ProcessNodes => serde_json::to_value(snapshot.process_nodes)?,
                        ApiResource::Sessions => serde_json::to_value(snapshot.sessions)?,
                        ApiResource::TokenSummary => unreachable!(),
                    }
                }
            };
            Ok(value)
        },
    )
    .await;

    match result {
        Ok(Ok(value)) => Ok(json_response(StatusCode::OK, &value)),
        Ok(Err(e)) => Ok(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to query view data: {}", e),
        )),
        Err(e) => Ok(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("view query task failed: {}", e),
        )),
    }
}

async fn serve_assets_list(
    assets: Arc<FrontendAssets>,
) -> std::result::Result<Response<Full<Bytes>>, Infallible> {
    let all_assets = assets.list_all_assets();
    let response = serde_json::json!({
        "assets": all_assets,
        "total_count": all_assets.len()
    });

    log::info!("📋 Serving assets list ({} assets)", all_assets.len());
    Ok(json_response(StatusCode::OK, &response))
}

fn plain_response(status: StatusCode, content_type: &str, body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .header("Access-Control-Allow-Origin", "*")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    plain_response(status, "application/json", body)
}

fn json_error(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    json_response(status, &serde_json::json!({ "error": message }))
}

fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    query?
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find_map(|(key, value)| (key == name).then(|| value.to_string()))
}

fn query_param_usize(query: Option<&str>, name: &str) -> Option<usize> {
    query_param(query, name).and_then(|value| value.parse::<usize>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_api_query_parameters() {
        let query = Some("audit_limit=9&group_by=provider");

        assert_eq!(query_param_usize(query, "audit_limit"), Some(9));
        assert_eq!(query_param(query, "group_by").as_deref(), Some("provider"));
        assert_eq!(query_param(query, "missing"), None);
    }
}
