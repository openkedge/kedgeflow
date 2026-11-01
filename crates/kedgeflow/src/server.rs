//! Native HTTP/1.1 TLS listener. Only a completed verified client handshake
//! creates the workload identity passed to the gateway.
use crate::{auth::WorkloadIdentity, endpoint::EndpointPolicy, error::Result, gateway::Gateway};
use axum::{
    Extension, Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};
use tokio_rustls::TlsAcceptor;

#[derive(Clone)]
pub(crate) struct Lifecycle(Arc<AtomicBool>);
impl Lifecycle {
    pub(crate) fn serving(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
async fn refuse_during_drain(
    State(lifecycle): State<Lifecycle>,
    request: Request,
    next: axum::middleware::Next,
) -> Response {
    if !lifecycle.serving() {
        return refusal(StatusCode::SERVICE_UNAVAILABLE);
    }
    next.run(request).await
}

#[derive(Clone)]
struct HttpState {
    gateway: Arc<Gateway>,
    endpoint: EndpointPolicy,
    operations: Arc<Semaphore>,
}
fn refusal(status: StatusCode) -> Response {
    (status, [("cache-control", "no-store")], "request refused").into_response()
}
async fn handle(
    State(state): State<HttpState>,
    Extension(workload): Extension<WorkloadIdentity>,
    request: Request,
) -> Response {
    if let Some(status) = state
        .endpoint
        .rejection_status(request.headers(), request.uri())
    {
        return refusal(status);
    }
    if request.method() != Method::POST {
        return refusal(StatusCode::METHOD_NOT_ALLOWED);
    }
    let headers = request.headers().clone();
    let raw = match tokio::time::timeout(
        Duration::from_secs(10),
        to_bytes(request.into_body(), 1 << 20),
    )
    .await
    {
        Ok(Ok(raw)) => raw,
        _ => return refusal(StatusCode::BAD_REQUEST),
    };
    // A disconnected client must not cancel completion recording after dispatch.
    // The owned task finishes its bounded stages even if this response is dropped.
    let permit = match state.operations.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return refusal(StatusCode::SERVICE_UNAVAILABLE),
    };
    match tokio::spawn(async move {
        let _permit = permit;
        state.gateway.handle(&headers, &workload, &raw).await
    })
    .await
    {
        Ok(result) => ([("cache-control", "no-store")], Json(result)).into_response(),
        Err(_) => refusal(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
pub fn router(gateway: Arc<Gateway>, endpoint: EndpointPolicy) -> Router {
    Router::new().fallback(handle).with_state(HttpState {
        gateway,
        endpoint,
        operations: Arc::new(Semaphore::new(64)),
    })
}
/// Bounded connections, handshake and header timeouts; no browser origin alias,
/// TLS offload, HTTP/2, streaming, notifications or session resumption profile.
pub async fn serve(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    gateway: Arc<Gateway>,
    endpoint: EndpointPolicy,
) -> Result<()> {
    gateway.validate()?;
    let app = router(gateway, endpoint);
    serve_router(listener, tls, app).await
}

/// Shared verified-mTLS transport for bounded authority and execution routers.
pub async fn serve_router(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    app: Router,
) -> Result<()> {
    serve_router_with_shutdown(listener, tls, app, crate::shutdown::wait()).await
}

/// Same bounded listener with an owner-supplied shutdown signal; no HTTP stop API.
pub async fn serve_router_with_shutdown(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    app: Router,
    shutdown: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    let lifecycle = Lifecycle(Arc::new(AtomicBool::new(true)));
    let app = app
        .layer(Extension(lifecycle.clone()))
        .layer(axum::middleware::from_fn_with_state(
            lifecycle.clone(),
            refuse_during_drain,
        ));
    let acceptor = TlsAcceptor::from(tls);
    let slots = Arc::new(Semaphore::new(64));
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            signal=&mut shutdown=>{signal?;lifecycle.0.store(false,Ordering::Release);break;}
            finished=connections.join_next(),if !connections.is_empty()=>{let _=finished;}
            accepted=listener.accept()=>{
                let (socket,_)=accepted?;
                let permit=match slots.clone().try_acquire_owned() {Ok(p)=>p,Err(_)=>continue};
                let acceptor=acceptor.clone();
                let app=app.clone();
                connections.spawn(async move {
                    let _permit=permit;
                    let stream=match tokio::time::timeout(Duration::from_secs(5),acceptor.accept(socket)).await {Ok(Ok(s))=>s,_=>return};
                    let cert=match stream.get_ref().1.peer_certificates().and_then(|c|c.first()) {Some(c)=>c,None=>return};
                    let workload=match WorkloadIdentity::from_verified_cert_der(cert.as_ref()) {Ok(w)=>w,Err(_)=>return};
                    let app=app.layer(Extension(workload));
                    let mut builder=hyper::server::conn::http1::Builder::new();
                    builder.timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(5)).max_buf_size(64*1024).max_headers(64);
                    // HTTP connection expiry cannot cancel the separately owned
                    // gateway task; pending attempts remain consumed on crashes.
                    let _=tokio::time::timeout(Duration::from_secs(30),builder.serve_connection(TokioIo::new(stream),TowerToHyperService::new(app))).await;
                });
            }
        }
    }
    drop(listener);
    let _ = tokio::time::timeout(Duration::from_secs(30), async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    Ok(())
}
