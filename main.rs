use async_trait::async_trait;
use log::info;
use prometheus::register_int_counter;
use structopt::StructOpt;

use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};

fn check_login(req: &pingora_http::RequestHeader) -> bool {
    req.headers.get("Authorization").map(|v| v.as_bytes()) == Some(b"password")
}

pub struct MyGateway {
    req_metric: prometheus::IntCounter,
}

#[async_trait]
impl ProxyHttp for MyGateway {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {

        if session.req_header().uri.path().starts_with("/login")
            && !check_login(session.req_header())
        {
            let _ = session.respond_error(403).await;
            // true: early return as the response is already written

            println!("Reached request filter.");
            return Ok(true);
        }
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {

        // Route
        let addr = if session.req_header().uri.path().starts_with("/info") {
            ("http://192.168.0.105", 9050)
        } else {
            ("http://192.168.0.105", 9050)
        };

        println!("Connecting to: {:?}", addr);

        info!("Connecting to {addr:?}");

        let peer = Box::new(HttpPeer::new(addr, true, "one.one.one.one".to_string()));
        Ok(peer)
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync, {
        // replace existing header if any
        upstream_response
            .insert_header("Server", "MyGateway")
            .unwrap();
        // because we don't support h3
        upstream_response.remove_header("alt-svc");

        println!("Reached response filter.");

        Ok(())
    }

    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&pingora_core::Error>,
        ctx: &mut Self::CTX,
    ) {
        let response_code = session
            .response_written()
            .map_or(0, |resp| resp.status.as_u16());
        info!(
            "{} response code: {response_code}",
            self.request_summary(session, ctx)
        );

        self.req_metric.inc();
    }
}

fn main() {

    // read command line arguments
    let opt = Opt::from_args();
    let mut server = Server::new(Some(opt)).unwrap();
    server.bootstrap();

    let mut proxy = pingora_proxy::http_proxy_service(
        &server.configuration,
        MyGateway {
            req_metric: register_int_counter!("reg_counter", "Number of requests").unwrap(),
        },
    );

    // Proxy
    proxy.add_tcp("http://127.0.0.1:443");
    server.add_service(proxy);

    // HTTP Server
    let mut prometheus_service_http =
        pingora_core::services::listening::Service::prometheus_http_service();
    prometheus_service_http.add_tcp("http://127.0.0.1:443");
    server.add_service(prometheus_service_http);

    println!("Server started...");
    server.run_forever();
}