#[macro_use]
extern crate log;
extern crate env_logger;
extern crate libmdns;
extern crate tokio;

use tokio::prelude::*;

pub fn main() {
    env_logger::init();

    let responder = libmdns::Builder::new()
        .hostname("test.local")
        .add_addr("::".parse().unwrap())
        .bind()
        .unwrap();

    let _svc = responder.register(
        "_http._tcp".to_owned(),
        "Web Server".to_owned(),
        80,
        &["path=/"],
    );

    tokio::run(responder.serve().map_err(|e| {
        error!("{:?}", e);
    }));
}
