#![cfg(target_arch = "wasm32")]

//! Contains the wasm component of the browser prover.
//!
//! Conceptually the browser prover consists of the native and the wasm
//! components.

use anyhow::Result;
use serio::{stream::IoStreamExt, SinkExt as _};
use tracing::info;
use wasm_bindgen::prelude::*;
use web_time::Instant;
use ws_stream_wasm::WsMeta;

use tlsn_benches_browser_core::{
    msg::{Config, Runtime},
    FramedIo,
};
use tlsn_benches_library::run_prover;
use tlsn_wasm::LoggingConfig;

#[wasm_bindgen]
pub async fn wasm_main(
    ws_ip: String,
    ws_port: u16,
    wasm_to_server_port: u16,
    wasm_to_verifier_port: u16,
    wasm_to_native_port: u16,
) -> Result<(), JsError> {
    // Wrapping main() since wasm_bindgen doesn't support anyhow.
    main(
        ws_ip,
        ws_port,
        wasm_to_server_port,
        wasm_to_verifier_port,
        wasm_to_native_port,
    )
    .await
    .map_err(|err| JsError::new(&err.to_string()))
}

pub async fn main(
    ws_ip: String,
    ws_port: u16,
    wasm_to_server_port: u16,
    wasm_to_verifier_port: u16,
    wasm_to_native_port: u16,
) -> Result<()> {
    info!("starting main");

    // Connect to the server.
    let (_, server_io_ws) = WsMeta::connect(
        &format!(
            "ws://{}:{}/tcp?addr=localhost%3A{}",
            ws_ip, ws_port, wasm_to_server_port
        ),
        None,
    )
    .await?;
    let server_io = server_io_ws.into_io();

    // Connect to the verifier.
    let (_, verifier_io_ws) = WsMeta::connect(
        &format!(
            "ws://{}:{}/tcp?addr=localhost%3A{}",
            ws_ip, ws_port, wasm_to_verifier_port
        ),
        None,
    )
    .await?;
    let verifier_io = verifier_io_ws.into_io();

    // Connect to the native component of the browser prover.
    let (_, native_io_ws) = WsMeta::connect(
        &format!(
            "ws://{}:{}/tcp?addr=localhost%3A{}",
            ws_ip, ws_port, wasm_to_native_port
        ),
        None,
    )
    .await?;
    let mut native_io = FramedIo::new(Box::new(native_io_ws.into_io()));

    info!("expecting config from the native component");

    let cfg: Config = native_io.expect_next().await?;

    let start_time = Instant::now();

    info!("running the prover");

    run_prover(
        cfg.upload_size,
        cfg.download_size,
        cfg.defer_decryption,
        Box::new(verifier_io),
        Box::new(server_io),
    )
    .await?;

    native_io
        .send(Runtime(start_time.elapsed().as_secs()))
        .await?;

    Ok(())
}

/// Initializes the module.
#[wasm_bindgen]
pub async fn initialize_bench(
    logging_config: Option<LoggingConfig>,
    thread_count: usize,
) -> Result<(), JsValue> {
    tlsn_wasm::initialize(logging_config, thread_count).await
}
