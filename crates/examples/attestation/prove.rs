// This example demonstrates how to use the Prover to acquire an attestation for
// an HTTP request sent to example.com. The attestation and secrets are saved to
// disk.

use std::env;

use clap::Parser;
use hyper::Method; // Added for dynamic HTTP methods
use http_body_util::Full; // Added for request body handling
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use notary_client::{Accepted, NotarizationRequest, NotaryClient};
// use tls_server_fixture::{CA_CERT_DER, SERVER_DOMAIN}; // Original server fixture, not used for Telegram
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{request::RequestConfig, transcript::TranscriptCommitConfig, CryptoProvider};
// use tlsn_examples::ExampleType; // Replaced Args structure, ExampleType not used for URI/headers
use tlsn_formats::http::HttpTranscript;
use hyper::header;
use tlsn_formats::spansy::Spanned;
use tlsn_prover::{Prover, ProverConfig};

const TELEGRAM_API_DOMAIN: &str = "api.telegram.org";
const DEFAULT_TELEGRAM_PORT: u16 = 443;
const DEFAULT_NOTARY_PORT: u16 = 7047; // Default from original example, user should override with NOTARY_PORT=8000

// Setting of the application server.
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Full URI for the Telegram API request (e.g., /bot<TOKEN>/getMe)
    #[clap(long)]
    target_uri: String,

    /// HTTP method (e.g., GET, POST)
    #[clap(long, default_value = "GET")]
    http_method: String,

    /// Optional request body for POST requests
    #[clap(long)]
    request_body: Option<String>,

    /// Optional extra headers in 'Key:Value' format, comma-separated (e.g., "Content-Type:application/json,Authorization:Bearer token")
    #[clap(long, value_delimiter = ',', num_args = 0..)]
    headers: Vec<String>,

    /// Prefix for output attestation and secrets files
    #[clap(long, default_value = "telegram_notarization")]
    output_prefix: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    // The example_type logic is removed as URI and headers are now direct args.
    notarize(args).await
}

async fn notarize(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr) // Direct all tracing output to stderr
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env()) // Respect RUST_LOG for filtering
        .init();

    let notary_host: String = env::var("NOTARY_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let notary_port: u16 = env::var("NOTARY_PORT")
        .ok()
        .and_then(|port_str| port_str.parse().ok())
        .unwrap_or(DEFAULT_NOTARY_PORT); // User's notary is on 8000, they'll need to set env var NOTARY_PORT=8000

    // SERVER_HOST and SERVER_PORT now refer to Telegram
    // SERVER_HOST defaults to TELEGRAM_API_DOMAIN, SERVER_PORT to DEFAULT_TELEGRAM_PORT (443)
    // These can still be overridden by environment variables if needed for some reason.
    let server_host: String = env::var("SERVER_HOST").unwrap_or_else(|_| TELEGRAM_API_DOMAIN.into());
    let server_port: u16 = env::var("SERVER_PORT")
        .ok()
        .and_then(|port_str| port_str.parse().ok())
        .unwrap_or(DEFAULT_TELEGRAM_PORT);

    // Build a client to connect to the notary server.
    let notary_client = NotaryClient::builder()
        .host(notary_host)
        .port(notary_port)
        // WARNING: Always use TLS to connect to notary server, except if notary is running locally (e.g. this example).
        // If your notary server at 127.0.0.1:8000 is using TLS, set this to true.
        // For now, assuming local notary is HTTP, consistent with original example's local notary behavior.
        .enable_tls(false)
        .build()
        .unwrap();

    // Send requests for configuration and notarization to the notary server.
    let notarization_request = NotarizationRequest::builder()
        // We must configure the amount of data we expect to exchange beforehand, which will
        // be preprocessed prior to the connection. Reducing these limits will improve
        // performance.
        .max_sent_data(tlsn_examples::MAX_SENT_DATA)
        .max_recv_data(tlsn_examples::MAX_RECV_DATA)
        .build()?;

    let Accepted {
        io: notary_connection,
        id: _session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await
        .expect("Could not connect to notary. Make sure it is running.");

    // Create a crypto provider using the default system roots for web PKI.
    // This is necessary to verify Telegram's TLS certificate.
    let crypto_provider = CryptoProvider::default();

    // Set up protocol configuration for prover.
    // Prover configuration.
    let prover_config = ProverConfig::builder()
        .server_name(TELEGRAM_API_DOMAIN)
        .protocol_config(
            ProtocolConfig::builder()
                // We must configure the amount of data we expect to exchange beforehand, which will
                // be preprocessed prior to the connection. Reducing these limits will improve
                // performance.
                .max_sent_data(tlsn_examples::MAX_SENT_DATA)
                .max_recv_data(tlsn_examples::MAX_RECV_DATA)
                .build()?,
        )
        .crypto_provider(crypto_provider)
        .build()?;

    // Create a new prover and perform necessary setup.
    let prover = Prover::new(prover_config)
        .setup(notary_connection.compat())
        .await?;

    // Open a TCP connection to the server.
    let client_socket = tokio::net::TcpStream::connect((server_host, server_port)).await?;

    // Bind the prover to the server connection.
    // The returned `mpc_tls_connection` is an MPC TLS connection to the server: all
    // data written to/read from it will be encrypted/decrypted using MPC with
    // the notary.
    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await?;
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    // Spawn the prover task to be run concurrently in the background.
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the connection.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection).await?;

    // Spawn the HTTP task to be run concurrently in the background.
    tokio::spawn(connection);

    // Build the HTTP request using command-line arguments
    let method = Method::from_bytes(args.http_method.as_bytes())
        .map_err(|e| format!("Invalid HTTP method: {} - {}", args.http_method, e))?;

    let mut request_builder = Request::builder()
        .method(method)
        .uri(args.target_uri.as_str())
        .header("Host", TELEGRAM_API_DOMAIN) // Host header should match the server_name for TLS
        .header("Accept", "application/json, */*") // Prefer JSON for APIs
        .header("Accept-Encoding", "identity") // Important for TLSNotary, no compression
        .header("Connection", "close") // Simplifies connection handling for this example
        .header("User-Agent", USER_AGENT);

    for header_str in args.headers {
        let parts: Vec<&str> = header_str.splitn(2, ':').collect();
        if parts.len() == 2 {
            request_builder = request_builder.header(parts[0].trim(), parts[1].trim());
        } else {
            // Using eprintln for warnings so it doesn't interfere with stdout for JSON response
            eprintln!("Warning: Skipping malformed header: {}", header_str);
        }
    }

    let request = if let Some(body_str) = args.request_body {
        // If there's a request body, ensure Content-Type is set if not already provided
        // For Telegram, this is often application/json for POST requests
        // This is a basic check; more robust header management might be needed for complex cases
        if request_builder.headers_ref().map_or(true, |h| !h.contains_key("Content-Type")) {
            if body_str.trim_start().starts_with('{') || body_str.trim_start().starts_with('[') {
                 request_builder = request_builder.header("Content-Type", "application/json");
            }
        }
        request_builder.body(Full::new(Bytes::from(body_str)))?
    } else {
        request_builder.body(Full::new(Bytes::new()))? // Use Full<Bytes> for empty body with GET too
    };

    eprintln!("Starting an MPC TLS connection with the server");

    // Send the request to the server and wait for the response.
    let response = request_sender.send_request(request).await?;

    eprintln!("Got a response from the server: {}", response.status());

    assert!(response.status() == StatusCode::OK);

    // The prover task should be done now, so we can await it.
    let mut prover = prover_task.await??;

    // Parse the HTTP transcript.
    let transcript = HttpTranscript::parse(prover.transcript())?;

    let response = &transcript.responses[0];
    let body_span = response.body.as_ref().unwrap().content.span();
    let mut builder = TranscriptCommitConfig::builder(prover.transcript());
    builder.commit_recv(body_span)?;
    eprintln!("[prove.rs] Committed body span: {:?}", body_span);

    let body_content = &transcript.responses[0].body.as_ref().unwrap().content;
    let body = String::from_utf8_lossy(body_content.span().as_bytes());

    // Print the raw response body to stdout for the calling Node.js script
    // Ensure this is the only thing printed to stdout if the script is successful,
    // other logs should go to stderr (e.g., using eprintln! or tracing to stderr).
    println!("{}", body);

    // The debug logging of the parsed body is removed to keep stdout clean.
    // If you need to debug the Rust code itself, you can use `eprintln!` or `debug!` (if tracing is configured for stderr).

    // Commit to the transcript selectively.
    let mut builder = TranscriptCommitConfig::builder(prover.transcript());

    // Commit specific request parts to prove connection to the correct host without revealing the API key.
    let request = &transcript.requests[0];

    // Commit the HTTP method (e.g., "GET")
    builder.commit_sent(request.request.method.span())?;
    eprintln!("[prove.rs] Committed request method span: {:?}", request.request.method.span().indices());

    // HTTP version is not committed as a separate spanned item as it's not directly available as such.
    // It is implicitly part of the overall request line and TLS exchange.

    // Commit only the "Host" request header
    let mut host_header_committed = false;
    for header_span in &request.headers {
        if header_span.name.as_str().eq_ignore_ascii_case(hyper::header::HOST.as_str()) {
            builder.commit_sent(header_span.span())?;
            eprintln!("[prove.rs] Committed Host header span: {:?}", header_span.span().indices());
            host_header_committed = true;
            break; // Assuming only one Host header
        }
    }
    if !host_header_committed {
        eprintln!("[prove.rs] WARNING: Host header not found or not committed.");
    }
    // The request target (path with API key) is intentionally NOT committed.
    // Assuming no sensitive request body to commit for Telegram GET requests.

    // Commit response parts
    let response = &transcript.responses[0];
    // Commit the structure of the response without the data.
    builder.commit_recv(&response.without_data())?;
    // Commit all response headers.
    for header_span in &response.headers {
        builder.commit_recv(header_span)?;
    }

    // Commit specific fields from the JSON response body
    if let Some(resp_body_container) = response.body.as_ref() {
        match &resp_body_container.content {
            tlsn_formats::http::BodyContent::Json(json_value) => {
                eprintln!("[prove.rs] Processing JSON response body for selective field commitment.");
                let allowed_fields = ["forward_from", "forward_sender_name", "forward_origin", "forward_date", "text"];
                match json_value {
                    tlsn_formats::json::JsonValue::Object(root_obj) => {
                        if let Some(result_val) = root_obj.get("result") {
                            if let tlsn_formats::json::JsonValue::Array(results_array) = result_val {
                                for update_container_val in results_array.elems.iter() {
                                    if let tlsn_formats::json::JsonValue::Object(update_container_obj) = update_container_val {
                                        if let Some(message_val) = update_container_obj.get("message") {
                                            if let tlsn_formats::json::JsonValue::Object(message_obj) = message_val {
                                                for &field_name in allowed_fields.iter() {
                                                    if let Some(field_data_val) = message_obj.get(field_name) {
                                                        let field_span = field_data_val.span();
                                                        eprintln!("[prove.rs] Committing field '{}' with span: {:?}", field_name, field_span.indices());
                                                        builder.commit_recv(field_span)?;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    tlsn_formats::json::JsonValue::Array(root_array) => {
                        for update_container_val in root_array.elems.iter() {
                            if let tlsn_formats::json::JsonValue::Object(update_container_obj) = update_container_val {
                                if let Some(message_val) = update_container_obj.get("message") {
                                    if let tlsn_formats::json::JsonValue::Object(message_obj) = message_val {
                                        for &field_name in allowed_fields.iter() {
                                            if let Some(field_data_val) = message_obj.get(field_name) {
                                                let field_span = field_data_val.span();
                                                eprintln!("[prove.rs] Committing field '{}' (from root array) with span: {:?}", field_name, field_span.indices());
                                                builder.commit_recv(field_span)?;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        eprintln!("[prove.rs] JSON response body is not an Object or Array at the root. No specific fields committed.");
                    }
                }
            }
            _ => {
                eprintln!("[prove.rs] Response body is not JSON. No specific fields committed.");
            }
        }
    } else {
        eprintln!("[prove.rs] No response body found. No specific fields committed.");
    }

    let transcript_commit = builder.build()?;

    // Build an attestation request.
    let mut builder = RequestConfig::builder();

    builder.transcript_commit(transcript_commit);

    // Optionally, add an extension to the attestation if the notary supports it.
    // builder.extension(Extension {
    //     id: b"example.name".to_vec(),
    //     value: b"Bobert".to_vec(),
    // });

    let request_config = builder.build()?;

    #[allow(deprecated)]
    let (attestation, secrets) = prover.notarize(&request_config).await?;

    eprintln!("Notarization complete!");

    // Write the attestation to disk.
    let attestation_path = format!("{}.attestation.tlsn", args.output_prefix);
    let secrets_path = format!("{}.secrets.tlsn", args.output_prefix);

    tokio::fs::write(&attestation_path, bincode::serialize(&attestation)?).await?;

    // Write the secrets to disk.
    tokio::fs::write(&secrets_path, bincode::serialize(&secrets)?).await?;

    eprintln!("Notarization completed successfully!");
    eprintln!(
        "The attestation has been written to `{attestation_path}` and the \
        corresponding secrets to `{secrets_path}`."
    );

    Ok(())
}
