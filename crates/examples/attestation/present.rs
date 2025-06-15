// This example demonstrates how to build a verifiable presentation from an
// attestation and the corresponding connection secrets. See the `prove.rs`
// example to learn how to acquire an attestation from a Notary.

use clap::Parser;
use hyper::header;

use tlsn_core::{attestation::Attestation, presentation::Presentation, CryptoProvider, Secrets};
use tlsn_formats::http::HttpTranscript;
use tlsn_formats::spansy::Spanned;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[clap(long)]
    attestation_path: String,
    #[clap(long)]
    secrets_path: String,
    #[clap(long, default_value = "presentation.tlsn")]
    output_path: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    create_presentation(&args.attestation_path, &args.secrets_path, &args.output_path).await
}

async fn create_presentation(
    attestation_path_str: &str, // Renamed to avoid conflict with variable below
    secrets_path_str: &str, // Renamed to avoid conflict with variable below
    output_path_str: &str, // Renamed to avoid conflict with variable below
) -> Result<(), Box<dyn std::error::Error>> {
    // Read attestation from disk using the provided path.
    let attestation: Attestation = bincode::deserialize(&std::fs::read(attestation_path_str)?)?;

    // Read secrets from disk using the provided path.
    let secrets: Secrets = bincode::deserialize(&std::fs::read(secrets_path_str)?)?;

    // Parse the HTTP transcript.
    let transcript = HttpTranscript::parse(secrets.transcript())?;

    // Build a transcript proof.
    let mut builder = secrets.transcript_proof_builder();

    // Reveal specific request parts committed by the prover.
    let request = &transcript.requests[0];

    // Reveal the HTTP method
    builder.reveal_sent(request.request.method.span())?;
    eprintln!("[present.rs] Revealed request method span: {:?}", request.request.method.span().indices());

    // HTTP version is not revealed as a separate spanned item.

    // Reveal only the "Host" request header
    let mut host_header_revealed = false;
    for header_span in &request.headers {
        if header_span.name.as_str().eq_ignore_ascii_case(hyper::header::HOST.as_str()) {
            builder.reveal_sent(header_span.span())?;
            eprintln!("[present.rs] Revealed Host header span: {:?}", header_span.span().indices());
            host_header_revealed = true;
            break; // Assuming only one Host header
        }
    }
    if !host_header_revealed {
        eprintln!("[present.rs] WARNING: Host header not found in transcript or not revealed.");
    }
    // The request target (path with API key) is intentionally NOT revealed.

    // Reveal only parts of the response.
    let response = &transcript.responses[0];
    // Reveal the structure of the response without the headers or body.
    builder.reveal_recv(&response.without_data())?;
    // Reveal all response headers.
    for header in &response.headers {
        builder.reveal_recv(header)?;
    }
    let content = &response.body.as_ref().unwrap().content;
    let body_span = response.body.as_ref().unwrap().content.span();
    eprintln!("[present.rs] Transcript body span: {:?}", body_span.indices());
    match content {
        tlsn_formats::http::BodyContent::Json(json) => {
            match json {
                tlsn_formats::json::JsonValue::Object(obj) => {
                    // Look for the "result" array
                    if let Some(result_field_value) = obj.get("result") {
                        if let tlsn_formats::json::JsonValue::Array(results) = result_field_value {
                            for msg in results.elems.iter() {
                                if let Some(message) = msg.get("message") {
                                    for field in ["forward_from", "forward_sender_name", "forward_origin", "forward_date", "text"] {
                                        if let Some(field_value) = message.get(field) {
                                            let span = field_value.span();
                                            eprintln!("[present.rs] Attempting to reveal span: {:?}", span.indices());
                                            builder.reveal_recv(field_value)?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }

    let transcript_proof = builder.build()?;

    // Use default crypto provider to build the presentation.
    let provider = CryptoProvider::default();

    let mut builder = attestation.presentation_builder(&provider);

    builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);

    let presentation: Presentation = builder.build()?;

    // Write the presentation to disk using the output_path
    std::fs::write(output_path_str, bincode::serialize(&presentation)?)?;

    println!("Presentation successfully created at: {}", output_path_str);

    Ok(())
}
