// This example demonstrates how to build a verifiable presentation from an
// attestation and the corresponding connection secrets. See the `prove.rs`
// example to learn how to acquire an attestation from a Notary.

use clap::Parser;
use hyper::header;

use tlsn_core::{attestation::Attestation, presentation::Presentation, CryptoProvider, Secrets};
use tlsn_formats::http::HttpTranscript;

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

    // Here is where we reveal all or some of the parts we committed in `prove.rs`
    // previously.
    let request = &transcript.requests[0];
    // Reveal the structure of the request without the headers or body.
    builder.reveal_sent(&request.without_data())?;
    // Reveal the request target.
    builder.reveal_sent(&request.request.target)?;
    // Reveal all request headers except the values of User-Agent and Authorization.
    for header in &request.headers {
        if !(header
            .name
            .as_str()
            .eq_ignore_ascii_case(header::USER_AGENT.as_str())
            || header
                .name
                .as_str()
                .eq_ignore_ascii_case(header::AUTHORIZATION.as_str()))
        {
            builder.reveal_sent(header)?;
        } else {
            builder.reveal_sent(&header.without_value())?;
        }
    }

    // Reveal only parts of the response.
    let response = &transcript.responses[0];
    // Reveal the structure of the response without the headers or body.
    builder.reveal_recv(&response.without_data())?;
    // Reveal all response headers.
    for header in &response.headers {
        builder.reveal_recv(header)?;
    }

    let content = &response.body.as_ref().unwrap().content;
    match content {
        tlsn_formats::http::BodyContent::Json(json) => {
            // The 'json' variable here is of type tlsn_formats::http::JsonValue (which is an alias for serde_json::Value)
            if let Some(result_field_value) = json.get("result") { // result_field_value is &tlsn_formats::http::JsonValue
                match result_field_value {
                    // Use the correct path to JsonValue as suggested by the compiler
                    tlsn_formats::json::JsonValue::Array(_) => {
                        // Likely a getUpdates response, reveal the entire array of updates.
                        builder.reveal_recv(result_field_value)?;
                    }
                    tlsn_formats::json::JsonValue::Object(_) => {
                        // Likely a getMe, sendMessage, or similar response where result is an object.
                        // Reveal known fields from getMe/sendMessage response structure:
                        if let Some(id_val) = result_field_value.get("id") {
                            builder.reveal_recv(id_val)?;
                        }
                        if let Some(is_bot_val) = result_field_value.get("is_bot") {
                            builder.reveal_recv(is_bot_val)?;
                        }
                        if let Some(first_name_val) = result_field_value.get("first_name") {
                            builder.reveal_recv(first_name_val)?;
                        }
                        if let Some(username_val) = result_field_value.get("username") {
                            builder.reveal_recv(username_val)?;
                        }
                        // Add more specific field reveals for sendMessage or other object types if necessary
                    }
                    _ => {
                        // The "result" field is present but is neither an Array nor an Object.
                        // This is unusual for a typical successful Telegram API "result" field.
                        // Fallback to revealing the 'ok' field from the root json if present.
                        if let Some(ok_val) = json.get("ok") {
                            builder.reveal_recv(ok_val)?;
                        }
                    }
                }
            } else {
                // No "result" field found. This is common for error responses from Telegram.
                // Reveal "ok" (usually false for errors) and "description" if available.
                if let Some(ok_val) = json.get("ok") {
                    builder.reveal_recv(ok_val)?;
                }
                if let Some(description_val) = json.get("description") {
                    builder.reveal_recv(description_val)?;
                }
            }
        }
        tlsn_formats::http::BodyContent::Unknown(span) => {
            builder.reveal_recv(span)?;
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
