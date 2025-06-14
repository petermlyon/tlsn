// This example demonstrates how to verify a presentation. See `present.rs` for
// an example of how to build a presentation from an attestation and connection
// secrets.

use std::time::Duration;

use clap::Parser;

use tls_core::verify::WebPkiVerifier;
use tlsn_core::{
    presentation::{Presentation, PresentationOutput},
    signing::VerifyingKey,
    CryptoProvider,
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[clap(long)]
    presentation_path: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    verify_presentation(&args.presentation_path).await
}

async fn verify_presentation(presentation_path_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Read the presentation from disk.
    let presentation: Presentation = bincode::deserialize(&std::fs::read(presentation_path_str)?)?;

    // Use the default crypto provider for web PKI verification.
    let crypto_provider = CryptoProvider::default();

    let VerifyingKey {
        alg,
        data: key_data,
    } = presentation.verifying_key();

    println!(
        "Verifying presentation with {alg} key: {}\n\n**Ask yourself, do you trust this key?**\n",
        hex::encode(key_data)
    );

    // Verify the presentation.
    let PresentationOutput {
        server_name,
        connection_info,
        transcript,
        // extensions, // Optionally, verify any custom extensions from prover/notary.
        ..
    } = presentation.verify(&crypto_provider).unwrap();

    // The time at which the connection was started.
    let time = chrono::DateTime::UNIX_EPOCH + Duration::from_secs(connection_info.time);
    let server_name = server_name.unwrap();
    let mut partial_transcript = transcript.unwrap();
    // Set the unauthenticated bytes so they are distinguishable.
    partial_transcript.set_unauthed(b'X');

    let sent = String::from_utf8_lossy(partial_transcript.sent_unsafe());
    let recv = String::from_utf8_lossy(partial_transcript.received_unsafe());

    println!("-------------------------------------------------------------------");
    println!(
        "Successfully verified that the data below came from a session with {server_name} at {time}.",
    );
    println!("Note that the data which the Prover chose not to disclose are shown as X.\n");
    println!("Data sent:\n");
    println!("{}\n", sent);
    println!("Data received:\n");
    println!("{}\n", recv);
    println!("-------------------------------------------------------------------");

    Ok(())
}
