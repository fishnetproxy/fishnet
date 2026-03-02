/// fishnet-sign: CLI tool for Foundry FFI tests.
///
/// Takes permit parameters as arguments, signs using the actual StubSigner,
/// and outputs the signer address and hex-encoded signature to stdout.
///
/// Usage:
///   fishnet-sign <private_key_hex> <wallet> <chain_id> <nonce> <expiry> \
///                <target> <value> <calldata_hash> <policy_hash> <verifying_contract>
///
/// Output (two lines):
///   0x<signer_address>
///   0x<65_byte_signature_hex>
use fishnet_server::signer::{FishnetPermit, StubSigner, SignerTrait};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 11 {
        eprintln!(
            "Usage: {} <private_key_hex> <wallet> <chain_id> <nonce> <expiry> \
             <target> <value> <calldata_hash> <policy_hash> <verifying_contract>",
            args[0]
        );
        eprintln!("  policy_hash: use '0x0' or '0x00..00' for None");
        std::process::exit(1);
    }

    let private_key_hex = args[1].strip_prefix("0x").unwrap_or(&args[1]);
    let key_bytes: [u8; 32] = hex::decode(private_key_hex)
        .expect("invalid private key hex")
        .try_into()
        .expect("private key must be 32 bytes");

    let signer = StubSigner::from_bytes(key_bytes);

    let policy_hash_raw = &args[9];
    let policy_hash = if policy_hash_raw == "0x0"
        || policy_hash_raw == "0x0000000000000000000000000000000000000000000000000000000000000000"
    {
        None
    } else {
        Some(policy_hash_raw.clone())
    };

    let permit = FishnetPermit {
        wallet: args[2].clone(),
        chain_id: args[3].parse().expect("invalid chain_id"),
        nonce: args[4].parse().expect("invalid nonce"),
        expiry: args[5].parse().expect("invalid expiry"),
        target: args[6].clone(),
        value: args[7].clone(),
        calldata_hash: args[8].clone(),
        policy_hash,
        verifying_contract: args[10].clone(),
    };

    let sig = signer.sign_permit(&permit).await.expect("signing failed");
    let info = signer.status();

    // Output: address on first line, signature on second
    println!("{}", info.address);
    println!("0x{}", hex::encode(&sig));
}
