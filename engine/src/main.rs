mod aggregate;
mod digest;
mod guardian;
mod invalidation;
mod policy;
mod rpc;
mod types;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match std::env::args().nth(1).as_deref() {
        Some("guardian") => guardian::run().await,
        Some("aggregate") => aggregate::run(),
        _ => {
            eprintln!("usage: engine <guardian|aggregate>");
            eprintln!("  guardian : SRC_RPC DST_RPC SRC_CONTRACT BRIDGE GUARDIAN_KEY [K=3 SET_ID=1 ATTEST_DIR POLL_MS FROM_BLOCK]");
            eprintln!("  aggregate: [ATTEST_DIR THRESHOLD=2]");
            std::process::exit(2);
        }
    }
}
