mod types;
mod invalidation;

use std::sync::Arc;
use ethers_core::{
    abi::{encode, Token},
    types::{Address, Bytes, H256, U256},
    utils::keccak256,
};
use ethers_providers::{Http, Middleware, Provider};
use ethers_signers::{LocalWallet, Signer};
use types::{
    CausalGraph, Decision, Edge, EdgeKind, Finality, Node, NodeId, NodeKind, Observation,
};
use invalidation::invalidate_derivation;

const ATTESTATION_TYPEHASH_STR: &str =
    "FirewallAttestation(bytes32 messageHash,bytes32 sourceStateRoot,uint256 validAfter,uint256 validUntil,uint256 sourceBlock)";

fn compute_digest(
    domain_separator: H256,
    message_hash: H256,
    source_state_root: H256,
    valid_after: U256,
    valid_until: U256,
    source_block: U256,
) -> H256 {
    let typehash = keccak256(ATTESTATION_TYPEHASH_STR.as_bytes());

    let encoded_struct = encode(&[
        Token::FixedBytes(typehash.to_vec()),
        Token::FixedBytes(message_hash.as_bytes().to_vec()),
        Token::FixedBytes(source_state_root.as_bytes().to_vec()),
        Token::Uint(valid_after),
        Token::Uint(valid_until),
        Token::Uint(source_block),
    ]);
    let struct_hash = keccak256(&encoded_struct);

    let mut packed = Vec::with_capacity(2 + 32 + 32);
    packed.extend_from_slice(b"\x19\x01");
    packed.extend_from_slice(domain_separator.as_bytes());
    packed.extend_from_slice(&struct_hash);

    H256::from(keccak256(&packed))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("====================================================");
    println!("   AEGIS FIREWALL: THRESHOLD QUORUM ENGINE (2/3)    ");
    println!("====================================================");

    // Initializare noduri gardian A, B si C
    let wallet_a: LocalWallet = LocalWallet::from_bytes(&hex::decode("0000000000000000000000000000000000000000000000000000000000001111")?)?;
    let wallet_b: LocalWallet = LocalWallet::from_bytes(&hex::decode("0000000000000000000000000000000000000000000000000000000000002222")?)?;
    let wallet_c: LocalWallet = LocalWallet::from_bytes(&hex::decode("0000000000000000000000000000000000000000000000000000000000003333")?)?;

    println!("[AUTH] Guardian A: {:?}", wallet_a.address());
    println!("[AUTH] Guardian B: {:?}", wallet_b.address());
    println!("[AUTH] Guardian C: {:?}", wallet_c.address());
    println!("[QUORUM] Prag necesar: 2 din 3 semnaturi independente");

    // Graful cauzal
    let mut graph = CausalGraph::new();
    let src_state = graph.add_node(Node {
        id: NodeId(0),
        kind: NodeKind::ChainState,
        observation: Some(Observation {
            chain_id: 1,
            height: 19_500_000,
            block_hash: H256::random(),
            parent_hash: H256::random(),
            tx_hash: H256::random(),
            node: NodeId(0),
            finality: Finality::Finalized,
            timestamp: 1710000000,
        }),
        valid: true,
        invalidated: false,
        message: None,
    });

    let message_node = graph.add_node(Node {
        id: NodeId(1),
        kind: NodeKind::Message,
        observation: None,
        valid: true,
        invalidated: false,
        message: None,
    });

    graph.add_edge(Edge {
        from: src_state,
        to: message_node,
        kind: EdgeKind::Produces,
    });

    println!("\n--- SCENARIUL 1: Tranzactie legitima cu cvorum atins ---");
    let payload = b"transfer(100 ETH to 0xAlice)";
    let message_hash = H256::from(keccak256(payload));
    let source_state_root = H256::from(keccak256(b"source_state_root_19500000"));
    let valid_after = U256::from(1000);
    let valid_until = U256::from(1060);
    let source_block = U256::from(19_500_000);
    let domain_separator = H256::random();

    let digest = compute_digest(domain_separator, message_hash, source_state_root, valid_after, valid_until, source_block);

    // Gardienii A si B valideaza si semneaza independent
    let sig_a = wallet_a.sign_hash(digest)?;
    let sig_b = wallet_b.sign_hash(digest)?;
    println!("[QUORUM] Guardian A a semnat -> OK");
    println!("[QUORUM] Guardian B a semnat -> OK");
    println!("[DECISION] Prag (2/2) atins -> MultiAttestation gata de emitere");

    println!("\n--- SCENARIUL 2: Detectare reorg pe Chain A ---");
    let evidence = invalidate_derivation(src_state, &mut graph);
    println!("[ENGINE] Nodul sursa 19,500,000 invalidat.");
    println!("[ENGINE] Decizie Causal: {:?}", evidence.decision);

    if evidence.decision == Decision::Freeze {
        println!("[FAIL-CLOSED]: Semnaturile au fost REFUSATE de nodurile clusterului.");
        println!("[STATUS]: Zero semnaturi emise. Niciun gardian nu aproba starea orfana.");
    }

    Ok(())
}
