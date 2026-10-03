use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ethers_core::{
    abi::{decode, ParamType},
    types::{transaction::eip2718::TypedTransaction, Address, Bytes, Filter, TransactionRequest, H256, U256},
    utils::{id, keccak256},
};
use ethers_providers::{Http, Middleware, Provider};
use ethers_signers::{LocalWallet, Signer};

use crate::digest::{digest, h256_hex, AttestationFields};
use crate::invalidation::invalidate_derivation;
use crate::policy::{classify, validity_window, SourceStatus};
use crate::types::{CausalGraph, DecisionEvidence, Edge, EdgeKind, Node, NodeId, NodeKind};

pub type Res<T> = Result<T, Box<dyn std::error::Error>>;

const DEPOSIT_EVENT: &str = "Deposit(bytes32,address,address,uint256,uint256,uint256,bytes)";

struct Config {
    src_rpc: String,
    dst_rpc: String,
    src_contract: Address,
    bridge: Address,
    key: String,
    k: u64,
    set_id: u64,
    dir: PathBuf,
    poll: Duration,
    from_block: u64,
}

fn var(name: &str) -> Res<String> {
    env::var(name).map_err(|_| format!("missing environment variable {name}").into())
}

fn var_or(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

impl Config {
    fn from_env() -> Res<Self> {
        Ok(Self {
            src_rpc: var("SRC_RPC")?,
            dst_rpc: var("DST_RPC")?,
            src_contract: var("SRC_CONTRACT")?.parse()?,
            bridge: var("BRIDGE")?.parse()?,
            key: var("GUARDIAN_KEY")?,
            k: var_or("K", "3").parse()?,
            set_id: var_or("SET_ID", "1").parse()?,
            dir: PathBuf::from(var_or("ATTEST_DIR", "./attestations")),
            poll: Duration::from_millis(var_or("POLL_MS", "500").parse()?),
            from_block: var_or("FROM_BLOCK", "0").parse()?,
        })
    }
}

struct Pending {
    message_hash: H256,
    block: u64,
    payload: Vec<u8>,
    signed_windows: HashSet<u64>,
    last_status: Option<SourceStatus>,
}

struct State {
    scanned: u64,
    seen: HashSet<H256>,
    pending: HashMap<H256, Pending>,
}

struct Ctx {
    cfg: Config,
    src: Provider<Http>,
    dst: Provider<Http>,
    wallet: LocalWallet,
    domain: H256,
}

pub async fn run() -> Res<()> {
    let cfg = Config::from_env()?;
    let src = Provider::<Http>::try_from(cfg.src_rpc.as_str())?;
    let dst = Provider::<Http>::try_from(cfg.dst_rpc.as_str())?;
    let wallet: LocalWallet = cfg.key.parse()?;

    let raw = eth_call(&dst, cfg.bridge, id("DOMAIN_SEPARATOR()").to_vec()).await?;
    if raw.len() < 32 {
        return Err("destination did not return DOMAIN_SEPARATOR".into());
    }
    let domain = H256::from_slice(&raw[..32]);
    fs::create_dir_all(&cfg.dir)?;
    println!(
        "[GUARDIAN {:?}] online | K={} | guardianSetId={} | domain={}",
        wallet.address(), cfg.k, cfg.set_id, h256_hex(domain)
    );

    let mut state = State { scanned: cfg.from_block, seen: HashSet::new(), pending: HashMap::new() };
    let ctx = Ctx { cfg, src, dst, wallet, domain };
    loop {
        if let Err(e) = tick(&ctx, &mut state).await {
            eprintln!("[WARN] {e}");
        }
        tokio::time::sleep(ctx.cfg.poll).await;
    }
}

async fn tick(ctx: &Ctx, st: &mut State) -> Res<()> {
    let cfg = &ctx.cfg;
    let head = ctx.src.get_block_number().await?.as_u64();

    // Re-scan a short tail every tick so reorged-then-reincluded deposits are seen again.
    let from = st.scanned.saturating_sub(cfg.k + 2).min(head);
    let filter = Filter::new().address(cfg.src_contract).event(DEPOSIT_EVENT).from_block(from).to_block(head);
    for log in ctx.src.get_logs(&filter).await? {
        let (Some(tx), Some(bn)) = (log.transaction_hash, log.block_number) else { continue };
        if log.removed == Some(true) || st.seen.contains(&tx) {
            continue;
        }
        let Some(mh) = log.topics.get(1).copied() else { continue };
        let tokens = decode(
            &[ParamType::Uint(256), ParamType::Uint(256), ParamType::Uint(256), ParamType::Bytes],
            log.data.as_ref(),
        )?;
        let amount = tokens[0].clone().into_uint().unwrap_or_default();
        let nonce = tokens[1].clone().into_uint().unwrap_or_default();
        let payload = tokens[3].clone().into_bytes().unwrap_or_default();
        st.seen.insert(tx);
        if H256::from(keccak256(&payload)) != mh {
            eprintln!("[WARN] tx {} payload does not hash to messageHash, ignored", h256_hex(tx));
            continue;
        }
        println!("[OBSERVED] msg {} | amount {} wei | nonce {} | block {}", short(mh), amount, nonce, bn);
        st.pending.insert(
            tx,
            Pending { message_hash: mh, block: bn.as_u64(), payload, signed_windows: HashSet::new(), last_status: None },
        );
    }
    st.scanned = head;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (valid_after, valid_until) = validity_window(now);
    let mut finished: Vec<(H256, bool)> = Vec::new();

    for (tx, p) in st.pending.iter_mut() {
        let receipt_hash = ctx.src.get_transaction_receipt(*tx).await?.and_then(|r| r.block_hash);
        let canonical = ctx.src.get_block(p.block).await?.and_then(|b| b.hash);
        let status = classify(receipt_hash, canonical, head, p.block, cfg.k);
        if p.last_status != Some(status) {
            println!("[STATUS] msg {} -> {:?}", short(p.message_hash), status);
            p.last_status = Some(status);
        }
        match status {
            SourceStatus::Pending { .. } => {}
            SourceStatus::Orphaned => {
                let ev = causal_evidence();
                println!(
                    "[REFUSED] msg {} | deposit no longer canonical (source reorg) | causal decision {:?} over {} nodes | no signature issued",
                    short(p.message_hash), ev.decision, ev.affected_nodes.len()
                );
                finished.push((*tx, true));
            }
            SourceStatus::Final => {
                if is_released(ctx, p.message_hash).await? {
                    println!("[DONE] msg {} released on destination", short(p.message_hash));
                    finished.push((*tx, false));
                    continue;
                }
                if p.signed_windows.insert(valid_after) {
                    let block = ctx.src.get_block(p.block).await?.ok_or("source block vanished")?;
                    let fields = AttestationFields {
                        message_hash: p.message_hash,
                        source_state_root: block.state_root,
                        valid_after: U256::from(valid_after),
                        valid_until: U256::from(valid_until),
                        source_block: U256::from(p.block),
                        guardian_set_id: U256::from(cfg.set_id),
                    };
                    let sig = ctx.wallet.sign_hash(digest(ctx.domain, &fields))?;
                    write_signature(&cfg.dir, &fields, ctx.wallet.address(), &sig, &p.payload)?;
                    println!(
                        "[SIGNED] msg {} | root {} | window {}..{}",
                        short(p.message_hash), short(block.state_root), valid_after, valid_until
                    );
                }
            }
        }
    }

    for (tx, orphaned) in finished {
        st.pending.remove(&tx);
        if orphaned {
            st.seen.remove(&tx);
        }
    }
    Ok(())
}

async fn eth_call(p: &Provider<Http>, to: Address, data: Vec<u8>) -> Res<Bytes> {
    let tx: TypedTransaction = TransactionRequest::new().to(to).data(data).into();
    Ok(p.call(&tx, None).await?)
}

async fn is_released(ctx: &Ctx, mh: H256) -> Res<bool> {
    let mut data = id("released(bytes32)").to_vec();
    data.extend_from_slice(mh.as_bytes());
    let out = eth_call(&ctx.dst, ctx.cfg.bridge, data).await?;
    Ok(out.len() == 32 && out[31] == 1)
}

/// Causal evidence for a refusal: ChainState -> Deposit -> Message, invalidated at the root.
fn causal_evidence() -> DecisionEvidence {
    let mut g = CausalGraph::new();
    let node = |kind| Node { id: NodeId(0), kind, observation: None, valid: true, invalidated: false, message: None };
    let state = g.add_node(node(NodeKind::ChainState));
    let deposit = g.add_node(node(NodeKind::Deposit));
    let message = g.add_node(node(NodeKind::Message));
    g.add_edge(Edge { from: state, to: deposit, kind: EdgeKind::Produces });
    g.add_edge(Edge { from: deposit, to: message, kind: EdgeKind::DerivesFrom });
    invalidate_derivation(state, &mut g)
}

fn write_signature(
    dir: &Path,
    f: &AttestationFields,
    signer: Address,
    sig: &ethers_core::types::Signature,
    payload: &[u8],
) -> Res<()> {
    let msg_dir = dir.join(h256_hex(f.message_hash));
    let win_dir = msg_dir.join(f.valid_after.to_string());
    fs::create_dir_all(&win_dir)?;
    atomic_write(&msg_dir.join("message.hex"), &format!("0x{}\n", hex::encode(payload)))?;
    let mut r = [0u8; 32];
    sig.r.to_big_endian(&mut r);
    let mut s = [0u8; 32];
    sig.s.to_big_endian(&mut s);
    let body = format!(
        "message_hash={}\nsource_state_root={}\nvalid_after={}\nvalid_until={}\nsource_block={}\nguardian_set_id={}\nsigner=0x{}\nv={}\nr=0x{}\ns=0x{}\n",
        h256_hex(f.message_hash),
        h256_hex(f.source_state_root),
        f.valid_after,
        f.valid_until,
        f.source_block,
        f.guardian_set_id,
        hex::encode(signer.as_bytes()),
        sig.v,
        hex::encode(r),
        hex::encode(s)
    );
    atomic_write(&win_dir.join(format!("0x{}.sig", hex::encode(signer.as_bytes()))), &body)
}

fn atomic_write(path: &Path, content: &str) -> Res<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, content)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn short(h: H256) -> String {
    let s = h256_hex(h);
    format!("{}…", &s[..12])
}
