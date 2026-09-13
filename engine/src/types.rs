#![allow(dead_code, unused_variables)]
use std::collections::VecDeque;
use ethers_core::{
    types::{Address, H256, U256},
    utils::keccak256,
};

pub type ChainId = u32;
pub type Height = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct NodeId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Finality {
    Observed = 0,
    Confirmed = 1,
    Finalized = 2,
    Reorged = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NodeKind {
    ChainState = 0,
    Message = 1,
    Deposit = 2,
    Release = 3,
    Asset = 4,
    ValidatorSet = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EdgeKind {
    DerivesFrom = 0,
    Authenticates = 1,
    Produces = 2,
    DependsOn = 3,
    Invalidates = 4,
}

#[derive(Clone, Debug)]
pub struct CanonicalMessage {
    pub src_chain: ChainId,
    pub dst_chain: ChainId,
    pub src_contract: Address,
    pub dst_contract: Address,
    pub nonce: u64,
    pub payload_hash: H256,
    pub domain_separator: H256,
}

impl CanonicalMessage {
    pub fn hash(&self) -> H256 {
        let mut buf = [0u8; 32 * 7];
        buf[0..32].copy_from_slice(self.domain_separator.as_bytes());
        U256::from(self.src_chain).to_big_endian(&mut buf[32..64]);
        U256::from(self.dst_chain).to_big_endian(&mut buf[64..96]);
        buf[96..128].copy_from_slice(self.src_contract.as_bytes());
        buf[128..160].copy_from_slice(self.dst_contract.as_bytes());
        U256::from(self.nonce).to_big_endian(&mut buf[160..192]);
        buf[192..224].copy_from_slice(self.payload_hash.as_bytes());
        H256::from(keccak256(buf))
    }
}

#[derive(Clone, Debug)]
pub struct Observation {
    pub chain_id: ChainId,
    pub height: Height,
    pub block_hash: H256,
    pub parent_hash: H256,
    pub tx_hash: H256,
    pub node: NodeId,
    pub finality: Finality,
    pub timestamp: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    pub kind: EdgeKind,
}

#[derive(Clone, Debug)]
pub struct Node {
    pub id: NodeId,
    pub kind: NodeKind,
    pub observation: Option<Observation>,
    pub valid: bool,
    pub invalidated: bool,
    pub message: Option<CanonicalMessage>,
}

#[derive(Clone, Debug)]
pub struct DecisionEvidence {
    pub decision: Decision,
    pub root: NodeId,
    pub affected_nodes: Vec<NodeId>,
    pub invalid_messages: Vec<NodeId>,
    pub confidence_bps: u32,
    pub economic_exposure: U256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Decision {
    Allow = 0,
    Observe = 1,
    Delay = 2,
    Freeze = 3,
}

pub struct CausalGraph {
    pub nodes: Vec<Node>,
    pub out_edges: Vec<Vec<u32>>,
    pub edges: Vec<Edge>,
    pub queue: VecDeque<NodeId>,
}

impl CausalGraph {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            out_edges: Vec::new(),
            edges: Vec::new(),
            queue: VecDeque::new(),
        }
    }

    #[inline(always)]
    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id.0 as usize]
    }

    #[inline(always)]
    pub fn node_mut(&mut self, id: NodeId) -> &mut Node {
        &mut self.nodes[id.0 as usize]
    }

    #[inline(always)]
    pub fn edges_from(&self, id: NodeId) -> &[u32] {
        &self.out_edges[id.0 as usize]
    }

    pub fn add_node(&mut self, mut node: Node) -> NodeId {
        let id = NodeId(self.nodes.len() as u32);
        node.id = id;
        self.nodes.push(node);
        self.out_edges.push(Vec::new());
        id
    }

    pub fn add_edge(&mut self, edge: Edge) {
        let index = self.edges.len() as u32;
        self.edges.push(edge);
        self.out_edges[edge.from.0 as usize].push(index);
    }
}
