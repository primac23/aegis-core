use std::collections::HashSet;
use ethers_core::types::U256;
use crate::types::{CausalGraph, Decision, DecisionEvidence, EdgeKind, NodeId, NodeKind};

#[inline]
pub fn invalidate_derivation(
    root_node: NodeId,
    graph: &mut CausalGraph,
) -> DecisionEvidence {
    graph.queue.clear();
    let mut visited: HashSet<NodeId> = HashSet::new();
    let mut affected_nodes = Vec::with_capacity(16);
    let mut invalid_messages = Vec::with_capacity(8);
    let mut economic_exposure = U256::zero();

    graph.queue.push_back(root_node);
    visited.insert(root_node);
    let mut hard_freeze = false;
    let mut delayed = false;

    while let Some(current) = graph.queue.pop_front() {
        affected_nodes.push(current);
        {
            let node = graph.node_mut(current);
            node.invalidated = true;
            node.valid = false;
        }

        let kind = graph.node(current).kind;
        match kind {
            NodeKind::Message => {
                invalid_messages.push(current);
                hard_freeze = true;
            }
            NodeKind::Release => {
                hard_freeze = true;
                economic_exposure += U256::from(100u64);
            }
            NodeKind::Deposit | NodeKind::Asset | NodeKind::ChainState => {
                delayed = true;
            }
            NodeKind::ValidatorSet => {
                hard_freeze = true;
            }
        }

        let outgoing = graph.edges_from(current).to_vec();
        for edge_index in outgoing {
            let edge = graph.edges[edge_index as usize];
            match edge.kind {
                EdgeKind::DerivesFrom
                | EdgeKind::Produces
                | EdgeKind::DependsOn
                | EdgeKind::Authenticates
                | EdgeKind::Invalidates => {
                    let child = edge.to;
                    if visited.insert(child) {
                        graph.queue.push_back(child);
                    }
                }
            }
        }
    }

    let decision = if hard_freeze {
        Decision::Freeze
    } else if delayed {
        Decision::Delay
    } else {
        Decision::Observe
    };

    let confidence_bps = match decision {
        Decision::Freeze => 10_000,
        Decision::Delay => 9_000,
        Decision::Observe => 5_000,
        Decision::Allow => 0,
    };

    DecisionEvidence {
        decision,
        root: root_node,
        affected_nodes,
        invalid_messages,
        confidence_bps,
        economic_exposure,
    }
}
