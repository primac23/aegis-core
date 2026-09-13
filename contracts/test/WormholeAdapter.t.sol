// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {WormholeAegisAdapter} from "../src/WormholeAegisAdapter.sol";
import {IFirewallGatedBridge, Signature, MultiAttestation} from "../src/IFirewallGatedBridge.sol";

contract WormholeAdapterTest is Test {
    WormholeAegisAdapter public adapter;

    uint256 internal keyA = 0x1111;
    uint256 internal keyB = 0x2222;
    uint256 internal keyC = 0x3333;

    address internal guardianA;
    address internal guardianB;
    address internal guardianC;

    uint256 internal activeSetId = 1;
    bytes internal sampleVaa;
    bytes32 internal vaaHash;
    bytes32 internal stateRoot = keccak256("wormhole_canonical_state");

    function setUp() public {
        vm.warp(1_000_000);

        guardianA = vm.addr(keyA);
        guardianB = vm.addr(keyB);
        guardianC = vm.addr(keyC);

        address[] memory guardians = new address[](3);
        guardians[0] = guardianA;
        guardians[1] = guardianB;
        guardians[2] = guardianC;

        adapter = new WormholeAegisAdapter(guardians, 2, activeSetId);

        // Simulăm un payload VAA: ChainId 2 (Ethereum), emitter 0x01, seq 42, recipient Alice, 50 ETH
        sampleVaa = abi.encode(
            uint16(2),
            bytes32(uint256(1)),
            uint64(42),
            makeAddr("alice"),
            50 ether
        );
        vaaHash = keccak256(sampleVaa);
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (Signature memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return Signature(v, r, s);
    }

    // Scenariul 1: VAA autentic, dar starea sursă a suferit reorg -> lipsă atestare AEGIS -> REVERT
    function test_RevertWhen_VaaAuthentic_ButAegisAuthorizationMissing() public {
        bytes memory emptyAttestation = "";

        vm.expectRevert(IFirewallGatedBridge.AttestationMissing.selector);
        adapter.completeTransferWithAegis(sampleVaa, emptyAttestation);
    }

    // Scenariul 2: VAA autentic + Stare canonică validată în DAG -> ALLOW
    function test_SuccessWhen_VaaAndAegisQuorumValid() public {
        bytes32 digest = adapter.hashTypedAttestation(
            vaaHash,
            stateRoot,
            block.timestamp,
            block.timestamp + 60,
            19500000,
            activeSetId
        );

        Signature[] memory sigs = new Signature[](2);
        if (guardianA < guardianB) {
            sigs[0] = _sign(keyA, digest);
            sigs[1] = _sign(keyB, digest);
        } else {
            sigs[0] = _sign(keyB, digest);
            sigs[1] = _sign(keyA, digest);
        }

        bytes memory attestation = abi.encode(
            MultiAttestation({
                messageHash: vaaHash,
                sourceStateRoot: stateRoot,
                validAfter: block.timestamp,
                validUntil: block.timestamp + 60,
                sourceBlock: 19500000,
                guardianSetId: activeSetId,
                signatures: sigs
            })
        );

        adapter.completeTransferWithAegis(sampleVaa, attestation);
        assertTrue(adapter.released(vaaHash));
    }
}
