// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract IFirewallGatedBridge {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    error AttestationMissing();
    error AttestationInvalid();
    error AttestationExpired();
    error AttestationNotYetValid();
    error MessageAlreadyReleased();
    error InvalidSigner();
    error InvalidMessage();

    bytes32 public constant ATTESTATION_TYPEHASH =
        keccak256(
            "FirewallAttestation(bytes32 messageHash,uint256 validAfter,uint256 validUntil,uint256 sourceBlock)"
        );

    bytes32 public immutable DOMAIN_SEPARATOR;
    address public immutable firewallSigner;
    uint256 public constant MAX_ATTESTATION_AGE = 2 minutes;

    mapping(bytes32 => bool) public released;

    struct Attestation {
        bytes32 messageHash;
        uint256 validAfter;
        uint256 validUntil;
        uint256 sourceBlock;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    constructor(address _firewallSigner) {
        if (_firewallSigner == address(0)) revert InvalidSigner();
        firewallSigner = _firewallSigner;

        uint256 chainId;
        assembly {
            chainId := chainid()
        }

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("AEGIS Firewall")),
                keccak256(bytes("1")),
                chainId,
                address(this)
            )
        );
    }

    function release(
        bytes calldata message,
        bytes calldata attestation
    ) external returns (bytes32 messageHash) {
        if (attestation.length == 0) {
            revert AttestationMissing();
        }

        messageHash = keccak256(message);
        Attestation memory a = abi.decode(attestation, (Attestation));

        if (a.messageHash != messageHash) {
            revert InvalidMessage();
        }
        if (released[messageHash]) {
            revert MessageAlreadyReleased();
        }
        if (block.timestamp < a.validAfter) {
            revert AttestationNotYetValid();
        }
        if (block.timestamp > a.validUntil) {
            revert AttestationExpired();
        }
        if (a.validUntil > block.timestamp + MAX_ATTESTATION_AGE) {
            revert AttestationInvalid();
        }

        bytes32 structHash = keccak256(
            abi.encode(
                ATTESTATION_TYPEHASH,
                a.messageHash,
                a.validAfter,
                a.validUntil,
                a.sourceBlock
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );

        address signer = digest.recover(a.v, a.r, a.s);
        if (signer != firewallSigner) {
            revert InvalidSigner();
        }

        if (a.sourceBlock == 0) {
            revert AttestationInvalid();
        }

        released[messageHash] = true;
        _executeRelease(message);
    }

    function _executeRelease(bytes calldata message) internal {
        // Fondurile sunt deblocate legitim
    }

    function hashTypedAttestation(
        bytes32 messageHash,
        uint256 validAfter,
        uint256 validUntil,
        uint256 sourceBlock
    ) external view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                ATTESTATION_TYPEHASH,
                messageHash,
                validAfter,
                validUntil,
                sourceBlock
            )
        );
        return keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );
    }
}
