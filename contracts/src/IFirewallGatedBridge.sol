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
    error QuorumNotReached();
    error DuplicateSigner();
    error InvalidSigner();
    error InvalidMessage();

    // Structură extinsă cu sourceStateRoot pentru angajament de stare real
    bytes32 public constant ATTESTATION_TYPEHASH =
        keccak256(
            "FirewallAttestation(bytes32 messageHash,bytes32 sourceStateRoot,uint256 validAfter,uint256 validUntil,uint256 sourceBlock)"
        );

    bytes32 public immutable DOMAIN_SEPARATOR;
    uint256 public constant MAX_ATTESTATION_AGE = 2 minutes;
    
    // Prag M of N (ex: 2 din 3)
    uint256 public immutable threshold;
    mapping(address => bool) public isGuardian;

    mapping(bytes32 => bool) public released;

    struct Signature {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    struct MultiAttestation {
        bytes32 messageHash;
        bytes32 sourceStateRoot;
        uint256 validAfter;
        uint256 validUntil;
        uint256 sourceBlock;
        Signature[] signatures;
    }

    constructor(address[] memory _guardians, uint256 _threshold) {
        require(_threshold > 0 && _threshold <= _guardians.length, "Invalid threshold");
        threshold = _threshold;

        for (uint256 i = 0; i < _guardians.length; i++) {
            address g = _guardians[i];
            if (g == address(0) || isGuardian[g]) revert InvalidSigner();
            isGuardian[g] = true;
        }

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
        if (attestation.length == 0) revert AttestationMissing();

        messageHash = keccak256(message);
        MultiAttestation memory a = abi.decode(attestation, (MultiAttestation));

        if (a.messageHash != messageHash) revert InvalidMessage();
        if (released[messageHash]) revert MessageAlreadyReleased();
        if (block.timestamp < a.validAfter) revert AttestationNotYetValid();
        if (block.timestamp > a.validUntil) revert AttestationExpired();
        if (a.validUntil > block.timestamp + MAX_ATTESTATION_AGE) revert AttestationInvalid();
        if (a.sourceBlock == 0 || a.sourceStateRoot == bytes32(0)) revert AttestationInvalid();

        // Verificăm pragul M of N
        if (a.signatures.length < threshold) revert QuorumNotReached();

        bytes32 structHash = keccak256(
            abi.encode(
                ATTESTATION_TYPEHASH,
                a.messageHash,
                a.sourceStateRoot,
                a.validAfter,
                a.validUntil,
                a.sourceBlock
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );

        address lastSigner = address(0);
        uint256 validSignatures = 0;

        for (uint256 i = 0; i < a.signatures.length; i++) {
            address signer = digest.recover(a.signatures[i].v, a.signatures[i].r, a.signatures[i].s);
            
            // Forțăm ordonare strictă pentru a preveni duplicatele fără mapping suplimentar
            if (signer <= lastSigner) revert DuplicateSigner();
            lastSigner = signer;

            if (isGuardian[signer]) {
                validSignatures++;
            }
        }

        if (validSignatures < threshold) revert QuorumNotReached();

        released[messageHash] = true;
        _executeRelease(message);
    }

    function _executeRelease(bytes calldata message) internal {
        // Deblocare fonduri
    }

    function hashTypedAttestation(
        bytes32 messageHash,
        bytes32 sourceStateRoot,
        uint256 validAfter,
        uint256 validUntil,
        uint256 sourceBlock
    ) external view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                ATTESTATION_TYPEHASH,
                messageHash,
                sourceStateRoot,
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
