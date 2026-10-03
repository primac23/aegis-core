// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IFirewallGatedBridge} from "../IFirewallGatedBridge.sol";
import {ITransceiverMinimal, INttManagerAttest, TransceiverStructs} from "./INttInterfaces.sol";

/// @notice AEGIS packaged as a Wormhole NTT transceiver. It attests a cross-chain message to its
///         NttManager ONLY after the AEGIS M-of-N guardian check passes (finality + multi-RPC
///         consensus are enforced off-chain by the guardian daemon before signing).
///
///         Deployed alongside the Wormhole transceiver under one NttManager with threshold 2/2,
///         both must attest before the manager executes — defense in depth without a parallel system.
contract AegisNttTransceiver is IFirewallGatedBridge, ITransceiverMinimal {
    error RecipientManagerMismatch(bytes32 got, bytes32 expected);
    error ZeroManager();

    address public immutable nttManager;
    address public immutable nttToken;
    bytes32 public immutable selfPeer; // this manager, Wormhole-formatted, for echo checks

    event AegisAttestationForwarded(
        bytes32 indexed messageHash, uint16 indexed sourceChainId, bytes32 sourceNttManager
    );

    modifier onlyManager() {
        if (msg.sender != nttManager) revert CallerNotNttManager(msg.sender);
        _;
    }

    constructor(
        address _nttManager,
        address _nttToken,
        address[] memory _guardians,
        uint256 _threshold,
        uint256 _guardianSetId
    ) IFirewallGatedBridge(_guardians, _threshold, _guardianSetId) {
        if (_nttManager == address(0)) revert ZeroManager();
        nttManager = _nttManager;
        nttToken = _nttToken;
        selfPeer = bytes32(uint256(uint160(_nttManager)));
    }

    // --- ITransceiver (identity + send side; send is a no-op stub for this verification-only transceiver) ---

    function getNttManagerToken() external view returns (address) {
        return nttToken;
    }

    function getTransceiverType() external pure returns (string memory) {
        return "aegis";
    }

    function quoteDeliveryPrice(uint16, TransceiverStructs.TransceiverInstruction memory)
        external
        pure
        returns (uint256)
    {
        return 0; // AEGIS attests an already-delivered message; it does not relay.
    }

    function sendMessage(
        uint16,
        TransceiverStructs.TransceiverInstruction memory,
        bytes memory,
        bytes32,
        bytes32
    ) external payable onlyManager {
        // AEGIS is a verification transceiver: the authenticity path (Wormhole) carries delivery.
        // No-op send keeps the ITransceiver surface complete for registration under the manager.
    }

    // --- Receive side: the AEGIS gate ---

    /// @notice Verify an AEGIS attestation for a delivered NTT message, then attest it to the manager.
    /// @param sourceChainId      Wormhole chain ID of the source.
    /// @param sourceNttManager   Source NttManager, Wormhole-formatted.
    /// @param nttManagerMessage  The exact NttManager message bytes delivered cross-chain.
    /// @param aegisAttestation   AEGIS M-of-N attestation bound to keccak256(nttManagerMessage).
    function receiveAndAttest(
        uint16 sourceChainId,
        bytes32 sourceNttManager,
        bytes calldata nttManagerMessage,
        bytes calldata aegisAttestation
    ) external {
        bytes32 messageHash = keccak256(nttManagerMessage);
        _verifyAttestation(messageHash, aegisAttestation); // reverts unless AEGIS quorum is valid
        emit AegisAttestationForwarded(messageHash, sourceChainId, sourceNttManager);
        INttManagerAttest(nttManager).attestationReceived(sourceChainId, sourceNttManager, nttManagerMessage);
    }
}
