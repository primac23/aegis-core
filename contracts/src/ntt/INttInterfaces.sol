// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal NTT surface AEGIS needs. Signatures match wormhole-foundation/native-token-transfers
///         (evm/src/interfaces/ITransceiver.sol, INttManager.sol) so AegisNttTransceiver is drop-in.
library TransceiverStructs {
    struct TransceiverInstruction {
        uint8 index;
        bytes payload;
    }
}

interface ITransceiverMinimal {
    error CallerNotNttManager(address caller);

    function getNttManagerToken() external view returns (address);
    function getTransceiverType() external view returns (string memory);
    function quoteDeliveryPrice(uint16 recipientChain, TransceiverStructs.TransceiverInstruction memory instruction)
        external
        view
        returns (uint256);
    function sendMessage(
        uint16 recipientChain,
        TransceiverStructs.TransceiverInstruction memory instruction,
        bytes memory nttManagerMessage,
        bytes32 recipientNttManagerAddress,
        bytes32 refundAddress
    ) external payable;
}

/// @notice The destination-side hook a transceiver calls once it has verified a message.
///         Matches NttManager.attestationReceived.
interface INttManagerAttest {
    function attestationReceived(
        uint16 sourceChainId,
        bytes32 sourceNttManagerAddress,
        bytes memory payload
    ) external;
}
