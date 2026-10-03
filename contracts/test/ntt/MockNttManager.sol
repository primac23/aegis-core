// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {INttManagerAttest} from "../../src/ntt/INttInterfaces.sol";

/// @notice Test double mirroring NttManager attestation accounting: a transceiver bitmap,
///         an M-of-N threshold, single execution, and TransceiverAlreadyAttestedToMessage.
contract MockNttManager is INttManagerAttest {
    error TransceiverAlreadyAttestedToMessage(bytes32 messageHash);
    error NotATransceiver(address who);

    event TransferExecuted(bytes32 indexed messageHash, uint16 sourceChainId);

    uint8 public threshold;
    address public nttToken;
    mapping(address => uint8) public transceiverIndex; // 1-based; 0 = not registered
    mapping(bytes32 => uint64) public attestedBitmap;
    mapping(bytes32 => bool) public executed;

    constructor(address _token, uint8 _threshold) {
        nttToken = _token;
        threshold = _threshold;
    }

    function registerTransceiver(address t, uint8 index1based) external {
        transceiverIndex[t] = index1based;
    }

    function attestationReceived(uint16 sourceChainId, bytes32, bytes calldata payload) external {
        uint8 idx = transceiverIndex[msg.sender];
        if (idx == 0) revert NotATransceiver(msg.sender);
        bytes32 h = keccak256(payload);
        uint64 bit = uint64(1) << (idx - 1);
        if (attestedBitmap[h] & bit != 0) revert TransceiverAlreadyAttestedToMessage(h);
        attestedBitmap[h] |= bit;

        if (!executed[h] && _popcount(attestedBitmap[h]) >= threshold) {
            executed[h] = true;
            emit TransferExecuted(h, sourceChainId);
        }
    }

    function attestations(bytes32 h) external view returns (uint8) {
        return _popcount(attestedBitmap[h]);
    }

    function _popcount(uint64 x) internal pure returns (uint8 c) {
        while (x != 0) {
            c += uint8(x & 1);
            x >>= 1;
        }
    }
}
