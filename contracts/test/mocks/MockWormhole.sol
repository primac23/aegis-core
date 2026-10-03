// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IWormhole} from "../../src/interfaces/IWormhole.sol";

/// @notice Test double for Wormhole Core. encodedVM = abi.encode(body, v, r, s), where
///         body = abi.encode(version, timestamp, nonce, emitterChainId, emitterAddress, sequence, consistencyLevel, payload)
///         and hash = keccak256(keccak256(body)), signed by a single Wormhole guardian key.
contract MockWormhole is IWormhole {
    address public immutable wormholeGuardian;

    constructor(address _wormholeGuardian) {
        wormholeGuardian = _wormholeGuardian;
    }

    function parseAndVerifyVM(bytes calldata encodedVM)
        external
        view
        returns (VM memory vm_, bool valid, string memory reason)
    {
        (bytes memory body, uint8 v, bytes32 r, bytes32 s) = abi.decode(encodedVM, (bytes, uint8, bytes32, bytes32));
        (
            vm_.version,
            vm_.timestamp,
            vm_.nonce,
            vm_.emitterChainId,
            vm_.emitterAddress,
            vm_.sequence,
            vm_.consistencyLevel,
            vm_.payload
        ) = abi.decode(body, (uint8, uint32, uint32, uint16, bytes32, uint64, uint8, bytes));
        vm_.hash = keccak256(abi.encodePacked(keccak256(body)));

        address signer = ecrecover(vm_.hash, v, r, s);
        if (signer == address(0) || signer != wormholeGuardian) {
            return (vm_, false, "VM signature invalid");
        }
        return (vm_, true, "");
    }
}
