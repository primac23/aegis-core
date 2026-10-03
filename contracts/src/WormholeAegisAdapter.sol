// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IFirewallGatedBridge} from "./IFirewallGatedBridge.sol";
import {IWormhole} from "./interfaces/IWormhole.sol";

/// @notice A release requires BOTH:
///         1. Authenticity: a valid Wormhole VAA from the registered emitter, at finalized consistency.
///         2. Authorization: an AEGIS M-of-N attestation bound to the VAA hash.
contract WormholeAegisAdapter is IFirewallGatedBridge {
    error InvalidVaa(string reason);
    error UnknownEmitter(uint16 emitterChainId, bytes32 emitterAddress);
    error VaaNotFinalized(uint8 consistencyLevel);
    error InvalidWormholeCore();
    error EmitterConfigMismatch();

    /// @notice Wormhole EVM consistency levels that are not finalized.
    uint8 public constant CONSISTENCY_INSTANT = 200;
    uint8 public constant CONSISTENCY_SAFE = 201;

    IWormhole public immutable wormhole;
    mapping(uint16 => bytes32) public registeredEmitter;

    event WormholeReleaseExecuted(
        bytes32 indexed vaaHash,
        uint16 indexed emitterChainId,
        uint64 indexed sequence,
        address recipient,
        uint256 amount
    );

    constructor(
        address[] memory _guardians,
        uint256 _threshold,
        uint256 _guardianSetId,
        address _wormholeCore,
        uint16[] memory _emitterChains,
        bytes32[] memory _emitters
    ) IFirewallGatedBridge(_guardians, _threshold, _guardianSetId) {
        if (_wormholeCore == address(0)) revert InvalidWormholeCore();
        if (_emitters.length == 0 || _emitterChains.length != _emitters.length) revert EmitterConfigMismatch();
        wormhole = IWormhole(_wormholeCore);
        for (uint256 i = 0; i < _emitters.length; i++) {
            if (_emitters[i] == bytes32(0) || registeredEmitter[_emitterChains[i]] != bytes32(0)) {
                revert EmitterConfigMismatch();
            }
            registeredEmitter[_emitterChains[i]] = _emitters[i];
        }
    }

    function completeTransferWithAegis(bytes calldata encodedVm, bytes calldata aegisAttestation)
        external
        returns (bytes32 vaaHash)
    {
        (IWormhole.VM memory vaa, bool valid, string memory reason) = wormhole.parseAndVerifyVM(encodedVm);
        if (!valid) revert InvalidVaa(reason);

        bytes32 expected = registeredEmitter[vaa.emitterChainId];
        if (expected == bytes32(0) || expected != vaa.emitterAddress) {
            revert UnknownEmitter(vaa.emitterChainId, vaa.emitterAddress);
        }

        if (vaa.consistencyLevel == CONSISTENCY_INSTANT || vaa.consistencyLevel == CONSISTENCY_SAFE) {
            revert VaaNotFinalized(vaa.consistencyLevel);
        }

        vaaHash = vaa.hash;
        _verifyAttestation(vaaHash, aegisAttestation);

        (address recipient, uint256 amount) = abi.decode(vaa.payload, (address, uint256));
        emit WormholeReleaseExecuted(vaaHash, vaa.emitterChainId, vaa.sequence, recipient, amount);
    }
}
