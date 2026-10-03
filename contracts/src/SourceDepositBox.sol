// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Source-side deposit emitter. Each deposit gets a unique, domain-separated payload:
///         abi.encode(recipient, amount, nonce, sourceChainId, sourceContract).
///         The first two fields stay compatible with IFirewallGatedBridge's (address,uint256) decoding.
contract SourceDepositBox {
    uint256 public nonce;

    event Deposit(
        bytes32 indexed messageHash,
        address indexed sender,
        address indexed recipient,
        uint256 amount,
        uint256 nonce,
        uint256 sourceBlock,
        bytes payload
    );

    function deposit(address recipient, uint256 amount)
        external
        returns (bytes32 messageHash, bytes memory payload)
    {
        uint256 n = nonce++;
        payload = abi.encode(recipient, amount, n, block.chainid, address(this));
        messageHash = keccak256(payload);
        emit Deposit(messageHash, msg.sender, recipient, amount, n, block.number, payload);
    }
}
