// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SourceDepositBox {
    event Deposit(
        bytes32 indexed messageHash,
        address indexed sender,
        address indexed recipient,
        uint256 amount,
        uint256 sourceBlock
    );

    function deposit(address recipient, uint256 amount) external returns (bytes32 messageHash) {
        bytes memory payload = abi.encode(recipient, amount);
        messageHash = keccak256(payload);

        emit Deposit(
            messageHash,
            msg.sender,
            recipient,
            amount,
            block.number
        );
    }
}
