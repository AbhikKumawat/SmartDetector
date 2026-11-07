// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PatchedToken
 * @notice Remediated token utilizing native checked arithmetic and explicit boundary assertions.
 * @dev Reverts with custom errors if balance is insufficient, preventing underflow/overflow.
 */
contract PatchedToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);

    error InsufficientBalance(uint256 available, uint256 required);
    error InvalidRecipient();

    constructor(uint256 _initialSupply) {
        balances[msg.sender] = _initialSupply;
        totalSupply = _initialSupply;
    }

    /// @notice REMEDIATION: Strict check and checked arithmetic
    function transfer(address to, uint256 amount) external returns (bool) {
        if (to == address(0)) revert InvalidRecipient();
        if (balances[msg.sender] < amount) {
            revert InsufficientBalance(balances[msg.sender], amount);
        }

        // Native checked arithmetic automatically reverts on overflow/underflow
        balances[msg.sender] -= amount;
        balances[to] += amount;

        emit Transfer(msg.sender, to, amount);
        return true;
    }
}
