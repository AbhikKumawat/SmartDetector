// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableToken
 * @notice Demonstrates Integer Underflow / Overflow vulnerabilities (SWC-101).
 * @dev Simulates legacy Solidity (<0.8.0) unchecked arithmetic flaw where subtracting
 * more than balance wraps around to 2^256 - 1.
 */
contract VulnerableToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(uint256 _initialSupply) {
        balances[msg.sender] = _initialSupply;
        totalSupply = _initialSupply;
    }

    /// @notice VULNERABILITY: Underflow in subtraction allowing arbitrary token generation!
    function transfer(address to, uint256 amount) external returns (bool) {
        // Flawed condition: balances[msg.sender] - amount is unsigned, always >= 0!
        unchecked {
            require(balances[msg.sender] - amount >= 0, "Insufficient balance");
            balances[msg.sender] -= amount; // Underflows if amount > balance!
            balances[to] += amount;
        }

        emit Transfer(msg.sender, to, amount);
        return true;
    }
}
