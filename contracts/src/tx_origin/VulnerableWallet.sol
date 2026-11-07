// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableWallet
 * @notice Demonstrates tx.origin Authentication Misuse (SWC-115).
 * @dev Using tx.origin for authorization makes the contract vulnerable to phishing attacks
 * where an attacker convinces the owner to invoke an intermediary contract.
 */
contract VulnerableWallet {
    address public immutable owner;

    event Transferred(address indexed to, uint256 amount);

    constructor() payable {
        owner = msg.sender;
    }

    /// @notice VULNERABILITY: Uses tx.origin instead of msg.sender!
    function transfer(address payable to, uint256 amount) external {
        require(tx.origin == owner, "Not authorized: tx.origin must be owner");
        require(address(this).balance >= amount, "Insufficient balance");

        (bool sent, ) = to.call{value: amount}("");
        require(sent, "Failed to send Ether");

        emit Transferred(to, amount);
    }

    receive() external payable {}
}
