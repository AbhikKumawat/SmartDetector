// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableVault
 * @notice Demonstrates Missing & Improper Access Control (SWC-105 / SWC-106).
 * @dev The critical function `setOwner()` lacks an authorization check, allowing
 * any caller to seize ownership and drain the treasury.
 */
contract VulnerableVault {
    address public owner;
    uint256 public totalDeposits;

    event OwnerChanged(address indexed oldOwner, address indexed newOwner);
    event EmergencyDrain(address indexed attacker, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    /// @notice VULNERABILITY: Missing access modifier (`onlyOwner`).
    /// Any external account can call this and overwrite the owner address.
    function setOwner(address newOwner) external {
        require(newOwner != address(0), "Invalid address");
        emit OwnerChanged(owner, newOwner);
        owner = newOwner;
    }

    function deposit() external payable {
        require(msg.value > 0, "No ETH sent");
        totalDeposits += msg.value;
    }

    /// @notice Privileged function intended only for contract owner.
    function withdrawAll(address payable recipient) external {
        require(msg.sender == owner, "Unauthorized: Only owner can withdraw");
        uint256 balance = address(this).balance;
        (bool sent, ) = recipient.call{value: balance}("");
        require(sent, "Failed to send Ether");
        emit EmergencyDrain(recipient, balance);
    }
}
