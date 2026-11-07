// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableBank
 * @notice Demonstrates a classic Reentrancy vulnerability (SWC-107).
 * @dev The withdraw function sends ether to msg.sender before zeroing their balance,
 * allowing an attacker's fallback/receive function to recursively call withdraw.
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;

    event Deposited(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount);

    function deposit() external payable {
        require(msg.value > 0, "Deposit must be > 0");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice VULNERABILITY: State change happens AFTER the external call.
    function withdraw() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "Insufficient balance");

        // Vulnerable external call before balance update
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        // State update happens too late!
        balances[msg.sender] = 0;
        emit Withdrawn(msg.sender, balance);
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
