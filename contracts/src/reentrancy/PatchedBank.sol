// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title PatchedBank
 * @notice Remediated version of VulnerableBank preventing reentrancy attacks.
 * @dev Employs the Checks-Effects-Interactions (CEI) pattern and OpenZeppelin ReentrancyGuard.
 */
contract PatchedBank is ReentrancyGuard {
    mapping(address => uint256) public balances;

    event Deposited(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount);

    function deposit() external payable {
        require(msg.value > 0, "Deposit must be > 0");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice REMEDIATION:
    /// 1. Uses nonReentrant modifier (mutex pattern).
    /// 2. Applies Checks-Effects-Interactions: balance is reset before external call.
    function withdraw() external nonReentrant {
        // 1. Checks
        uint256 balance = balances[msg.sender];
        require(balance > 0, "Insufficient balance");

        // 2. Effects
        balances[msg.sender] = 0;
        emit Withdrawn(msg.sender, balance);

        // 3. Interactions
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
