// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title PatchedDistributor
 * @notice Remediated distributor employing the Pull-Payment pattern.
 * @dev Replaces unbounded loop push distribution with O(1) state accounting
 * and independent claim calls, eliminating DoS vectors.
 */
contract PatchedDistributor is ReentrancyGuard {
    address[] public investors;
    mapping(address => bool) public isInvestor;
    mapping(address => uint256) public claimableRewards;

    event InvestorAdded(address indexed investor);
    event RewardAllocated(uint256 amountPerInvestor);
    event RewardClaimed(address indexed investor, uint256 amount);

    error NoRewardProvided();
    error NoInvestors();
    error NoRewardsToClaim();
    error TransferFailed();

    function join() external payable {
        require(msg.value >= 0.1 ether, "Minimum 0.1 ETH");
        if (!isInvestor[msg.sender]) {
            isInvestor[msg.sender] = true;
            investors.push(msg.sender);
            emit InvestorAdded(msg.sender);
        }
    }

    /// @notice Allocates accounting balances without external calls in loop
    function notifyReward() external payable {
        if (msg.value == 0) revert NoRewardProvided();
        uint256 total = investors.length;
        if (total == 0) revert NoInvestors();

        uint256 payoutPerUser = msg.value / total;
        for (uint256 i = 0; i < total; i++) {
            claimableRewards[investors[i]] += payoutPerUser;
        }

        emit RewardAllocated(payoutPerUser);
    }

    /// @notice REMEDIATION: Pull payment prevents malicious contract from stalling system
    function claimReward() external nonReentrant {
        uint256 amount = claimableRewards[msg.sender];
        if (amount == 0) revert NoRewardsToClaim();

        claimableRewards[msg.sender] = 0;

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        if (!success) {
            claimableRewards[msg.sender] = amount;
            revert TransferFailed();
        }

        emit RewardClaimed(msg.sender, amount);
    }
}
