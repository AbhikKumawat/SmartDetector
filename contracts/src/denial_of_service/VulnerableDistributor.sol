// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableDistributor
 * @notice Demonstrates Denial of Service (DoS) via Reverting External Calls in Unbounded Loops (SWC-113).
 * @dev If any recipient reverts on receive, or if gas limit is exceeded by array growth,
 * the entire payout process is permanently frozen.
 */
contract VulnerableDistributor {
    address[] public investors;
    mapping(address => bool) public isInvestor;

    event InvestorAdded(address indexed investor);
    event RewardsDistributed(uint256 totalAmount);

    function join() external payable {
        require(msg.value >= 0.1 ether, "Minimum 0.1 ETH");
        if (!isInvestor[msg.sender]) {
            isInvestor[msg.sender] = true;
            investors.push(msg.sender);
            emit InvestorAdded(msg.sender);
        }
    }

    /// @notice VULNERABILITY: Unbounded loop with pushing ETH!
    /// A single reverting contract in `investors` prevents all payouts.
    function distributeReward() external payable {
        require(msg.value > 0, "No reward provided");
        require(investors.length > 0, "No investors");

        uint256 payoutPerUser = msg.value / investors.length;

        for (uint256 i = 0; i < investors.length; i++) {
            // If one address reverts (e.g. MaliciousReceiver), whole function reverts!
            (bool success, ) = payable(investors[i]).call{value: payoutPerUser}("");
            require(success, "Payout failed to investor");
        }

        emit RewardsDistributed(msg.value);
    }

    function getInvestorCount() external view returns (uint256) {
        return investors.length;
    }
}
