// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title PatchedAuction
 * @notice Remediated auction using the Pull-over-Push architectural pattern.
 * @dev Instead of pushing refunds directly during new bids, refunds are recorded
 * in state and withdrawn independently by bidders, eliminating DoS and unchecked call risks.
 */
contract PatchedAuction is ReentrancyGuard {
    address public highestBidder;
    uint256 public highestBid;

    mapping(address => uint256) public pendingReturns;

    event BidPlaced(address indexed bidder, uint256 amount);
    event RefundClaimed(address indexed bidder, uint256 amount);

    error BidTooLow(uint256 currentHighest);
    error NoPendingRefund();
    error TransferFailed();

    function bid() external payable {
        if (msg.value <= highestBid) {
            revert BidTooLow(highestBid);
        }

        if (highestBidder != address(0)) {
            // REMEDIATION: Pull-over-push pattern
            pendingReturns[highestBidder] += highestBid;
        }

        highestBidder = msg.sender;
        highestBid = msg.value;

        emit BidPlaced(msg.sender, msg.value);
    }

    /// @notice Safe withdrawal function called individually by outbid participants
    function withdrawRefund() external nonReentrant returns (bool) {
        uint256 amount = pendingReturns[msg.sender];
        if (amount == 0) revert NoPendingRefund();

        pendingReturns[msg.sender] = 0;

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        if (!success) {
            // Revert on failure to protect accounting
            pendingReturns[msg.sender] = amount;
            revert TransferFailed();
        }

        emit RefundClaimed(msg.sender, amount);
        return true;
    }
}
