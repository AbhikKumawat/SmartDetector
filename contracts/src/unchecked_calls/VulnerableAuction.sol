// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableAuction
 * @notice Demonstrates Unchecked Low-Level External Calls (SWC-104).
 * @dev In bid(), the contract attempts to refund the previous highest bidder using
 * an external call whose return value is completely ignored.
 */
contract VulnerableAuction {
    address public highestBidder;
    uint256 public highestBid;

    event BidPlaced(address indexed bidder, uint256 amount);

    function bid() external payable {
        require(msg.value > highestBid, "Bid too low");

        address previousBidder = highestBidder;
        uint256 previousBid = highestBid;

        highestBidder = msg.sender;
        highestBid = msg.value;

        // VULNERABILITY: Return value of call is ignored!
        // If previousBidder is a malicious contract reverting on receive,
        // or if gas is exhausted, the call fails silently.
        if (previousBidder != address(0)) {
            (bool success, ) = payable(previousBidder).call{value: previousBid}("");
            // Return value `success` is not checked with require() or revert!
        }

        emit BidPlaced(msg.sender, msg.value);
    }
}
