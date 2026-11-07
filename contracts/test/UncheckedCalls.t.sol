// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/unchecked_calls/VulnerableAuction.sol";
import "../src/unchecked_calls/PatchedAuction.sol";

contract SilentRevertingBidder {
    function placeBid(address auction) external payable {
        VulnerableAuction(auction).bid{value: msg.value}();
    }

    // Reverts whenever ETH is sent, causing unchecked call to silently fail
    receive() external payable {
        revert("I refuse ETH");
    }
}

contract UncheckedCallsTest is Test {
    VulnerableAuction public vulnerableAuction;
    PatchedAuction public patchedAuction;
    SilentRevertingBidder public silentBidder;

    address public honestBidder = address(0x2222);
    address public secondBidder = address(0x3333);

    function setUp() public {
        vulnerableAuction = new VulnerableAuction();
        patchedAuction = new PatchedAuction();
        silentBidder = new SilentRevertingBidder();

        vm.deal(honestBidder, 10 ether);
        vm.deal(secondBidder, 20 ether);
        vm.deal(address(silentBidder), 10 ether);
    }

    function testExploitUncheckedCallSilentFailure() public {
        // Silent bidder bids 2 ETH
        silentBidder.placeBid{value: 2 ether}(address(vulnerableAuction));
        assertEq(vulnerableAuction.highestBidder(), address(silentBidder));
        assertEq(vulnerableAuction.highestBid(), 2 ether);

        // Honest bidder outbids with 5 ETH
        // The contract tries to send 2 ETH back to silentBidder.
        // silentBidder reverts! But because success boolean is unchecked,
        // the transaction succeeds anyway and previous bid is trapped inside contract!
        vm.prank(honestBidder);
        vulnerableAuction.bid{value: 5 ether}();

        assertEq(vulnerableAuction.highestBidder(), honestBidder);
        assertEq(vulnerableAuction.highestBid(), 5 ether);
        // Both 2 ETH and 5 ETH are trapped
        assertEq(address(vulnerableAuction).balance, 7 ether, "Vulnerable contract locked untracked ETH");
    }

    function testPatchedAuctionPullPattern() public {
        // Honest bidder bids 2 ETH on patched auction
        vm.prank(honestBidder);
        patchedAuction.bid{value: 2 ether}();

        // Second bidder outbids with 4 ETH
        vm.prank(secondBidder);
        patchedAuction.bid{value: 4 ether}();

        assertEq(patchedAuction.highestBidder(), secondBidder);
        assertEq(patchedAuction.highestBid(), 4 ether);

        // Honest bidder can safely withdraw their refund independently
        uint256 honestBalBefore = honestBidder.balance;
        vm.prank(honestBidder);
        patchedAuction.withdrawRefund();
        assertEq(honestBidder.balance, honestBalBefore + 2 ether, "Honest bidder pulled full refund");
    }
}
