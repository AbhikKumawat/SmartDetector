// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/oracle_manipulation/VulnerableLending.sol";
import "../src/oracle_manipulation/PatchedLending.sol";

contract MockDexPair is ISimpleDexPair {
    uint256 public reserveToken;
    uint256 public reserveETH;

    constructor(uint256 _token, uint256 _eth) {
        reserveToken = _token;
        reserveETH = _eth;
    }

    function setReserves(uint256 _token, uint256 _eth) external {
        reserveToken = _token;
        reserveETH = _eth;
    }

    function getReserves() external view returns (uint256, uint256) {
        return (reserveToken, reserveETH);
    }
}

contract MockChainlinkFeed is IAggregatorV3 {
    int256 public price;
    uint256 public updatedAt;
    uint80 public roundId;

    constructor(int256 _price) {
        price = _price;
        updatedAt = block.timestamp;
        roundId = 1;
    }

    function setRound(int256 _price, uint256 _updatedAt, uint80 _roundId) external {
        price = _price;
        updatedAt = _updatedAt;
        roundId = _roundId;
    }

    function latestRoundData()
        external
        view
        returns (
            uint80,
            int256,
            uint256,
            uint256,
            uint80
        )
    {
        return (roundId, price, block.timestamp, updatedAt, roundId);
    }
}

contract OracleManipulationTest is Test {
    VulnerableLending public vulnerableLending;
    PatchedLending public patchedLending;
    MockDexPair public dexPair;
    MockChainlinkFeed public chainlinkFeed;

    address public attacker = address(0x9999);

    function setUp() public {
        vm.warp(100000); // Advance block timestamp past genesis to permit time deltas
        // Initial reserves: 1000 tokens = 100 ETH (1 token = 0.1 ETH)
        dexPair = new MockDexPair(1000 ether, 100 ether);
        // Chainlink fair price: 0.1 ETH (1e17)
        chainlinkFeed = new MockChainlinkFeed(0.1 ether);

        // Deploy lending contracts funded with 50 ETH each
        vulnerableLending = new VulnerableLending{value: 50 ether}(address(dexPair));
        patchedLending = new PatchedLending{value: 50 ether}(address(chainlinkFeed));

        vm.deal(attacker, 10 ether);
    }

    function testExploitSpotPriceManipulation() public {
        vm.startPrank(attacker);

        // Attacker deposits only 10 tokens as collateral
        vulnerableLending.depositCollateral(10 ether);

        // Normally 10 tokens * 0.1 ETH = 1 ETH collateral. Max borrow = 0.8 ETH.
        // Attacker simulates flash loan dumping 900 ETH into pool, spiking spot reserves:
        // Now pool has 100 tokens and 1000 ETH -> 1 token = 10 ETH!
        dexPair.setReserves(100 ether, 1000 ether);

        emit log_named_uint("Manipulated Spot Price", vulnerableLending.getSpotPrice());

        // Now 10 tokens collateral = 100 ETH value! Max borrow = 80 ETH.
        // Attacker borrows all 50 ETH available in protocol!
        vulnerableLending.borrow(50 ether);

        assertEq(address(vulnerableLending).balance, 0, "Lending protocol drained via oracle pump");
        assertEq(attacker.balance, 60 ether, "Attacker extracted 50 ETH");
        vm.stopPrank();
    }

    function testPatchedLendingRejectsManipulatedOrStaleFeed() public {
        vm.startPrank(attacker);
        patchedLending.depositCollateral(10 ether);

        // Even if dexPair is skewed, patched lending queries validated Chainlink feed:
        dexPair.setReserves(100 ether, 1000 ether);

        // Attempting to borrow 50 ETH reverts with ExceedsCollateralRatio
        vm.expectRevert(PatchedLending.ExceedsCollateralRatio.selector);
        patchedLending.borrow(50 ether);

        // Test stale oracle rejection
        chainlinkFeed.setRound(0.1 ether, block.timestamp - 2 hours, 1);
        vm.expectRevert(PatchedLending.StaleOracleData.selector);
        patchedLending.borrow(0.5 ether);

        vm.stopPrank();
    }
}
