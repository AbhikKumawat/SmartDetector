// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAggregatorV3 {
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
}

/**
 * @title PatchedLending
 * @notice Remediated lending protocol using validated decentralized oracle feeds.
 * @dev Replaces vulnerable single-pool spot pricing with Chainlink AggregatorV3
 * data feed protected against zero values, stale updates, and round inconsistency.
 */
contract PatchedLending {
    IAggregatorV3 public immutable priceFeed;
    uint256 public constant MAX_ORACLE_DELAY = 1 hours;

    mapping(address => uint256) public tokenCollateral;
    mapping(address => uint256) public borrowedETH;

    event CollateralDeposited(address indexed user, uint256 amount);
    event Borrowed(address indexed user, uint256 ethAmount);

    error InvalidOraclePrice();
    error StaleOracleData();
    error IncompleteOracleRound();
    error ExceedsCollateralRatio();
    error TransferFailed();

    constructor(address _priceFeed) payable {
        priceFeed = IAggregatorV3(_priceFeed);
    }

    /// @notice REMEDIATION: Decentralized oracle price with validation checks
    function getValidatedPrice() public view returns (uint256) {
        (
            uint80 roundId,
            int256 answer,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();

        if (answer <= 0) revert InvalidOraclePrice();
        if (block.timestamp - updatedAt > MAX_ORACLE_DELAY) revert StaleOracleData();
        if (answeredInRound < roundId) revert IncompleteOracleRound();

        return uint256(answer);
    }

    function depositCollateral(uint256 amount) external {
        tokenCollateral[msg.sender] += amount;
        emit CollateralDeposited(msg.sender, amount);
    }

    function borrow(uint256 ethToBorrow) external {
        uint256 price = getValidatedPrice();
        uint256 collateralValueETH = (tokenCollateral[msg.sender] * price) / 1e18;

        uint256 maxBorrow = (collateralValueETH * 80) / 100;
        if (borrowedETH[msg.sender] + ethToBorrow > maxBorrow) {
            revert ExceedsCollateralRatio();
        }

        borrowedETH[msg.sender] += ethToBorrow;
        require(address(this).balance >= ethToBorrow, "Insufficient protocol liquidity");

        (bool sent, ) = msg.sender.call{value: ethToBorrow}("");
        if (!sent) revert TransferFailed();

        emit Borrowed(msg.sender, ethToBorrow);
    }

    receive() external payable {}
}
