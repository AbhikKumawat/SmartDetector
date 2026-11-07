// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISimpleDexPair {
    function getReserves() external view returns (uint256 reserveToken, uint256 reserveETH);
}

/**
 * @title VulnerableLending
 * @notice Demonstrates Oracle Manipulation & Flash Loan Attack Surface (SWC-115 / Defi Vuln).
 * @dev The protocol calculates collateral value directly from spot reserves of an AMM pair.
 * An attacker can take a flash loan to manipulate spot reserves within the same block,
 * borrow all available ETH, and drain the lending protocol.
 */
contract VulnerableLending {
    ISimpleDexPair public immutable dexPair;
    mapping(address => uint256) public tokenCollateral;
    mapping(address => uint256) public borrowedETH;

    event CollateralDeposited(address indexed user, uint256 amount);
    event Borrowed(address indexed user, uint256 ethAmount);

    constructor(address _dexPair) payable {
        dexPair = ISimpleDexPair(_dexPair);
    }

    /// @notice VULNERABILITY: Spot price calculation directly from reserves
    /// Susceptible to single-block flash loan manipulation!
    function getSpotPrice() public view returns (uint256) {
        (uint256 reserveToken, uint256 reserveETH) = dexPair.getReserves();
        require(reserveToken > 0, "Zero reserve");
        // Spot price: ETH per Token scaled by 1e18
        return (reserveETH * 1e18) / reserveToken;
    }

    function depositCollateral(uint256 amount) external {
        tokenCollateral[msg.sender] += amount;
        emit CollateralDeposited(msg.sender, amount);
    }

    function borrow(uint256 ethToBorrow) external {
        uint256 price = getSpotPrice();
        uint256 collateralValueETH = (tokenCollateral[msg.sender] * price) / 1e18;
        
        // 80% LTV
        uint256 maxBorrow = (collateralValueETH * 80) / 100;
        require(borrowedETH[msg.sender] + ethToBorrow <= maxBorrow, "Borrow exceeds collateral value");

        borrowedETH[msg.sender] += ethToBorrow;
        require(address(this).balance >= ethToBorrow, "Insufficient protocol liquidity");

        (bool sent, ) = msg.sender.call{value: ethToBorrow}("");
        require(sent, "ETH transfer failed");

        emit Borrowed(msg.sender, ethToBorrow);
    }

    receive() external payable {}
}
