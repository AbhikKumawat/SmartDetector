// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableVaultKill
 * @notice Demonstrates Unprotected Self-Destruct (SWC-106).
 * @dev The kill function destroys the contract and forwards all remaining funds
 * to the arbitrary caller without access controls.
 */
contract VulnerableVaultKill {
    address public owner;

    event Deposited(address indexed sender, uint256 amount);

    constructor() payable {
        owner = msg.sender;
    }

    function deposit() external payable {
        require(msg.value > 0, "No ETH");
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice VULNERABILITY: Public unauthenticated selfdestruct!
    /// Any external account can destroy the contract and siphon the entire balance.
    function kill() external {
        // selfdestruct is unprotected!
        selfdestruct(payable(msg.sender));
    }
}
