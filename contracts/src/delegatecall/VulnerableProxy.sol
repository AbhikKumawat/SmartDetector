// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableProxy
 * @notice Demonstrates Dangerous Delegatecall & Storage Collision (SWC-112).
 * @dev delegatecall executes in the context of the calling contract. An attacker
 * can pass an arbitrary logic contract that overwrites slot 0 (owner) or drains funds.
 */
contract VulnerableProxy {
    // Slot 0: owner
    address public owner;
    // Slot 1: implementation
    address public implementation;

    event Executed(address indexed target, bool success);

    constructor(address _implementation) {
        owner = msg.sender;
        implementation = _implementation;
    }

    /// @notice VULNERABILITY: Arbitrary target and payload passed to delegatecall!
    function forwardCall(address target, bytes calldata data) external returns (bytes memory) {
        // Arbitrary delegatecall allows target to modify any storage slot in VulnerableProxy
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "Delegatecall failed");
        emit Executed(target, success);
        return result;
    }

    receive() external payable {}
}
