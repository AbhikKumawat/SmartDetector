// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title PatchedVaultKill
 * @notice Remediated vault eliminating selfdestruct in favor of Pausable emergency exit.
 * @dev Replaces dangerous selfdestruct opcode (deprecated in EIP-6780) with governed
 * emergency pause and authenticated asset migration.
 */
contract PatchedVaultKill is Ownable, Pausable {
    event EmergencyFundsEvacuated(address indexed admin, uint256 amount);
    event Deposited(address indexed sender, uint256 amount);

    error VaultPaused();
    error TransferFailed();

    constructor() Ownable(msg.sender) payable {}

    function deposit() external payable whenNotPaused {
        require(msg.value > 0, "No ETH");
        emit Deposited(msg.sender, msg.value);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    /// @notice REMEDIATION: Controlled emergency evacuation without selfdestruct.
    function emergencyWithdraw(address payable target) external onlyOwner whenPaused {
        require(target != address(0), "Invalid address");
        uint256 balance = address(this).balance;

        (bool success, ) = target.call{value: balance}("");
        if (!success) revert TransferFailed();

        emit EmergencyFundsEvacuated(msg.sender, balance);
    }
}
