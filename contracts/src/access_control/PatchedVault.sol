// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable2Step.sol";

/**
 * @title PatchedVault
 * @notice Remediated version of VulnerableVault with strict role-based access control.
 * @dev Inherits OpenZeppelin Ownable2Step to enforce 2-phase ownership transfer
 * and restrict all sensitive operations to authenticated owners.
 */
contract PatchedVault is Ownable2Step {
    uint256 public totalDeposits;

    event VaultWithdrawn(address indexed owner, address indexed recipient, uint256 amount);

    error ZeroAddress();
    error ZeroDeposit();
    error WithdrawalFailed();

    constructor() Ownable(msg.sender) {}

    function deposit() external payable {
        if (msg.value == 0) revert ZeroDeposit();
        totalDeposits += msg.value;
    }

    /// @notice REMEDIATION: Protected with onlyOwner modifier and transfers funds securely.
    function withdrawAll(address payable recipient) external onlyOwner {
        if (recipient == address(0)) revert ZeroAddress();
        uint256 balance = address(this).balance;
        
        (bool sent, ) = recipient.call{value: balance}("");
        if (!sent) revert WithdrawalFailed();

        emit VaultWithdrawn(msg.sender, recipient, balance);
    }
}
