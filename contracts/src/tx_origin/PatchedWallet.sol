// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PatchedWallet
 * @notice Remediated wallet using direct msg.sender authentication.
 * @dev Replaces tx.origin with msg.sender to ensure only the direct authenticated caller
 * can trigger transfers, defeating phishing and malicious intermediary contracts.
 */
contract PatchedWallet {
    address public immutable owner;

    event Transferred(address indexed to, uint256 amount);

    error UnauthorizedCaller();
    error InsufficientBalance();
    error TransferFailed();

    constructor() payable {
        owner = msg.sender;
    }

    /// @notice REMEDIATION: Authenticates immediate msg.sender
    function transfer(address payable to, uint256 amount) external {
        if (msg.sender != owner) revert UnauthorizedCaller();
        if (address(this).balance < amount) revert InsufficientBalance();

        (bool sent, ) = to.call{value: amount}("");
        if (!sent) revert TransferFailed();

        emit Transferred(to, amount);
    }

    receive() external payable {}
}
