// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title PatchedProxy
 * @notice Remediated proxy design restricting delegatecall strictly to authorized implementation.
 * @dev Protects execution context, disallows arbitrary target invocation, and enforces access control.
 */
contract PatchedProxy is Ownable {
    // Dedicated slot or authorized address
    address public trustedImplementation;

    event ImplementationUpdated(address indexed oldImpl, address indexed newImpl);
    event Forwarded(bool success);

    error UnauthorizedTarget();
    error ExecutionFailed();

    constructor(address _initialImpl) Ownable(msg.sender) {
        trustedImplementation = _initialImpl;
    }

    function setImplementation(address _newImpl) external onlyOwner {
        require(_newImpl != address(0), "Invalid address");
        emit ImplementationUpdated(trustedImplementation, _newImpl);
        trustedImplementation = _newImpl;
    }

    /// @notice REMEDIATION: Delegatecall is restricted ONLY to the verified trusted implementation.
    function execute(bytes calldata data) external onlyOwner returns (bytes memory) {
        address impl = trustedImplementation;
        if (impl == address(0)) revert UnauthorizedTarget();

        (bool success, bytes memory result) = impl.delegatecall(data);
        if (!success) revert ExecutionFailed();

        emit Forwarded(success);
        return result;
    }

    receive() external payable {}
}
