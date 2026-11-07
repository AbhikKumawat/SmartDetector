// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/access_control/VulnerableVault.sol";
import "../src/access_control/PatchedVault.sol";

contract AccessControlTest is Test {
    VulnerableVault public vulnerableVault;
    PatchedVault public patchedVault;

    address public owner = address(0xAAAA);
    address public victim = address(0xBBBB);
    address public attacker = address(0xDEAD);

    function setUp() public {
        vm.prank(owner);
        vulnerableVault = new VulnerableVault();

        vm.prank(owner);
        patchedVault = new PatchedVault();

        // Victim deposits 25 ETH into VulnerableVault
        vm.deal(victim, 50 ether);
        vm.prank(victim);
        vulnerableVault.deposit{value: 25 ether}();

        // Victim deposits 25 ETH into PatchedVault
        vm.prank(victim);
        patchedVault.deposit{value: 25 ether}();
    }

    function testExploitMissingAccessControl() public {
        emit log_named_address("Original Owner", vulnerableVault.owner());
        emit log_named_uint("Vault Balance Before Exploit", address(vulnerableVault).balance);

        vm.startPrank(attacker);

        // Attacker hijacks ownership due to unprotected setOwner()
        vulnerableVault.setOwner(attacker);
        assertEq(vulnerableVault.owner(), attacker, "Attacker should now be owner");

        // Attacker drains all vault funds
        vulnerableVault.withdrawAll(payable(attacker));
        assertEq(address(vulnerableVault).balance, 0, "Vault should be drained");
        assertEq(attacker.balance, 25 ether, "Attacker should hold 25 ETH");

        emit log_named_address("Compromised Owner", vulnerableVault.owner());
        emit log_named_uint("Vault Balance After Exploit", address(vulnerableVault).balance);
        vm.stopPrank();
    }

    function testPatchedVaultPreventsUnauthorized() public {
        vm.startPrank(attacker);

        // Attacker cannot withdraw directly (reverts with OwnableUnauthorizedAccount)
        vm.expectRevert();
        patchedVault.withdrawAll(payable(attacker));

        // Attacker cannot seize ownership (transferOwnership is protected by onlyOwner)
        vm.expectRevert();
        patchedVault.transferOwnership(attacker);

        assertEq(address(patchedVault).balance, 25 ether, "Patched vault balance must remain intact");
        assertEq(patchedVault.owner(), owner, "Owner must remain original owner");
        vm.stopPrank();
    }
}
