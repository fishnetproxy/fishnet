// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {FishnetWallet} from "../src/FishnetWallet.sol";

contract MockTarget {
    uint256 public lastValue;
    bool public shouldFail;

    function doSomething(uint256 x) external payable {
        require(!shouldFail, "mock revert");
        lastValue = x;
    }

    function setShouldFail(bool _fail) external {
        shouldFail = _fail;
    }
}

contract FishnetWalletTest is Test {
    FishnetWallet public wallet;
    MockTarget public target;

    uint256 internal signerPrivateKey;
    address internal signer;
    address internal walletOwner;

    bytes32 internal domainSeparator;

    bytes32 constant PERMIT_TYPEHASH = keccak256(
        "FishnetPermit(address wallet,uint64 chainId,uint256 nonce,"
        "uint48 expiry,address target,uint256 value,"
        "bytes32 calldataHash,bytes32 policyHash)"
    );

    function setUp() public {
        signerPrivateKey = 0xA11CE;
        signer = vm.addr(signerPrivateKey);
        walletOwner = address(this);

        wallet = new FishnetWallet(signer);
        target = new MockTarget();

        vm.deal(address(wallet), 10 ether);

        domainSeparator = wallet.DOMAIN_SEPARATOR();
    }

    function _buildPermit(
        address _target,
        uint256 _value,
        bytes memory _data,
        uint256 _nonce,
        uint48 _expiry,
        bytes32 _policyHash
    ) internal view returns (FishnetWallet.FishnetPermit memory) {
        return FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: _nonce,
            expiry: _expiry,
            target: _target,
            value: _value,
            calldataHash: keccak256(_data),
            policyHash: _policyHash
        });
    }

    function _signPermit(
        FishnetWallet.FishnetPermit memory permit,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_TYPEHASH,
                permit.wallet,
                permit.chainId,
                permit.nonce,
                permit.expiry,
                permit.target,
                permit.value,
                permit.calldataHash,
                permit.policyHash
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_constructor_setsOwner() public view {
        assertEq(wallet.owner(), walletOwner);
    }

    function test_constructor_setsSigner() public view {
        assertEq(wallet.fishnetSigner(), signer);
    }

    function test_constructor_notPaused() public view {
        assertFalse(wallet.paused());
    }

    function test_constructor_domainSeparator() public view {
        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Fishnet"),
                keccak256("1"),
                block.chainid,
                address(wallet)
            )
        );
        assertEq(domainSeparator, expected);
    }

    function test_constructor_reverts_zeroSigner() public {
        vm.expectRevert(FishnetWallet.ZeroAddress.selector);
        new FishnetWallet(address(0));
    }

    function test_execute_success() public {
        bytes memory data = abi.encodeWithSelector(MockTarget.doSomething.selector, 42);
        uint48 expiry = uint48(block.timestamp + 300);
        bytes32 policyHash = keccak256("policy-v1");

        FishnetWallet.FishnetPermit memory permit = _buildPermit(
            address(target), 0, data, 1, expiry, policyHash
        );
        bytes memory sig = _signPermit(permit, signerPrivateKey);

        wallet.execute(address(target), 0, data, permit, sig);

        assertEq(target.lastValue(), 42);
        assertTrue(wallet.usedNonces(1));
    }

    function test_execute_withValue() public {
        bytes memory data = abi.encodeWithSelector(MockTarget.doSomething.selector, 99);
        uint48 expiry = uint48(block.timestamp + 300);
        bytes32 policyHash = keccak256("policy-v1");

        FishnetWallet.FishnetPermit memory permit = _buildPermit(
            address(target), 1 ether, data, 1, expiry, policyHash
        );
        bytes memory sig = _signPermit(permit, signerPrivateKey);

        uint256 targetBalBefore = address(target).balance;
        wallet.execute(address(target), 1 ether, data, permit, sig);

        assertEq(address(target).balance, targetBalBefore + 1 ether);
    }

    function test_execute_emitsActionExecuted() public {
        bytes memory data = abi.encodeWithSelector(MockTarget.doSomething.selector, 1);
        uint48 expiry = uint48(block.timestamp + 300);
        bytes32 policyHash = keccak256("policy-v1");

        FishnetWallet.FishnetPermit memory permit = _buildPermit(
            address(target), 0, data, 7, expiry, policyHash
        );
        bytes memory sig = _signPermit(permit, signerPrivateKey);

        vm.expectEmit(true, false, false, true);
        emit FishnetWallet.ActionExecuted(address(target), 0, 7, policyHash);

        wallet.execute(address(target), 0, data, permit, sig);
    }

    function test_execute_reverts_permitExpired() public {
        bytes memory data = abi.encodeWithSelector(MockTarget.doSomething.selector, 1);
        uint48 expiry = uint48(block.timestamp - 1);
        bytes32 policyHash = keccak256("policy-v1");

        FishnetWallet.FishnetPermit memory permit = _buildPermit(
            address(target), 0, data, 1, expiry, policyHash
        );
        bytes memory sig = _signPermit(permit, signerPrivateKey);

        vm.expectRevert(FishnetWallet.PermitExpired.selector);
        wallet.execute(address(target), 0, data, permit, sig);
    }

    function test_execute_reverts_wrongChain() public {
        bytes memory data = abi.encodeWithSelector(MockTarget.doSomething.selector, 1);
        uint48 expiry = uint48(block.timestamp + 300);
        bytes32 policyHash = keccak256("policy-v1");

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: 999,
            nonce: 1,
            expiry: expiry,
            target: address(target),
            value: 0,
            calldataHash: keccak256(data),
            policyHash: policyHash
        });
        bytes memory sig = _signPermit(permit, signerPrivateKey);

        vm.expectRevert(FishnetWallet.WrongChain.selector);
        wallet.execute(address(target), 0, data, permit, sig);
    }

    function test_execute_reverts_nonceAlreadyUsed() public {
        bytes memory data = abi.encodeWithSelector(MockTarget.doSomething.selector, 1);
        uint48 expiry = uint48(block.timestamp + 300);
        bytes32 policyHash = keccak256("policy-v1");

        FishnetWallet.FishnetPermit memory permit = _buildPermit(
            address(target), 0, data, 1, expiry, policyHash
        );
        bytes memory sig = _signPermit(permit, signerPrivateKey);

        wallet.execute(address(target), 0, data, permit, sig);

        vm.expectRevert(FishnetWallet.NonceUsed.selector);
        wallet.execute(address(target), 0, data, permit, sig);
    }

    function test_execute_reverts_targetMismatch() public {
        bytes memory data = abi.encodeWithSelector(MockTarget.doSomething.selector, 1);
        uint48 expiry = uint48(block.timestamp + 300);
        bytes32 policyHash = keccak256("policy-v1");

        FishnetWallet.FishnetPermit memory permit = _buildPermit(
            address(target), 0, data, 1, expiry, policyHash
        );
        bytes memory sig = _signPermit(permit, signerPrivateKey);

        vm.expectRevert(FishnetWallet.TargetMismatch.selector);
        wallet.execute(address(0xdead), 0, data, permit, sig);
    }

    function test_execute_reverts_valueMismatch() public {
        bytes memory data = abi.encodeWithSelector(MockTarget.doSomething.selector, 1);
        uint48 expiry = uint48(block.timestamp + 300);
        bytes32 policyHash = keccak256("policy-v1");

        FishnetWallet.FishnetPermit memory permit = _buildPermit(
            address(target), 0.1 ether, data, 1, expiry, policyHash
        );
        bytes memory sig = _signPermit(permit, signerPrivateKey);

        vm.expectRevert(FishnetWallet.ValueMismatch.selector);
        wallet.execute(address(target), 10 ether, data, permit, sig);
    }

    function test_execute_reverts_calldataMismatch() public {
        bytes memory data = abi.encodeWithSelector(MockTarget.doSomething.selector, 1);
        bytes memory wrongData = abi.encodeWithSelector(MockTarget.doSomething.selector, 999);
        uint48 expiry = uint48(block.timestamp + 300);
        bytes32 policyHash = keccak256("policy-v1");

        FishnetWallet.FishnetPermit memory permit = _buildPermit(
            address(target), 0, data, 1, expiry, policyHash
        );
        bytes memory sig = _signPermit(permit, signerPrivateKey);

        vm.expectRevert(FishnetWallet.CalldataMismatch.selector);
        wallet.execute(address(target), 0, wrongData, permit, sig);
    }

    function test_execute_reverts_walletMismatch() public {
        bytes memory data = abi.encodeWithSelector(MockTarget.doSomething.selector, 1);
        uint48 expiry = uint48(block.timestamp + 300);
        bytes32 policyHash = keccak256("policy-v1");

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(0xbeef),
            chainId: uint64(block.chainid),
            nonce: 1,
            expiry: expiry,
            target: address(target),
            value: 0,
            calldataHash: keccak256(data),
            policyHash: policyHash
        });
        bytes memory sig = _signPermit(permit, signerPrivateKey);

        vm.expectRevert(FishnetWallet.WalletMismatch.selector);
        wallet.execute(address(target), 0, data, permit, sig);
    }

    function test_execute_reverts_invalidSignature() public {
        bytes memory data = abi.encodeWithSelector(MockTarget.doSomething.selector, 1);
        uint48 expiry = uint48(block.timestamp + 300);
        bytes32 policyHash = keccak256("policy-v1");

        FishnetWallet.FishnetPermit memory permit = _buildPermit(
            address(target), 0, data, 1, expiry, policyHash
        );

        uint256 wrongKey = 0xB0B;
        bytes memory sig = _signPermit(permit, wrongKey);

        vm.expectRevert(FishnetWallet.InvalidSignature.selector);
        wallet.execute(address(target), 0, data, permit, sig);
    }

    function test_execute_reverts_whenPaused() public {
        wallet.pause();

        bytes memory data = abi.encodeWithSelector(MockTarget.doSomething.selector, 1);
        uint48 expiry = uint48(block.timestamp + 300);
        bytes32 policyHash = keccak256("policy-v1");

        FishnetWallet.FishnetPermit memory permit = _buildPermit(
            address(target), 0, data, 1, expiry, policyHash
        );
        bytes memory sig = _signPermit(permit, signerPrivateKey);

        vm.expectRevert(FishnetWallet.WalletPaused.selector);
        wallet.execute(address(target), 0, data, permit, sig);
    }

    function test_execute_reverts_invalidSignatureLength() public {
        bytes memory data = abi.encodeWithSelector(MockTarget.doSomething.selector, 1);
        uint48 expiry = uint48(block.timestamp + 300);
        bytes32 policyHash = keccak256("policy-v1");

        FishnetWallet.FishnetPermit memory permit = _buildPermit(
            address(target), 0, data, 1, expiry, policyHash
        );

        bytes memory shortSig = hex"AABBCC";

        vm.expectRevert(FishnetWallet.InvalidSignatureLength.selector);
        wallet.execute(address(target), 0, data, permit, shortSig);
    }

    function test_execute_reverts_executionFailed() public {
        target.setShouldFail(true);

        bytes memory data = abi.encodeWithSelector(MockTarget.doSomething.selector, 1);
        uint48 expiry = uint48(block.timestamp + 300);
        bytes32 policyHash = keccak256("policy-v1");

        FishnetWallet.FishnetPermit memory permit = _buildPermit(
            address(target), 0, data, 1, expiry, policyHash
        );
        bytes memory sig = _signPermit(permit, signerPrivateKey);

        vm.expectRevert(FishnetWallet.ExecutionFailed.selector);
        wallet.execute(address(target), 0, data, permit, sig);
    }

    function test_differentNonces_bothSucceed() public {
        bytes memory data = abi.encodeWithSelector(MockTarget.doSomething.selector, 1);
        uint48 expiry = uint48(block.timestamp + 300);
        bytes32 policyHash = keccak256("policy-v1");

        FishnetWallet.FishnetPermit memory permit1 = _buildPermit(
            address(target), 0, data, 1, expiry, policyHash
        );
        bytes memory sig1 = _signPermit(permit1, signerPrivateKey);
        wallet.execute(address(target), 0, data, permit1, sig1);

        FishnetWallet.FishnetPermit memory permit2 = _buildPermit(
            address(target), 0, data, 2, expiry, policyHash
        );
        bytes memory sig2 = _signPermit(permit2, signerPrivateKey);
        wallet.execute(address(target), 0, data, permit2, sig2);

        assertTrue(wallet.usedNonces(1));
        assertTrue(wallet.usedNonces(2));
    }

    function test_setSigner() public {
        address newSigner = address(0x1234);

        vm.expectEmit(true, true, false, false);
        emit FishnetWallet.SignerUpdated(signer, newSigner);

        wallet.setSigner(newSigner);
        assertEq(wallet.fishnetSigner(), newSigner);
    }

    function test_setSigner_reverts_notOwner() public {
        vm.prank(address(0xdead));
        vm.expectRevert(FishnetWallet.NotOwner.selector);
        wallet.setSigner(address(0x1234));
    }

    function test_setSigner_reverts_zeroAddress() public {
        vm.expectRevert(FishnetWallet.ZeroAddress.selector);
        wallet.setSigner(address(0));
    }

    function test_withdraw() public {
        address recipient = address(0x7777);
        uint256 walletBalance = address(wallet).balance;

        vm.expectEmit(true, false, false, true);
        emit FishnetWallet.Withdrawn(recipient, walletBalance);

        wallet.withdraw(recipient);

        assertEq(address(wallet).balance, 0);
        assertEq(recipient.balance, walletBalance);
    }

    function test_withdraw_reverts_notOwner() public {
        vm.prank(address(0xdead));
        vm.expectRevert(FishnetWallet.NotOwner.selector);
        wallet.withdraw(address(0x7777));
    }

    function test_pause() public {
        vm.expectEmit(false, false, false, true);
        emit FishnetWallet.Paused(walletOwner);

        wallet.pause();
        assertTrue(wallet.paused());
    }

    function test_pause_reverts_notOwner() public {
        vm.prank(address(0xdead));
        vm.expectRevert(FishnetWallet.NotOwner.selector);
        wallet.pause();
    }

    function test_unpause() public {
        wallet.pause();
        assertTrue(wallet.paused());

        vm.expectEmit(false, false, false, true);
        emit FishnetWallet.Unpaused(walletOwner);

        wallet.unpause();
        assertFalse(wallet.paused());
    }

    function test_unpause_reverts_notOwner() public {
        wallet.pause();
        vm.prank(address(0xdead));
        vm.expectRevert(FishnetWallet.NotOwner.selector);
        wallet.unpause();
    }

    function test_receiveETH() public {
        uint256 balBefore = address(wallet).balance;
        vm.deal(address(this), 5 ether);
        (bool success, ) = address(wallet).call{value: 1 ether}("");
        assertTrue(success);
        assertEq(address(wallet).balance, balBefore + 1 ether);
    }

    function test_domainSeparator_recomputesOnFork() public {
        bytes32 originalDS = wallet.DOMAIN_SEPARATOR();

        vm.chainId(999);

        bytes32 forkedDS = wallet.DOMAIN_SEPARATOR();
        assertTrue(originalDS != forkedDS);

        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Fishnet"),
                keccak256("1"),
                uint256(999),
                address(wallet)
            )
        );
        assertEq(forkedDS, expected);
    }

    function test_execute_afterSignerRotation() public {
        uint256 newSignerKey = 0xC0FFEE;
        address newSigner = vm.addr(newSignerKey);

        wallet.setSigner(newSigner);

        bytes memory data = abi.encodeWithSelector(MockTarget.doSomething.selector, 77);
        uint48 expiry = uint48(block.timestamp + 300);
        bytes32 policyHash = keccak256("policy-v2");

        FishnetWallet.FishnetPermit memory permit = _buildPermit(
            address(target), 0, data, 1, expiry, policyHash
        );

        bytes memory oldSig = _signPermit(permit, signerPrivateKey);
        vm.expectRevert(FishnetWallet.InvalidSignature.selector);
        wallet.execute(address(target), 0, data, permit, oldSig);

        bytes memory newSig = _signPermit(permit, newSignerKey);
        wallet.execute(address(target), 0, data, permit, newSig);

        assertEq(target.lastValue(), 77);
    }

    function test_execute_afterUnpause() public {
        wallet.pause();

        bytes memory data = abi.encodeWithSelector(MockTarget.doSomething.selector, 55);
        uint48 expiry = uint48(block.timestamp + 300);
        bytes32 policyHash = keccak256("policy-v1");

        FishnetWallet.FishnetPermit memory permit = _buildPermit(
            address(target), 0, data, 1, expiry, policyHash
        );
        bytes memory sig = _signPermit(permit, signerPrivateKey);

        vm.expectRevert(FishnetWallet.WalletPaused.selector);
        wallet.execute(address(target), 0, data, permit, sig);

        wallet.unpause();

        wallet.execute(address(target), 0, data, permit, sig);
        assertEq(target.lastValue(), 55);
    }
}
