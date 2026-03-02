// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {FishnetWallet} from "../src/FishnetWallet.sol";

contract FuzzTarget {
    uint256 public lastValue;
    bytes public lastData;

    fallback() external payable {
        lastData = msg.data;
    }

    receive() external payable {}

    function doWork(uint256 x) external payable {
        lastValue = x;
    }
}

contract FishnetWalletFuzzTest is Test {
    FishnetWallet public wallet;
    FuzzTarget public target;

    uint256 internal signerPrivateKey;
    address internal signer;

    bytes32 constant PERMIT_TYPEHASH = keccak256(
        "FishnetPermit(address wallet,uint64 chainId,uint256 nonce,"
        "uint48 expiry,address target,uint256 value,"
        "bytes32 calldataHash,bytes32 policyHash)"
    );

    function setUp() public {
        signerPrivateKey = 0xA11CE;
        signer = vm.addr(signerPrivateKey);
        wallet = new FishnetWallet(signer);
        target = new FuzzTarget();
        vm.deal(address(wallet), 100 ether);
    }

    function _signPermit(
        FishnetWallet.FishnetPermit memory permit
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
            abi.encodePacked("\x19\x01", wallet.DOMAIN_SEPARATOR(), structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    // =========================================================================
    // Fuzz: any nonce should work (as long as it hasn't been used)
    // =========================================================================

    function testFuzz_executeWithAnyNonce(uint256 nonce) public {
        bytes memory data = abi.encodeWithSelector(FuzzTarget.doWork.selector, nonce);

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: nonce,
            expiry: uint48(block.timestamp + 300),
            target: address(target),
            value: 0,
            calldataHash: keccak256(data),
            policyHash: keccak256("policy-v1")
        });

        bytes memory sig = _signPermit(permit);
        wallet.execute(address(target), 0, data, permit, sig);

        assertTrue(wallet.usedNonces(nonce));
        assertEq(target.lastValue(), nonce);
    }

    // =========================================================================
    // Fuzz: any value within wallet balance should work
    // =========================================================================

    function testFuzz_executeWithAnyValue(uint96 value) public {
        // Cap to wallet balance
        uint256 val = uint256(value) % (address(wallet).balance + 1);

        bytes memory data = abi.encodeWithSelector(FuzzTarget.doWork.selector, val);

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 1,
            expiry: uint48(block.timestamp + 300),
            target: address(target),
            value: val,
            calldataHash: keccak256(data),
            policyHash: keccak256("policy-v1")
        });

        bytes memory sig = _signPermit(permit);

        uint256 targetBalBefore = address(target).balance;
        wallet.execute(address(target), val, data, permit, sig);

        assertEq(address(target).balance, targetBalBefore + val);
    }

    // =========================================================================
    // Fuzz: any calldata should work if properly signed
    // =========================================================================

    function testFuzz_executeWithAnyCalldata(bytes calldata data) public {
        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 1,
            expiry: uint48(block.timestamp + 300),
            target: address(target),
            value: 0,
            calldataHash: keccak256(data),
            policyHash: keccak256("policy-v1")
        });

        bytes memory sig = _signPermit(permit);

        // FuzzTarget has a fallback that accepts any calldata
        wallet.execute(address(target), 0, data, permit, sig);
        assertTrue(wallet.usedNonces(1));
    }

    // =========================================================================
    // Fuzz: wrong private key should ALWAYS be rejected
    // =========================================================================

    function testFuzz_wrongSignerRejected(uint256 wrongKey) public {
        // Avoid key = 0 (invalid) and key = signerPrivateKey (would pass)
        vm.assume(wrongKey != 0);
        vm.assume(wrongKey < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141);
        vm.assume(wrongKey != signerPrivateKey);

        bytes memory data = abi.encodeWithSelector(FuzzTarget.doWork.selector, 42);

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 1,
            expiry: uint48(block.timestamp + 300),
            target: address(target),
            value: 0,
            calldataHash: keccak256(data),
            policyHash: keccak256("policy-v1")
        });

        // Sign with the wrong key
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
            abi.encodePacked("\x19\x01", wallet.DOMAIN_SEPARATOR(), structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(FishnetWallet.InvalidSignature.selector);
        wallet.execute(address(target), 0, data, permit, sig);
    }

    // =========================================================================
    // Fuzz: expired permits should ALWAYS be rejected
    // =========================================================================

    function testFuzz_expiredPermitRejected(uint48 expiry) public {
        // Ensure the permit is expired: expiry < block.timestamp
        vm.assume(expiry < block.timestamp);

        bytes memory data = abi.encodeWithSelector(FuzzTarget.doWork.selector, 1);

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 1,
            expiry: expiry,
            target: address(target),
            value: 0,
            calldataHash: keccak256(data),
            policyHash: keccak256("policy-v1")
        });

        bytes memory sig = _signPermit(permit);

        vm.expectRevert(FishnetWallet.PermitExpired.selector);
        wallet.execute(address(target), 0, data, permit, sig);
    }

    // =========================================================================
    // Fuzz: wrong signature length should ALWAYS be rejected
    // =========================================================================

    function testFuzz_wrongSignatureLengthRejected(bytes calldata sig) public {
        vm.assume(sig.length != 65);

        bytes memory data = abi.encodeWithSelector(FuzzTarget.doWork.selector, 1);

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 1,
            expiry: uint48(block.timestamp + 300),
            target: address(target),
            value: 0,
            calldataHash: keccak256(data),
            policyHash: keccak256("policy-v1")
        });

        vm.expectRevert(FishnetWallet.InvalidSignatureLength.selector);
        wallet.execute(address(target), 0, data, permit, sig);
    }

    // =========================================================================
    // Fuzz: any policy hash should work
    // =========================================================================

    function testFuzz_anyPolicyHash(bytes32 policyHash) public {
        bytes memory data = abi.encodeWithSelector(FuzzTarget.doWork.selector, 1);

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 1,
            expiry: uint48(block.timestamp + 300),
            target: address(target),
            value: 0,
            calldataHash: keccak256(data),
            policyHash: policyHash
        });

        bytes memory sig = _signPermit(permit);
        wallet.execute(address(target), 0, data, permit, sig);
        assertTrue(wallet.usedNonces(1));
    }

    // =========================================================================
    // Fuzz: nonce replay should ALWAYS fail
    // =========================================================================

    function testFuzz_nonceReplayAlwaysFails(uint256 nonce) public {
        bytes memory data = abi.encodeWithSelector(FuzzTarget.doWork.selector, 1);

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: nonce,
            expiry: uint48(block.timestamp + 300),
            target: address(target),
            value: 0,
            calldataHash: keccak256(data),
            policyHash: keccak256("policy-v1")
        });

        bytes memory sig = _signPermit(permit);

        // First execution succeeds
        wallet.execute(address(target), 0, data, permit, sig);

        // Second execution with same nonce always fails
        vm.expectRevert(FishnetWallet.NonceUsed.selector);
        wallet.execute(address(target), 0, data, permit, sig);
    }
}
