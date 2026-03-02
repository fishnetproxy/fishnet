// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {FishnetWallet} from "../src/FishnetWallet.sol";

// =============================================================================
// Attack Surface Tests
// Covers: signature malleability, self-call, gas griefing, expiry boundary
// =============================================================================

contract AttackSurfaceTest is Test {
    FishnetWallet public wallet;
    SimpleTarget public target;

    uint256 internal signerPrivateKey;
    address internal signer;

    bytes32 constant PERMIT_TYPEHASH = keccak256(
        "FishnetPermit(address wallet,uint64 chainId,uint256 nonce,"
        "uint48 expiry,address target,uint256 value,"
        "bytes32 calldataHash,bytes32 policyHash)"
    );

    // secp256k1 curve order
    uint256 constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function setUp() public {
        signerPrivateKey = 0xA11CE;
        signer = vm.addr(signerPrivateKey);
        wallet = new FishnetWallet(signer);
        target = new SimpleTarget();
        vm.deal(address(wallet), 10 ether);
    }

    function _signDigest(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = _rawSign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _rawSign(uint256 pk, bytes32 digest) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        (v, r, s) = vm.sign(pk, digest);
    }

    function _computeDigest(
        FishnetWallet.FishnetPermit memory permit
    ) internal view returns (bytes32) {
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
        return keccak256(
            abi.encodePacked("\x19\x01", wallet.DOMAIN_SEPARATOR(), structHash)
        );
    }

    // =========================================================================
    // 1. SIGNATURE MALLEABILITY
    // =========================================================================

    /// @notice Proves the contract accepts malleable signatures.
    ///         For any valid (r, s, v), (r, n-s, flipped_v) also passes ecrecover.
    function test_malleableSignatureAccepted() public {
        bytes memory data = abi.encodeWithSelector(SimpleTarget.store.selector, 42);

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

        bytes32 digest = _computeDigest(permit);
        (uint8 v, bytes32 r, bytes32 s) = _rawSign(signerPrivateKey, digest);

        // Compute the malleable counterpart
        bytes32 sMalleable = bytes32(SECP256K1_N - uint256(s));
        uint8 vMalleable = (v == 27) ? 28 : 27;

        // Verify ecrecover produces the same address for both
        address recoveredOriginal = ecrecover(digest, v, r, s);
        address recoveredMalleable = ecrecover(digest, vMalleable, r, sMalleable);
        assertEq(recoveredOriginal, signer, "Original sig should recover to signer");
        assertEq(recoveredMalleable, signer, "Malleable sig should also recover to signer");

        // Execute with the MALLEABLE signature — proves the contract accepts it
        bytes memory malleableSig = abi.encodePacked(r, sMalleable, vMalleable);
        wallet.execute(address(target), 0, data, permit, malleableSig);

        assertEq(target.lastValue(), 42, "Execution with malleable sig should succeed");
        assertTrue(wallet.usedNonces(1));
    }

    /// @notice Proves nonce protection prevents replay with malleable signature.
    function test_malleableSignatureBlockedByNonce() public {
        bytes memory data = abi.encodeWithSelector(SimpleTarget.store.selector, 42);

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

        bytes32 digest = _computeDigest(permit);
        (uint8 v, bytes32 r, bytes32 s) = _rawSign(signerPrivateKey, digest);

        // Execute with original signature
        bytes memory originalSig = abi.encodePacked(r, s, v);
        wallet.execute(address(target), 0, data, permit, originalSig);
        assertTrue(wallet.usedNonces(1));

        // Attempt replay with malleable signature — blocked by nonce
        bytes32 sMalleable = bytes32(SECP256K1_N - uint256(s));
        uint8 vMalleable = (v == 27) ? 28 : 27;
        bytes memory malleableSig = abi.encodePacked(r, sMalleable, vMalleable);

        vm.expectRevert(FishnetWallet.NonceUsed.selector);
        wallet.execute(address(target), 0, data, permit, malleableSig);
    }

    // =========================================================================
    // 2. SELF-CALL (target = wallet)
    // =========================================================================

    /// @notice Calling admin functions via execute(target=wallet) should fail
    ///         because msg.sender inside the self-call is address(wallet), not owner.
    function test_selfCall_withdrawBlockedByOnlyOwner() public {
        bytes memory data = abi.encodeWithSelector(
            FishnetWallet.withdraw.selector, address(0xdead)
        );

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 1,
            expiry: uint48(block.timestamp + 300),
            target: address(wallet), // self-call
            value: 0,
            calldataHash: keccak256(data),
            policyHash: keccak256("policy-v1")
        });

        bytes memory sig = _signDigest(signerPrivateKey, _computeDigest(permit));

        // The inner call reverts (NotOwner), so outer execute reverts with ExecutionFailed
        vm.expectRevert(FishnetWallet.ExecutionFailed.selector);
        wallet.execute(address(wallet), 0, data, permit, sig);
    }

    /// @notice Self-call to setSigner should also be blocked.
    function test_selfCall_setSignerBlockedByOnlyOwner() public {
        bytes memory data = abi.encodeWithSelector(
            FishnetWallet.setSigner.selector, address(0xbad)
        );

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 1,
            expiry: uint48(block.timestamp + 300),
            target: address(wallet),
            value: 0,
            calldataHash: keccak256(data),
            policyHash: keccak256("policy-v1")
        });

        bytes memory sig = _signDigest(signerPrivateKey, _computeDigest(permit));

        vm.expectRevert(FishnetWallet.ExecutionFailed.selector);
        wallet.execute(address(wallet), 0, data, permit, sig);

        // Signer should be unchanged
        assertEq(wallet.fishnetSigner(), signer);
    }

    /// @notice Self-call to pause should also be blocked.
    function test_selfCall_pauseBlockedByOnlyOwner() public {
        bytes memory data = abi.encodeWithSelector(FishnetWallet.pause.selector);

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 1,
            expiry: uint48(block.timestamp + 300),
            target: address(wallet),
            value: 0,
            calldataHash: keccak256(data),
            policyHash: keccak256("policy-v1")
        });

        bytes memory sig = _signDigest(signerPrivateKey, _computeDigest(permit));

        vm.expectRevert(FishnetWallet.ExecutionFailed.selector);
        wallet.execute(address(wallet), 0, data, permit, sig);

        // Wallet should still be unpaused
        assertFalse(wallet.paused());
    }

    /// @notice Self-call to a nonexistent function hits no fallback — reverts.
    function test_selfCall_arbitraryDataReverts() public {
        // Wallet has receive() but no fallback(), so non-empty data to an unknown
        // selector will revert.
        bytes memory data = hex"deadbeef";

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 1,
            expiry: uint48(block.timestamp + 300),
            target: address(wallet),
            value: 0,
            calldataHash: keccak256(data),
            policyHash: keccak256("policy-v1")
        });

        bytes memory sig = _signDigest(signerPrivateKey, _computeDigest(permit));

        vm.expectRevert(FishnetWallet.ExecutionFailed.selector);
        wallet.execute(address(wallet), 0, data, permit, sig);
    }

    /// @notice Self-call with ETH value and empty data hits receive() — succeeds
    ///         (wallet sends ETH to itself, balance unchanged).
    function test_selfCall_ethToSelfViaReceive() public {
        bytes memory data = "";

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 1,
            expiry: uint48(block.timestamp + 300),
            target: address(wallet),
            value: 1 ether, // send to self
            calldataHash: keccak256(data),
            policyHash: keccak256("policy-v1")
        });

        bytes memory sig = _signDigest(signerPrivateKey, _computeDigest(permit));

        uint256 balBefore = address(wallet).balance;
        wallet.execute(address(wallet), 1 ether, data, permit, sig);

        // Balance unchanged — wallet sent ETH to itself
        assertEq(address(wallet).balance, balBefore);
        assertTrue(wallet.usedNonces(1));
    }

    // =========================================================================
    // 3. TYPE RANGE BOUNDARY — uint48 expiry
    // =========================================================================

    /// @notice Permit with expiry = type(uint48).max should work.
    function test_expiryAtUint48Max() public {
        uint48 maxExpiry = type(uint48).max; // 281474976710655
        // Warp to a time before max expiry
        vm.warp(281474976710000);

        bytes memory data = abi.encodeWithSelector(SimpleTarget.store.selector, 1);

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 1,
            expiry: maxExpiry,
            target: address(target),
            value: 0,
            calldataHash: keccak256(data),
            policyHash: keccak256("policy-v1")
        });

        bytes memory sig = _signDigest(signerPrivateKey, _computeDigest(permit));
        wallet.execute(address(target), 0, data, permit, sig);
        assertEq(target.lastValue(), 1);
    }

    // =========================================================================
    // 4. GAS GRIEFING
    // =========================================================================

    /// @notice Target that consumes all gas causes ExecutionFailed.
    ///         Nonce is NOT consumed (entire tx reverts).
    function test_gasGuzzlerTargetReverts() public {
        GasGuzzler guzzler = new GasGuzzler();
        bytes memory data = abi.encodeWithSelector(GasGuzzler.guzzle.selector);

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 1,
            expiry: uint48(block.timestamp + 300),
            target: address(guzzler),
            value: 0,
            calldataHash: keccak256(data),
            policyHash: keccak256("policy-v1")
        });

        bytes memory sig = _signDigest(signerPrivateKey, _computeDigest(permit));

        // The call either reverts with ExecutionFailed or runs out of gas entirely.
        // Either way the transaction does not succeed.
        vm.expectRevert();
        wallet.execute{gas: 500_000}(address(guzzler), 0, data, permit, sig);

        // Since the entire tx reverted, nonce should NOT be consumed
        assertFalse(wallet.usedNonces(1), "Nonce must not be consumed on revert");
    }

    /// @notice Target that returns a huge returndata blob — tests memory expansion cost.
    function test_returnBombTarget() public {
        ReturnBomb bomb = new ReturnBomb();
        bytes memory data = abi.encodeWithSelector(ReturnBomb.explode.selector);

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 1,
            expiry: uint48(block.timestamp + 300),
            target: address(bomb),
            value: 0,
            calldataHash: keccak256(data),
            policyHash: keccak256("policy-v1")
        });

        bytes memory sig = _signDigest(signerPrivateKey, _computeDigest(permit));

        // The wallet uses (bool success, ) = target.call{...}(data) which means
        // Solidity uses retSize=0 in the CALL opcode. The returndata is available
        // via RETURNDATASIZE but never copied. So the return bomb should not
        // cause excessive memory expansion in the caller.
        // This should succeed if the compiler doesn't copy returndata.
        wallet.execute(address(bomb), 0, data, permit, sig);
        assertTrue(wallet.usedNonces(1), "Should succeed - returndata not copied");
    }

    /// @notice When execute() reverts, nonce is NOT consumed (state rollback).
    function test_failedExecutionDoesNotConsumeNonce() public {
        // Use a target that will revert
        RevertTarget reverter = new RevertTarget();
        bytes memory data = abi.encodeWithSelector(RevertTarget.fail.selector);

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 1,
            expiry: uint48(block.timestamp + 300),
            target: address(reverter),
            value: 0,
            calldataHash: keccak256(data),
            policyHash: keccak256("policy-v1")
        });

        bytes memory sig = _signDigest(signerPrivateKey, _computeDigest(permit));

        vm.expectRevert(FishnetWallet.ExecutionFailed.selector);
        wallet.execute(address(reverter), 0, data, permit, sig);

        // Nonce must NOT be marked used — the tx reverted
        assertFalse(wallet.usedNonces(1), "Nonce must not be consumed when execute reverts");

        // The same nonce can be reused with a working target
        bytes memory goodData = abi.encodeWithSelector(SimpleTarget.store.selector, 77);
        FishnetWallet.FishnetPermit memory permit2 = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 1, // same nonce
            expiry: uint48(block.timestamp + 300),
            target: address(target),
            value: 0,
            calldataHash: keccak256(goodData),
            policyHash: keccak256("policy-v1")
        });

        bytes memory sig2 = _signDigest(signerPrivateKey, _computeDigest(permit2));
        wallet.execute(address(target), 0, goodData, permit2, sig2);
        assertEq(target.lastValue(), 77);
        assertTrue(wallet.usedNonces(1));
    }

    /// @notice Execute with value > wallet balance should revert.
    function test_insufficientBalanceReverts() public {
        bytes memory data = abi.encodeWithSelector(SimpleTarget.store.selector, 1);
        uint256 excessiveValue = address(wallet).balance + 1 ether;

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 1,
            expiry: uint48(block.timestamp + 300),
            target: address(target),
            value: excessiveValue,
            calldataHash: keccak256(data),
            policyHash: keccak256("policy-v1")
        });

        bytes memory sig = _signDigest(signerPrivateKey, _computeDigest(permit));

        vm.expectRevert(FishnetWallet.ExecutionFailed.selector);
        wallet.execute(address(target), excessiveValue, data, permit, sig);
    }
}

// =============================================================================
// Helper contracts
// =============================================================================

contract SimpleTarget {
    uint256 public lastValue;

    function store(uint256 x) external payable {
        lastValue = x;
    }

    receive() external payable {}
}

contract GasGuzzler {
    function guzzle() external pure {
        // Infinite loop — consumes all forwarded gas
        while (true) {}
    }
}

contract ReturnBomb {
    function explode() external pure returns (bytes memory) {
        // Return a large payload. The wallet's (bool success, ) = call(...)
        // should NOT copy this into memory.
        bytes memory payload = new bytes(50_000);
        return payload;
    }
}

contract RevertTarget {
    function fail() external pure {
        revert("intentional revert");
    }
}
