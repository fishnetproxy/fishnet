// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {FishnetWallet} from "../src/FishnetWallet.sol";

contract MockDEXRouter {
    mapping(address => uint256) public tokenBalances;
    uint256 public swapCount;

    function swap(address, uint256 minAmountOut) external payable {
        require(msg.value > 0, "no ETH sent");
        uint256 tokensOut = msg.value * 2000;
        require(tokensOut >= minAmountOut, "slippage exceeded");
        tokenBalances[msg.sender] += tokensOut;
        swapCount++;
    }
}

contract FishnetWalletE2ETest is Test {
    FishnetWallet public wallet;
    MockDEXRouter public dex;
    address internal tokenAddr;

    address internal walletOwner;
    uint256 internal fishnetSignerKey;
    address internal fishnetSignerAddr;
    address internal agent;
    address internal attacker;

    bytes32 internal domainSeparator;

    bytes32 constant PERMIT_TYPEHASH = keccak256(
        "FishnetPermit(address wallet,uint64 chainId,uint256 nonce,"
        "uint48 expiry,address target,uint256 value,"
        "bytes32 calldataHash,bytes32 policyHash)"
    );

    function setUp() public {
        walletOwner = makeAddr("walletOwner");
        fishnetSignerKey = 0xF15E;
        fishnetSignerAddr = vm.addr(fishnetSignerKey);
        agent = makeAddr("agent");
        attacker = makeAddr("attacker");
        tokenAddr = makeAddr("token");

        vm.prank(walletOwner);
        wallet = new FishnetWallet(fishnetSignerAddr);

        dex = new MockDEXRouter();

        vm.deal(address(wallet), 100 ether);

        domainSeparator = wallet.DOMAIN_SEPARATOR();
    }

    function _fishnetBuildPermit(
        address target,
        uint256 value,
        bytes memory data,
        uint256 nonce,
        uint48 expiry,
        bytes32 policyHash
    ) internal view returns (FishnetWallet.FishnetPermit memory) {
        return FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: nonce,
            expiry: expiry,
            target: target,
            value: value,
            calldataHash: keccak256(data),
            policyHash: policyHash
        });
    }

    function _fishnetSignPermit(
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
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fishnetSignerKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_e2e_agentSwapsViaPermit() public {
        bytes memory swapCalldata = abi.encodeWithSelector(
            MockDEXRouter.swap.selector, tokenAddr, 100
        );
        uint256 swapValue = 0.1 ether;

        bytes32 policyHash = keccak256("onchain-policy-v1");
        uint48 expiry = uint48(block.timestamp + 300);

        FishnetWallet.FishnetPermit memory permit = _fishnetBuildPermit(
            address(dex), swapValue, swapCalldata, 1, expiry, policyHash
        );
        bytes memory signature = _fishnetSignPermit(permit);

        uint256 walletBalBefore = address(wallet).balance;
        uint256 dexBalBefore = address(dex).balance;

        vm.prank(agent);
        wallet.execute(address(dex), swapValue, swapCalldata, permit, signature);

        assertEq(address(wallet).balance, walletBalBefore - swapValue);
        assertEq(address(dex).balance, dexBalBefore + swapValue);
        assertEq(dex.tokenBalances(address(wallet)), 0.1 ether * 2000);
        assertEq(dex.swapCount(), 1);
        assertTrue(wallet.usedNonces(1));
    }

    function test_e2e_multipleSequentialSwaps() public {
        bytes32 policyHash = keccak256("onchain-policy-v1");

        for (uint256 i = 1; i <= 5; i++) {
            bytes memory swapCalldata = abi.encodeWithSelector(
                MockDEXRouter.swap.selector, tokenAddr, 0
            );
            uint48 expiry = uint48(block.timestamp + 300);

            FishnetWallet.FishnetPermit memory permit = _fishnetBuildPermit(
                address(dex), 0.05 ether, swapCalldata, i, expiry, policyHash
            );
            bytes memory signature = _fishnetSignPermit(permit);

            vm.prank(agent);
            wallet.execute(address(dex), 0.05 ether, swapCalldata, permit, signature);
        }

        assertEq(dex.swapCount(), 5);
        assertEq(dex.tokenBalances(address(wallet)), 0.25 ether * 2000);
        assertEq(address(wallet).balance, 100 ether - 0.25 ether);

        for (uint256 i = 1; i <= 5; i++) {
            assertTrue(wallet.usedNonces(i));
        }
    }

    function test_e2e_agentCannotForgePermit() public {
        bytes memory swapCalldata = abi.encodeWithSelector(
            MockDEXRouter.swap.selector, tokenAddr, 0
        );
        bytes32 policyHash = keccak256("onchain-policy-v1");
        uint48 expiry = uint48(block.timestamp + 300);

        FishnetWallet.FishnetPermit memory permit = _fishnetBuildPermit(
            address(dex), 1 ether, swapCalldata, 1, expiry, policyHash
        );

        // Agent signs with their own key instead of fishnetSigner
        uint256 agentFakeKey = 0xBADA6E;
        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_TYPEHASH,
                permit.wallet, permit.chainId, permit.nonce,
                permit.expiry, permit.target, permit.value,
                permit.calldataHash, permit.policyHash
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentFakeKey, digest);
        bytes memory forgery = abi.encodePacked(r, s, v);

        vm.prank(agent);
        vm.expectRevert(FishnetWallet.InvalidSignature.selector);
        wallet.execute(address(dex), 1 ether, swapCalldata, permit, forgery);

        assertEq(address(wallet).balance, 100 ether);
    }

    function test_e2e_cannotSwapTargetOnSignedPermit() public {
        bytes memory swapCalldata = abi.encodeWithSelector(
            MockDEXRouter.swap.selector, tokenAddr, 0
        );
        bytes32 policyHash = keccak256("onchain-policy-v1");
        uint48 expiry = uint48(block.timestamp + 300);

        FishnetWallet.FishnetPermit memory permit = _fishnetBuildPermit(
            address(dex), 1 ether, swapCalldata, 1, expiry, policyHash
        );
        bytes memory signature = _fishnetSignPermit(permit);

        address maliciousContract = makeAddr("malicious");

        vm.prank(attacker);
        vm.expectRevert(FishnetWallet.TargetMismatch.selector);
        wallet.execute(maliciousContract, 1 ether, swapCalldata, permit, signature);
    }

    function test_e2e_cannotAlterCalldataOnSignedPermit() public {
        bytes memory approvedCalldata = abi.encodeWithSelector(
            MockDEXRouter.swap.selector, tokenAddr, 100
        );
        bytes32 policyHash = keccak256("onchain-policy-v1");
        uint48 expiry = uint48(block.timestamp + 300);

        FishnetWallet.FishnetPermit memory permit = _fishnetBuildPermit(
            address(dex), 0.1 ether, approvedCalldata, 1, expiry, policyHash
        );
        bytes memory signature = _fishnetSignPermit(permit);

        // Attacker changes minAmountOut from 100 to 0 to bypass slippage
        bytes memory maliciousCalldata = abi.encodeWithSelector(
            MockDEXRouter.swap.selector, tokenAddr, 0
        );

        vm.prank(attacker);
        vm.expectRevert(FishnetWallet.CalldataMismatch.selector);
        wallet.execute(address(dex), 0.1 ether, maliciousCalldata, permit, signature);
    }

    function test_e2e_cannotInflateValueOnSignedPermit() public {
        bytes memory swapCalldata = abi.encodeWithSelector(
            MockDEXRouter.swap.selector, tokenAddr, 0
        );
        bytes32 policyHash = keccak256("onchain-policy-v1");
        uint48 expiry = uint48(block.timestamp + 300);

        // Permit signed for 0.01 ETH, attacker submits with 100 ETH
        FishnetWallet.FishnetPermit memory permit = _fishnetBuildPermit(
            address(dex), 0.01 ether, swapCalldata, 1, expiry, policyHash
        );
        bytes memory signature = _fishnetSignPermit(permit);

        vm.prank(attacker);
        vm.expectRevert(FishnetWallet.ValueMismatch.selector);
        wallet.execute(address(dex), 100 ether, swapCalldata, permit, signature);

        assertEq(address(wallet).balance, 100 ether);
    }

    function test_e2e_permitExpiresAfterWindow() public {
        bytes memory swapCalldata = abi.encodeWithSelector(
            MockDEXRouter.swap.selector, tokenAddr, 0
        );
        bytes32 policyHash = keccak256("onchain-policy-v1");
        uint48 expiry = uint48(block.timestamp + 300);

        FishnetWallet.FishnetPermit memory permit = _fishnetBuildPermit(
            address(dex), 0.1 ether, swapCalldata, 1, expiry, policyHash
        );
        bytes memory signature = _fishnetSignPermit(permit);

        vm.warp(block.timestamp + 360);

        vm.prank(agent);
        vm.expectRevert(FishnetWallet.PermitExpired.selector);
        wallet.execute(address(dex), 0.1 ether, swapCalldata, permit, signature);
    }

    function test_e2e_nonceReplayRejectedEvenWithDifferentCalldata() public {
        bytes memory calldata1 = abi.encodeWithSelector(
            MockDEXRouter.swap.selector, tokenAddr, 0
        );
        bytes32 policyHash = keccak256("onchain-policy-v1");
        uint48 expiry = uint48(block.timestamp + 300);

        FishnetWallet.FishnetPermit memory permit1 = _fishnetBuildPermit(
            address(dex), 0.1 ether, calldata1, 1, expiry, policyHash
        );
        bytes memory sig1 = _fishnetSignPermit(permit1);

        vm.prank(agent);
        wallet.execute(address(dex), 0.1 ether, calldata1, permit1, sig1);

        bytes memory calldata2 = abi.encodeWithSelector(
            MockDEXRouter.swap.selector, tokenAddr, 999
        );
        FishnetWallet.FishnetPermit memory permit2 = _fishnetBuildPermit(
            address(dex), 0.1 ether, calldata2, 1, expiry, policyHash
        );
        bytes memory sig2 = _fishnetSignPermit(permit2);

        vm.prank(agent);
        vm.expectRevert(FishnetWallet.NonceUsed.selector);
        wallet.execute(address(dex), 0.1 ether, calldata2, permit2, sig2);
    }

    function test_e2e_ownerPauseStopsAgent() public {
        bytes memory swapCalldata = abi.encodeWithSelector(
            MockDEXRouter.swap.selector, tokenAddr, 0
        );
        bytes32 policyHash = keccak256("onchain-policy-v1");
        uint48 expiry = uint48(block.timestamp + 300);

        FishnetWallet.FishnetPermit memory permit = _fishnetBuildPermit(
            address(dex), 0.1 ether, swapCalldata, 1, expiry, policyHash
        );
        bytes memory signature = _fishnetSignPermit(permit);

        vm.prank(walletOwner);
        wallet.pause();

        vm.prank(agent);
        vm.expectRevert(FishnetWallet.WalletPaused.selector);
        wallet.execute(address(dex), 0.1 ether, swapCalldata, permit, signature);

        uint256 newSignerKey = 0xAE5106E;
        address newSignerAddr = vm.addr(newSignerKey);

        vm.startPrank(walletOwner);
        wallet.setSigner(newSignerAddr);
        wallet.unpause();
        vm.stopPrank();

        // Old permit signed by rotated-out signer must fail
        vm.prank(agent);
        vm.expectRevert(FishnetWallet.InvalidSignature.selector);
        wallet.execute(address(dex), 0.1 ether, swapCalldata, permit, signature);

        fishnetSignerKey = newSignerKey;
        FishnetWallet.FishnetPermit memory newPermit = _fishnetBuildPermit(
            address(dex), 0.1 ether, swapCalldata, 1, expiry, policyHash
        );
        bytes memory newSig = _fishnetSignPermit(newPermit);

        vm.prank(agent);
        wallet.execute(address(dex), 0.1 ether, swapCalldata, newPermit, newSig);

        assertEq(dex.swapCount(), 1);
    }

    function test_e2e_ownerEmergencyWithdraw() public {
        address safeAddress = makeAddr("safeAddress");
        uint256 walletBal = address(wallet).balance;

        vm.prank(walletOwner);
        wallet.withdraw(safeAddress);

        assertEq(address(wallet).balance, 0);
        assertEq(safeAddress.balance, walletBal);

        bytes memory swapCalldata = abi.encodeWithSelector(
            MockDEXRouter.swap.selector, tokenAddr, 0
        );
        bytes32 policyHash = keccak256("onchain-policy-v1");
        uint48 expiry = uint48(block.timestamp + 300);

        FishnetWallet.FishnetPermit memory permit = _fishnetBuildPermit(
            address(dex), 0.1 ether, swapCalldata, 1, expiry, policyHash
        );
        bytes memory signature = _fishnetSignPermit(permit);

        vm.prank(agent);
        vm.expectRevert(FishnetWallet.ExecutionFailed.selector);
        wallet.execute(address(dex), 0.1 ether, swapCalldata, permit, signature);
    }

    function test_e2e_actionExecutedEmitsPolicyHash() public {
        bytes memory swapCalldata = abi.encodeWithSelector(
            MockDEXRouter.swap.selector, tokenAddr, 0
        );
        uint48 expiry = uint48(block.timestamp + 300);

        bytes32 policyV1 = keccak256("onchain-policy-v1");
        FishnetWallet.FishnetPermit memory permit = _fishnetBuildPermit(
            address(dex), 0.1 ether, swapCalldata, 1, expiry, policyV1
        );
        bytes memory signature = _fishnetSignPermit(permit);

        vm.expectEmit(true, false, false, true);
        emit FishnetWallet.ActionExecuted(address(dex), 0.1 ether, 1, policyV1);

        vm.prank(agent);
        wallet.execute(address(dex), 0.1 ether, swapCalldata, permit, signature);
    }

    function test_e2e_anyoneCanSubmitPermitTx() public {
        bytes memory swapCalldata = abi.encodeWithSelector(
            MockDEXRouter.swap.selector, tokenAddr, 0
        );
        bytes32 policyHash = keccak256("onchain-policy-v1");
        uint48 expiry = uint48(block.timestamp + 300);

        FishnetWallet.FishnetPermit memory permit = _fishnetBuildPermit(
            address(dex), 0.1 ether, swapCalldata, 1, expiry, policyHash
        );
        bytes memory signature = _fishnetSignPermit(permit);

        address relayer = makeAddr("relayer");
        vm.prank(relayer);
        wallet.execute(address(dex), 0.1 ether, swapCalldata, permit, signature);

        assertEq(dex.swapCount(), 1);
    }
}
