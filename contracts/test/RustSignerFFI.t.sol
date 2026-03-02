// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {FishnetWallet} from "../src/FishnetWallet.sol";

/// @title Rust Signer FFI Test
/// @notice Calls the actual Rust StubSigner binary via Foundry FFI and verifies
///         the produced signature is accepted by the on-chain FishnetWallet contract.
///         This is the true cross-stack integration test — no Solidity signing involved.
contract RustSignerFFITest is Test {
    FishnetWallet public wallet;
    MockFFITarget public target;

    // Anvil account #1 private key (used by the Rust signer)
    string constant SIGNER_PRIVATE_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    address constant EXPECTED_SIGNER = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;

    function setUp() public {
        wallet = new FishnetWallet(EXPECTED_SIGNER);
        target = new MockFFITarget();
        vm.deal(address(wallet), 10 ether);
    }

    /// @notice Call the Rust signer binary and return (signerAddress, signature)
    function _rustSign(
        address _wallet,
        uint64 _chainId,
        uint64 _nonce,
        uint64 _expiry,
        address _target,
        uint256 _value,
        bytes32 _calldataHash,
        bytes32 _policyHash,
        address _verifyingContract
    ) internal returns (address signerAddr, bytes memory signature) {
        string[] memory cmd = new string[](11);
        cmd[0] = "../target/debug/fishnet-sign";
        cmd[1] = SIGNER_PRIVATE_KEY;
        cmd[2] = vm.toString(_wallet);
        cmd[3] = vm.toString(_chainId);
        cmd[4] = vm.toString(_nonce);
        cmd[5] = vm.toString(_expiry);
        cmd[6] = vm.toString(_target);
        cmd[7] = vm.toString(_value);
        cmd[8] = vm.toString(_calldataHash);
        cmd[9] = vm.toString(_policyHash);
        cmd[10] = vm.toString(_verifyingContract);

        bytes memory result = vm.ffi(cmd);

        // The binary outputs two lines: address\nsignature
        // vm.ffi returns raw bytes of stdout. Parse the hex values.
        // Output format: "0x<addr>\n0x<sig>\n"
        (signerAddr, signature) = _parseFFIOutput(result);
    }

    /// @notice Parse "0x<40 hex chars>\n0x<130 hex chars>\n" from FFI output
    function _parseFFIOutput(bytes memory raw) internal pure returns (address addr, bytes memory sig) {
        // Find the newline separator
        uint256 newlinePos = 0;
        for (uint256 i = 0; i < raw.length; i++) {
            if (raw[i] == 0x0a) { // \n
                newlinePos = i;
                break;
            }
        }
        require(newlinePos > 0, "no newline in FFI output");

        // First line: address (skip "0x" prefix = 2 bytes, then 40 hex chars = 20 bytes)
        bytes memory addrHex = new bytes(newlinePos);
        for (uint256 i = 0; i < newlinePos; i++) {
            addrHex[i] = raw[i];
        }
        addr = _parseAddress(addrHex);

        // Second line: signature (skip newline, "0x" prefix, then 130 hex chars = 65 bytes)
        uint256 sigStart = newlinePos + 1;
        uint256 sigEnd = raw.length;
        // Trim trailing newline if present
        if (sigEnd > 0 && raw[sigEnd - 1] == 0x0a) {
            sigEnd--;
        }
        bytes memory sigHex = new bytes(sigEnd - sigStart);
        for (uint256 i = 0; i < sigHex.length; i++) {
            sigHex[i] = raw[sigStart + i];
        }
        sig = _hexToBytes(sigHex);
    }

    function _parseAddress(bytes memory addrStr) internal pure returns (address) {
        bytes memory addrBytes = _hexToBytes(addrStr);
        require(addrBytes.length == 20, "address must be 20 bytes");
        address result;
        assembly {
            result := mload(add(addrBytes, 20))
        }
        return result;
    }

    function _hexToBytes(bytes memory hexStr) internal pure returns (bytes memory) {
        // Skip "0x" prefix if present
        uint256 start = 0;
        if (hexStr.length >= 2 && hexStr[0] == 0x30 && hexStr[1] == 0x78) {
            start = 2;
        }
        uint256 hexLen = hexStr.length - start;
        require(hexLen % 2 == 0, "odd hex length");
        bytes memory result = new bytes(hexLen / 2);
        for (uint256 i = 0; i < hexLen / 2; i++) {
            result[i] = bytes1(
                _hexCharToByte(hexStr[start + i * 2]) * 16 +
                _hexCharToByte(hexStr[start + i * 2 + 1])
            );
        }
        return result;
    }

    function _hexCharToByte(bytes1 c) internal pure returns (uint8) {
        if (c >= 0x30 && c <= 0x39) return uint8(c) - 0x30;       // 0-9
        if (c >= 0x61 && c <= 0x66) return uint8(c) - 0x61 + 10;  // a-f
        if (c >= 0x41 && c <= 0x46) return uint8(c) - 0x41 + 10;  // A-F
        revert("invalid hex char");
    }

    // =========================================================================
    // Test: Full end-to-end with actual Rust signer
    // =========================================================================

    function test_rustSignerFFI_executesOnChain() public {
        bytes memory callData = abi.encodeWithSelector(MockFFITarget.recordCall.selector, 42);
        uint48 expiry = uint48(block.timestamp + 600);
        bytes32 calldataHash = keccak256(callData);
        bytes32 policyHash = keccak256("policy-v1");

        (address signerAddr, bytes memory signature) = _rustSign(
            address(wallet),
            uint64(block.chainid),
            1, // nonce
            uint64(expiry),
            address(target),
            0, // value
            calldataHash,
            policyHash,
            address(wallet)
        );

        // Verify the Rust signer returned the expected address
        assertEq(signerAddr, EXPECTED_SIGNER, "Rust signer address mismatch");
        assertEq(signature.length, 65, "Signature must be 65 bytes");

        // Build the permit
        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 1,
            expiry: expiry,
            target: address(target),
            value: 0,
            calldataHash: calldataHash,
            policyHash: policyHash
        });

        // Execute with the Rust-produced signature — this is the real test
        wallet.execute(address(target), 0, callData, permit, signature);

        // Verify state changes
        assertTrue(wallet.usedNonces(1), "Nonce should be marked used");
        assertEq(target.lastValue(), 42, "Target should have received the call");
        assertEq(target.callCount(), 1, "Target should have been called exactly once");
    }

    function test_rustSignerFFI_withETHValue() public {
        bytes memory callData = abi.encodeWithSelector(MockFFITarget.recordCall.selector, 99);
        uint48 expiry = uint48(block.timestamp + 600);
        bytes32 calldataHash = keccak256(callData);
        bytes32 policyHash = keccak256("policy-v2");

        (, bytes memory signature) = _rustSign(
            address(wallet),
            uint64(block.chainid),
            2, // nonce
            uint64(expiry),
            address(target),
            1 ether,
            calldataHash,
            policyHash,
            address(wallet)
        );

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 2,
            expiry: expiry,
            target: address(target),
            value: 1 ether,
            calldataHash: calldataHash,
            policyHash: policyHash
        });

        uint256 targetBalBefore = address(target).balance;
        wallet.execute(address(target), 1 ether, callData, permit, signature);

        assertEq(address(target).balance, targetBalBefore + 1 ether, "Target should receive ETH");
        assertEq(target.lastValue(), 99);
    }

    function test_rustSignerFFI_zeroPolicyHash() public {
        bytes memory callData = abi.encodeWithSelector(MockFFITarget.recordCall.selector, 7);
        uint48 expiry = uint48(block.timestamp + 600);
        bytes32 calldataHash = keccak256(callData);
        bytes32 policyHash = bytes32(0); // None in Rust

        (, bytes memory signature) = _rustSign(
            address(wallet),
            uint64(block.chainid),
            3, // nonce
            uint64(expiry),
            address(target),
            0,
            calldataHash,
            policyHash, // will be "0x0000...0000" → Rust treats as None
            address(wallet)
        );

        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 3,
            expiry: expiry,
            target: address(target),
            value: 0,
            calldataHash: calldataHash,
            policyHash: policyHash
        });

        wallet.execute(address(target), 0, callData, permit, signature);
        assertTrue(wallet.usedNonces(3));
        assertEq(target.lastValue(), 7);
    }
}

contract MockFFITarget {
    uint256 public lastValue;
    uint256 public callCount;

    function recordCall(uint256 x) external payable {
        lastValue = x;
        callCount++;
    }

    receive() external payable {}
}
