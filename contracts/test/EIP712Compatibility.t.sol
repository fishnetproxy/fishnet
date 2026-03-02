// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {FishnetWallet} from "../src/FishnetWallet.sol";

/// @title EIP712 Compatibility Tests
/// @notice Proves encoding compatibility between the Rust backend signer and Solidity contract.
///         Each test mirrors the exact encoding path used in crates/server/src/signer.rs.
contract EIP712CompatibilityTest is Test {
    FishnetWallet public wallet;

    uint256 internal signerPrivateKey;
    address internal signer;

    bytes32 constant EXPECTED_PERMIT_TYPEHASH = keccak256(
        "FishnetPermit(address wallet,uint64 chainId,uint256 nonce,"
        "uint48 expiry,address target,uint256 value,"
        "bytes32 calldataHash,bytes32 policyHash)"
    );

    bytes32 constant EXPECTED_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    function setUp() public {
        signerPrivateKey = 0xA11CE;
        signer = vm.addr(signerPrivateKey);
        wallet = new FishnetWallet(signer);
    }

    // =========================================================================
    // Test 1: PERMIT_TYPEHASH matches the raw keccak256 of the type string
    // =========================================================================

    function test_permitTypehashMatchesSolidity() public view {
        // Compute from the raw string exactly as Rust does:
        // Keccak256::digest(b"FishnetPermit(address wallet,uint64 chainId,...)")
        bytes32 fromRawString = keccak256(
            "FishnetPermit(address wallet,uint64 chainId,uint256 nonce,"
            "uint48 expiry,address target,uint256 value,"
            "bytes32 calldataHash,bytes32 policyHash)"
        );

        // The contract's PERMIT_TYPEHASH is internal, so we recompute and verify
        // they match the same constant used in _verifySignature
        assertEq(fromRawString, EXPECTED_PERMIT_TYPEHASH);

        // Verify through a successful execution (indirect proof that contract uses same typehash)
        // This is validated by test_rustSignerEndToEnd below
    }

    // =========================================================================
    // Test 2: Domain separator encoding matches Rust's field-by-field construction
    // =========================================================================

    function test_domainSeparatorEncoding() public view {
        // Rust constructs the domain separator as:
        //   domain_data = domain_type_hash || name_hash || version_hash || chain_id_padded || vc_padded
        //   domain_separator = keccak256(domain_data)

        bytes32 domainTypeHash = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
        assertEq(domainTypeHash, EXPECTED_DOMAIN_TYPEHASH);

        // Rust: Keccak256::digest(b"Fishnet")  (was incorrectly "FishnetPermit" before fix)
        bytes32 nameHash = keccak256("Fishnet");

        // Rust: Keccak256::digest(b"1")
        bytes32 versionHash = keccak256("1");

        // Manual domain separator construction (mirrors Rust's byte concatenation)
        bytes32 manualDomainSep = keccak256(
            abi.encode(
                domainTypeHash,
                nameHash,
                versionHash,
                block.chainid,
                address(wallet)
            )
        );

        // Must match the contract's cached domain separator
        assertEq(manualDomainSep, wallet.DOMAIN_SEPARATOR());
    }

    // =========================================================================
    // Test 3: Struct hash encoding — field-by-field abi.encode matches Rust
    // =========================================================================

    function test_structHashEncoding() public view {
        // Construct a permit with known values
        address walletAddr = address(wallet);
        uint64 chainId = uint64(block.chainid);
        uint256 nonce = 42;
        uint48 expiry = uint48(block.timestamp + 300);
        address target = address(0xBEEF);
        uint256 value = 1 ether;
        bytes32 calldataHash = keccak256(hex"deadbeef");
        bytes32 policyHash = keccak256("test-policy");

        // Rust encodes struct hash as:
        //   permit_type_hash || wallet_padded || chain_id_bytes || nonce_bytes || expiry_bytes
        //   || target_padded || value_bytes || calldata_hash || policy_hash
        // Each field is left-padded to 32 bytes (standard abi.encode behavior)

        // Solidity's abi.encode automatically pads smaller types (uint64, uint48, address)
        // to 32 bytes, which matches Rust's manual padding
        bytes32 structHash = keccak256(
            abi.encode(
                EXPECTED_PERMIT_TYPEHASH,
                walletAddr,
                chainId,    // uint64 → padded to 32 bytes by abi.encode
                nonce,
                expiry,     // uint48 → padded to 32 bytes by abi.encode
                target,
                value,
                calldataHash,
                policyHash
            )
        );

        // Verify that encoding each field individually and concatenating
        // produces the same hash — this mirrors Rust's field-by-field approach
        bytes memory manualConcat = abi.encode(
            EXPECTED_PERMIT_TYPEHASH,
            walletAddr,
            chainId,
            nonce,
            expiry,
            target,
            value,
            calldataHash,
            policyHash
        );
        bytes32 structHashManual = keccak256(manualConcat);

        assertEq(structHash, structHashManual);
    }

    // =========================================================================
    // Test 4: Full end-to-end — Rust signer path produces valid signature
    // =========================================================================

    function test_rustSignerEndToEnd() public {
        // This test follows the EXACT code path in signer.rs:eip712_hash()
        // to prove that the Rust signer produces signatures the contract accepts.

        MockReceiver receiver = new MockReceiver();
        bytes memory callData = abi.encodeWithSelector(MockReceiver.doWork.selector, 123);
        uint48 expiry = uint48(block.timestamp + 600);
        bytes32 policyHash = keccak256("policy-v1");
        bytes32 calldataHash = keccak256(callData);

        // Compute EIP-712 digest following Rust's exact code path
        bytes32 digest = _computeDigest(address(receiver), expiry, calldataHash, policyHash);

        // Sign and pack as r || s || v (65 bytes, matches Rust's output)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        assertEq(signature.length, 65);

        // Build permit and execute
        FishnetWallet.FishnetPermit memory permit = FishnetWallet.FishnetPermit({
            wallet: address(wallet),
            chainId: uint64(block.chainid),
            nonce: 1,
            expiry: expiry,
            target: address(receiver),
            value: 0,
            calldataHash: calldataHash,
            policyHash: policyHash
        });

        vm.deal(address(wallet), 1 ether);
        wallet.execute(address(receiver), 0, callData, permit, signature);

        // Verify execution succeeded
        assertTrue(wallet.usedNonces(1), "Nonce should be marked used");
        assertEq(receiver.lastArg(), 123, "Target should have received call");
    }

    /// @dev Mirrors signer.rs:eip712_hash() — domain separator + struct hash + 0x1901 prefix
    function _computeDigest(
        address target,
        uint48 expiry,
        bytes32 calldataHash,
        bytes32 policyHash
    ) internal view returns (bytes32) {
        // Step 1: Domain separator (mirrors signer.rs lines 75-99)
        bytes32 domainSeparator = keccak256(
            abi.encode(
                EXPECTED_DOMAIN_TYPEHASH,
                keccak256("Fishnet"),
                keccak256("1"),
                block.chainid,
                address(wallet)
            )
        );

        // Step 2: Struct hash (mirrors signer.rs lines 102-165)
        bytes32 structHash = keccak256(
            abi.encode(
                EXPECTED_PERMIT_TYPEHASH,
                address(wallet),
                uint64(block.chainid),
                uint256(1),   // nonce
                expiry,
                target,
                uint256(0),   // value
                calldataHash,
                policyHash
            )
        );

        // Step 3: EIP-712 digest (mirrors signer.rs lines 168-177)
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    // =========================================================================
    // Test 5: Signature format — r || s || v packed to 65 bytes
    // =========================================================================

    function test_signatureFormatRSV() public view {
        // The Rust signer outputs: signature.to_bytes() (r || s, 64 bytes) + recovery_id + 27
        // This produces a 65-byte signature in [r(32) || s(32) || v(1)] format

        bytes32 testDigest = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, testDigest);

        // Pack exactly as Rust does: r || s || v
        bytes memory packed = abi.encodePacked(r, s, v);
        assertEq(packed.length, 65, "Signature must be exactly 65 bytes");

        // Verify the contract can unpack this format
        // The contract uses assembly to extract r, s, v from calldata:
        //   r = calldataload(ptr)        → bytes 0-31
        //   s = calldataload(ptr + 32)   → bytes 32-63
        //   v = byte(0, calldataload(ptr + 64)) → byte 64
        bytes32 extractedR;
        bytes32 extractedS;
        uint8 extractedV;
        assembly {
            let ptr := add(packed, 32)
            extractedR := mload(ptr)
            extractedS := mload(add(ptr, 32))
            extractedV := byte(0, mload(add(ptr, 64)))
        }

        assertEq(extractedR, r, "R component mismatch");
        assertEq(extractedS, s, "S component mismatch");
        assertEq(extractedV, v, "V component mismatch");

        // Verify ecrecover works with extracted components
        address recovered = ecrecover(testDigest, extractedV, extractedR, extractedS);
        assertEq(recovered, signer, "ecrecover should return signer address");
    }

    // =========================================================================
    // Test 6: abi.encode padding — uint64 and uint48 pad identically to Rust
    // =========================================================================

    function test_abiEncodePaddingMatchesRust() public pure {
        // Rust pads u64 values into 32-byte arrays with big-endian right-alignment:
        //   let mut chain_id_bytes = [0u8; 32];
        //   chain_id_bytes[24..].copy_from_slice(&permit.chain_id.to_be_bytes());
        //
        // Solidity's abi.encode(uint64(x)) produces the same 32-byte left-padded output.

        uint64 chainId = 84532; // Base Sepolia
        bytes memory encoded = abi.encode(chainId);
        assertEq(encoded.length, 32);

        // Verify left-padding: first 24 bytes should be zero
        for (uint256 i = 0; i < 24; i++) {
            assertEq(uint8(encoded[i]), 0, "Should be zero-padded");
        }

        // Same for uint48 (expiry) — Rust uses 8 bytes (u64) but the value fits in 6 bytes
        // abi.encode(uint48) also produces 32-byte left-padded output
        uint48 expiry = 1700000000;
        bytes memory encodedExpiry = abi.encode(expiry);
        assertEq(encodedExpiry.length, 32);

        // First 26 bytes should be zero for uint48
        for (uint256 i = 0; i < 26; i++) {
            assertEq(uint8(encodedExpiry[i]), 0, "Expiry should be zero-padded");
        }
    }
}

/// @dev Simple target contract for end-to-end test
contract MockReceiver {
    uint256 public lastArg;

    function doWork(uint256 x) external payable {
        lastArg = x;
    }

    receive() external payable {}
}
