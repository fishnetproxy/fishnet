// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract FishnetWallet {
    error PermitExpired();
    error WrongChain();
    error NonceUsed();
    error TargetMismatch();
    error ValueMismatch();
    error CalldataMismatch();
    error WalletMismatch();
    error InvalidSignature();
    error InvalidSignatureLength();
    error ExecutionFailed();
    error NotOwner();
    error WalletPaused();
    error ZeroAddress();
    error WithdrawFailed();

    // Slot 0: owner (20 bytes) + paused (1 byte) packed
    address public owner;
    bool public paused;
    address public fishnetSigner;
    mapping(uint256 => bool) public usedNonces;

    bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;
    uint256 private immutable _CACHED_CHAIN_ID;

    bytes32 internal constant PERMIT_TYPEHASH = keccak256(
        "FishnetPermit(address wallet,uint64 chainId,uint256 nonce,"
        "uint48 expiry,address target,uint256 value,"
        "bytes32 calldataHash,bytes32 policyHash)"
    );

    struct FishnetPermit {
        address wallet;
        uint64  chainId;
        uint256 nonce;
        uint48  expiry;
        address target;
        uint256 value;
        bytes32 calldataHash;
        bytes32 policyHash;
    }

    event ActionExecuted(address indexed target, uint256 value, uint256 nonce, bytes32 policyHash);
    event SignerUpdated(address indexed oldSigner, address indexed newSigner);
    event Paused(address account);
    event Unpaused(address account);
    event Withdrawn(address indexed to, uint256 amount);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert WalletPaused();
        _;
    }

    constructor(address _fishnetSigner) {
        if (_fishnetSigner == address(0)) revert ZeroAddress();
        owner = msg.sender;
        fishnetSigner = _fishnetSigner;

        _CACHED_CHAIN_ID = block.chainid;
        _CACHED_DOMAIN_SEPARATOR = _computeDomainSeparator();
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        if (block.chainid == _CACHED_CHAIN_ID) {
            return _CACHED_DOMAIN_SEPARATOR;
        }
        return _computeDomainSeparator();
    }

    function _computeDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Fishnet"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        FishnetPermit calldata permit,
        bytes calldata signature
    ) external whenNotPaused {
        if (block.timestamp > permit.expiry) revert PermitExpired();
        if (permit.chainId != block.chainid) revert WrongChain();
        if (usedNonces[permit.nonce]) revert NonceUsed();
        if (permit.target != target) revert TargetMismatch();
        if (permit.value != value) revert ValueMismatch();
        if (permit.calldataHash != keccak256(data)) revert CalldataMismatch();
        if (permit.wallet != address(this)) revert WalletMismatch();
        if (!_verifySignature(permit, signature)) revert InvalidSignature();

        usedNonces[permit.nonce] = true;

        (bool success, ) = target.call{value: value}(data);
        if (!success) revert ExecutionFailed();

        emit ActionExecuted(target, value, permit.nonce, permit.policyHash);
    }

    function _verifySignature(
        FishnetPermit calldata permit,
        bytes calldata signature
    ) internal view returns (bool) {
        if (signature.length != 65) revert InvalidSignatureLength();

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
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash)
        );

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            let ptr := signature.offset
            r := calldataload(ptr)
            s := calldataload(add(ptr, 32))
            v := byte(0, calldataload(add(ptr, 64)))
        }

        address recoveredSigner = ecrecover(digest, v, r, s);
        return recoveredSigner == fishnetSigner;
    }

    function setSigner(address _signer) external onlyOwner {
        if (_signer == address(0)) revert ZeroAddress();
        address oldSigner = fishnetSigner;
        fishnetSigner = _signer;
        emit SignerUpdated(oldSigner, _signer);
    }

    function withdraw(address to) external onlyOwner {
        uint256 balance = address(this).balance;
        (bool success, ) = to.call{value: balance}("");
        if (!success) revert WithdrawFailed();
        emit Withdrawn(to, balance);
    }

    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    receive() external payable {}
}
