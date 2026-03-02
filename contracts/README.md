# Fishnet Contracts

Smart contracts for the Fishnet permit-based wallet system.

## FishnetWallet

EIP-712 permit-gated smart wallet. The Fishnet backend signs permits authorizing on-chain actions, and any relayer can submit them.

### Build & Test

```bash
cd contracts
forge build
forge test -vvv
```

### EIP712 Compatibility Tests

The `EIP712Compatibility.t.sol` test suite proves encoding compatibility between the Rust backend signer (`crates/server/src/signer.rs`) and the Solidity contract:

- **Typehash match**: Raw keccak256 of the type string matches `PERMIT_TYPEHASH`
- **Domain separator**: Field-by-field construction matches `DOMAIN_SEPARATOR()`
- **Struct hash**: `abi.encode` padding for `uint64`/`uint48` matches Rust's manual padding
- **End-to-end**: Full EIP-712 hash → sign → execute flow succeeds
- **Signature format**: `r || s || v` (65 bytes) unpacking matches contract expectations

```bash
forge test --match-contract EIP712Compatibility -vvv
```

### Deployment

#### Local (Anvil)

```bash
# Terminal 1
anvil

# Terminal 2
cd contracts
SIGNER_ADDRESS=0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
  forge script script/Deploy.s.sol:DeployFishnetWallet \
  --rpc-url http://127.0.0.1:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --broadcast
```

#### Base Sepolia

```bash
cd contracts
export BASE_SEPOLIA_RPC_URL="https://sepolia.base.org"
export SIGNER_ADDRESS="<your-signer-address>"
export BASESCAN_API_KEY="<your-api-key>"

forge script script/Deploy.s.sol:DeployFishnetWallet \
  --rpc-url base_sepolia \
  --private-key $DEPLOYER_PRIVATE_KEY \
  --broadcast \
  --verify
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SIGNER_ADDRESS` | Yes | Address of the Fishnet backend signer |
| `OWNER_ADDRESS` | No | Wallet owner (defaults to deployer) |
| `BASE_SEPOLIA_RPC_URL` | For testnet | Base Sepolia RPC endpoint |
| `BASE_MAINNET_RPC_URL` | For mainnet | Base mainnet RPC endpoint |
| `BASESCAN_API_KEY` | For verification | Basescan API key |

### Integration Test

Run the full Anvil-based E2E test (deploys, signs permit with `cast`, executes on-chain):

```bash
bash scripts/sc3-integration-test.sh
```

### Multi-Chain Deployments

Deployment artifacts are stored in `contracts/deployments/`:

```
deployments/
  base-sepolia.json      # Base Sepolia testnet
  base-mainnet.json      # Base mainnet (future)
  arbitrum-sepolia.json   # Arbitrum Sepolia (future)
```

Each file contains: `wallet`, `signer`, `owner`, `chainId`, `deployBlock`, `timestamp`.

### EIP712 Encoding Notes

The permit typehash uses `uint64 chainId` and `uint48 expiry` (not `uint256`). Both Solidity's `abi.encode` and Rust's manual big-endian padding produce identical 32-byte left-padded values for these smaller types, ensuring cross-stack compatibility.

Domain name is `"Fishnet"` (not `"FishnetPermit"`), version is `"1"`.
