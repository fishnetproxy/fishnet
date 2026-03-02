// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {FishnetWallet} from "../src/FishnetWallet.sol";

contract DeployFishnetWallet is Script {
    function run() external {
        address signerAddress = vm.envAddress("SIGNER_ADDRESS");

        vm.startBroadcast();

        FishnetWallet wallet = new FishnetWallet(signerAddress);
        console.log("FishnetWallet deployed at:", address(wallet));
        console.log("Signer:", signerAddress);
        console.log("Owner:", msg.sender);
        console.log("Chain ID:", block.chainid);

        vm.stopBroadcast();

        // Write deployment info to JSON
        string memory networkName = _getNetworkName();
        string memory json = "deployment";
        vm.serializeAddress(json, "wallet", address(wallet));
        vm.serializeAddress(json, "signer", signerAddress);
        vm.serializeAddress(json, "owner", msg.sender);
        vm.serializeUint(json, "chainId", block.chainid);
        vm.serializeUint(json, "deployBlock", block.number);
        string memory finalJson = vm.serializeUint(json, "timestamp", block.timestamp);

        string memory path = string.concat("deployments/", networkName, ".json");
        vm.writeJson(finalJson, path);
        console.log("Deployment info written to:", path);
    }

    function _getNetworkName() internal view returns (string memory) {
        if (block.chainid == 84532) return "base-sepolia";
        if (block.chainid == 8453) return "base-mainnet";
        if (block.chainid == 421614) return "arbitrum-sepolia";
        if (block.chainid == 42161) return "arbitrum-one";
        if (block.chainid == 31337) return "localhost";
        return vm.toString(block.chainid);
    }
}
