// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {SourceDepositBox} from "../src/SourceDepositBox.sol";
import {IFirewallGatedBridge} from "../src/IFirewallGatedBridge.sol";

contract DeployChainA is Script {
    function run() external returns (address depositBox) {
        uint256 deployerPrivateKey = vm.envOr("DEPLOYER_KEY", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80));
        vm.startBroadcast(deployerPrivateKey);
        SourceDepositBox box = new SourceDepositBox();
        vm.stopBroadcast();
        console2.log("Chain A - SourceDepositBox deployed at:", address(box));
        return address(box);
    }
}

contract DeployChainB is Script {
    function run() external returns (address bridge) {
        uint256 deployerPrivateKey = vm.envOr("DEPLOYER_KEY", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80));
        
        address[] memory guardians = new address[](3);
        guardians[0] = vm.addr(0x1111);
        guardians[1] = vm.addr(0x2222);
        guardians[2] = vm.addr(0x3333);

        vm.startBroadcast(deployerPrivateKey);
        IFirewallGatedBridge gatedBridge = new IFirewallGatedBridge(guardians, 2, 1);
        vm.stopBroadcast();
        console2.log("Chain B - IFirewallGatedBridge deployed at:", address(gatedBridge));
        return address(gatedBridge);
    }
}
