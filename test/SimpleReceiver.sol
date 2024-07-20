// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {console} from "lib/forge-std/src/Test.sol";

contract SimpleReceiver {
    // Event to log when Ether is received
    event Received(address sender, uint256 amount);

    // Fallback function to receive Ether
    receive() external payable {
        console.log("fallback called");
        emit Received(msg.sender, msg.value);
    }
}
