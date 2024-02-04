// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

contract Distributor {
    function send(
        address payable[] calldata to,
        uint256 amount
    ) public payable {
        for (uint256 i = 0; i < to.length; i++) {
            to[i].transfer(amount);
        }
    }
}
