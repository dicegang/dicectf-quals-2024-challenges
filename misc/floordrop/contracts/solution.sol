// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

interface IPow {
    function solveChallenge(
        bytes calldata solution,
        uint256 solver_nonce
    ) external;
}

contract Solution {
    bytes solution;
    IPow target;

    function solveChallenge(
        bytes calldata,
        uint256 solver_nonce
    ) public payable {
        target.solveChallenge(solution, solver_nonce);
    }

    function feedSolution(bytes calldata _solution, address _target) public {
        solution = _solution;
        target = IPow(_target);
    }
}
