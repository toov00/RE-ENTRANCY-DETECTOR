// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * This contract demonstrates secure patterns that prevent reentrancy.
 */
contract SafeBank is ReentrancyGuard {
    mapping(address => uint256) public balances;
    mapping(address => bool) public hasDeposited;

    uint256 public totalDeposits;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    /**
     * Deposit ETH into the bank
     */
    function deposit() external payable {
        require(msg.value > 0, "Must deposit something");

        balances[msg.sender] += msg.value;
        hasDeposited[msg.sender] = true;
        totalDeposits += msg.value;

        emit Deposit(msg.sender, msg.value);
    }

    /**
     * SAFE: Follows Checks-Effects-Interactions pattern
     */
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        totalDeposits -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdrawal(msg.sender, amount);
    }

    /**
     * SAFE: Withdraw all funds with proper ordering
     */
    function withdrawAll() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        balances[msg.sender] = 0;
        totalDeposits -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdrawal(msg.sender, amount);
    }

    /**
     * SAFE: Pull pattern instead of push
     */
    function claimRefund() external nonReentrant {
        uint256 refund = balances[msg.sender];
        require(refund > 0, "Nothing to claim");

        balances[msg.sender] = 0;
        totalDeposits -= refund;

        (bool success, ) = msg.sender.call{value: refund}("");
        require(success, "Claim failed");
    }

    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}

/**
 * Safe batch processing using pull pattern
 */
contract SafeBatchProcessor is ReentrancyGuard {
    mapping(address => uint256) public pendingPayments;
    address[] public payees;

    event PaymentRegistered(address indexed payee, uint256 amount);
    event PaymentClaimed(address indexed payee, uint256 amount);

    function registerPayments(
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external payable {
        require(recipients.length == amounts.length, "Length mismatch");

        uint256 total = 0;
        for (uint256 i = 0; i < recipients.length; i++) {
            pendingPayments[recipients[i]] += amounts[i];
            payees.push(recipients[i]);
            total += amounts[i];
            emit PaymentRegistered(recipients[i], amounts[i]);
        }

        require(msg.value >= total, "Insufficient ETH sent");
    }

    /**
     * SAFE: Pull pattern, users claim their own payments
     */
    function claimPayment() external nonReentrant {
        uint256 amount = pendingPayments[msg.sender];
        require(amount > 0, "No pending payment");

        // Effects first
        pendingPayments[msg.sender] = 0;

        // Interactions last
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Claim failed");

        emit PaymentClaimed(msg.sender, amount);
    }

    receive() external payable {}
}

/**
 * Manual mutex implementation
 */
contract MutexExample {
    mapping(address => uint256) public balances;

    bool private locked;

    modifier noReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /**
     * SAFE: Protected by custom mutex
     */
    function withdraw(uint256 amount) external noReentrant {
        require(balances[msg.sender] >= amount, "Insufficient");

        balances[msg.sender] -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    receive() external payable {}
}
