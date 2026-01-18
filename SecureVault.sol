// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title SecureVault
 * @notice Example of a properly secured vault contract
 * @dev Demonstrates security best practices
 */
contract SecureVault is ReentrancyGuard, Pausable, Ownable {
    
    mapping(address => uint256) private _balances;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    
    constructor() Ownable(msg.sender) {}
    
    /**
     * @notice Get balance of an account
     * @param account The address to query
     * @return The balance of the account
     */
    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }
    
    /**
     * @notice Deposit ETH into the vault
     */
    function deposit() external payable whenNotPaused {
        require(msg.value > 0, "SecureVault: zero deposit");
        
        _balances[msg.sender] += msg.value;
        
        emit Deposit(msg.sender, msg.value);
    }
    
    /**
     * @notice Withdraw ETH from the vault
     * @param amount The amount to withdraw
     * @dev Uses checks-effects-interactions pattern and reentrancy guard
     */
    function withdraw(uint256 amount) external nonReentrant whenNotPaused {
        // CHECKS
        require(amount > 0, "SecureVault: zero amount");
        require(_balances[msg.sender] >= amount, "SecureVault: insufficient balance");
        
        // EFFECTS - State update BEFORE external call
        _balances[msg.sender] -= amount;
        
        // INTERACTIONS - External call AFTER state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "SecureVault: transfer failed");
        
        emit Withdrawal(msg.sender, amount);
    }
    
    /**
     * @notice Pause deposits and withdrawals
     * @dev Only owner can pause
     */
    function pause() external onlyOwner {
        _pause();
    }
    
    /**
     * @notice Unpause deposits and withdrawals
     * @dev Only owner can unpause
     */
    function unpause() external onlyOwner {
        _unpause();
    }
    
    /**
     * @notice Transfer ownership with zero address check
     * @param newOwner The new owner address
     */
    function transferOwnership(address newOwner) public override onlyOwner {
        require(newOwner != address(0), "SecureVault: zero address");
        super.transferOwnership(newOwner);
    }
    
    /**
     * @notice Emergency withdrawal for owner
     * @dev Uses msg.sender not tx.origin for auth
     */
    function emergencyWithdraw() external onlyOwner {
        uint256 balance = address(this).balance;
        require(balance > 0, "SecureVault: no balance");
        
        (bool success, ) = owner().call{value: balance}("");
        require(success, "SecureVault: transfer failed");
    }
    
    /**
     * @notice Get contract balance
     * @return The ETH balance of the contract
     */
    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }
    
    receive() external payable {
        _balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
}
