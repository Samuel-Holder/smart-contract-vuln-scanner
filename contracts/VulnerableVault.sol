// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableVault
 * @notice Example contract with intentional vulnerabilities for scanner demonstration
 * @dev DO NOT USE IN PRODUCTION - This contract is for educational purposes only
 */
contract VulnerableVault {
    
    mapping(address => uint256) public balances;
    address public owner;
    bool public paused;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABILITY: Missing zero address check
    function setOwner(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        owner = newOwner;
    }
    
    function deposit() external payable {
        require(!paused, "Paused");
        require(msg.value > 0, "Zero deposit");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    // VULNERABILITY: Classic reentrancy - external call before state update
    function withdraw(uint256 amount) external {
        require(!paused, "Paused");
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // BUG: External call BEFORE state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State update happens AFTER external call - vulnerable!
        balances[msg.sender] -= amount;
        
        emit Withdrawal(msg.sender, amount);
    }
    
    // VULNERABILITY: Missing access control on critical function
    function pause() external {
        paused = true;
    }
    
    // VULNERABILITY: Missing access control on critical function
    function unpause() external {
        paused = false;
    }
    
    // VULNERABILITY: tx.origin for authorization
    function emergencyWithdraw() external {
        require(tx.origin == owner, "Not owner");
        (bool success, ) = owner.call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }
    
    // VULNERABILITY: Timestamp used for randomness
    function getRandomNumber() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 100;
    }
    
    // VULNERABILITY: Unbounded loop - DoS vector
    function batchTransfer(address[] calldata recipients, uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        
        for (uint256 i = 0; i < recipients.length; i++) {
            (bool success, ) = recipients[i].call{value: amount}("");
            require(success, "Transfer failed");
        }
    }
    
    // VULNERABILITY: Unchecked send return value
    function unsafeSend(address payable to, uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        to.send(amount);  // Return value not checked!
    }
    
    // VULNERABILITY: Selfdestruct without proper protection
    function destroy() external {
        require(msg.sender == owner, "Not owner");
        selfdestruct(payable(owner));
    }
    
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}


/**
 * @title VulnerableProxy
 * @notice Proxy with dangerous delegatecall
 */
contract VulnerableProxy {
    address public implementation;
    address public owner;
    
    constructor(address _implementation) {
        implementation = _implementation;
        owner = msg.sender;
    }
    
    // VULNERABILITY: Arbitrary delegatecall with user data
    function execute(address target, bytes calldata data) external returns (bytes memory) {
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "Delegatecall failed");
        return result;
    }
    
    // VULNERABILITY: Unprotected initialize function
    function initialize(address newOwner) public {
        owner = newOwner;
    }
    
    fallback() external payable {
        (bool success, ) = implementation.delegatecall(msg.data);
        require(success, "Fallback failed");
    }
}


/**
 * @title VulnerableLottery
 * @notice Lottery with weak randomness
 */
contract VulnerableLottery {
    address public owner;
    address[] public players;
    uint256 public ticketPrice = 0.01 ether;
    
    constructor() {
        owner = msg.sender;
    }
    
    function buyTicket() external payable {
        require(msg.value == ticketPrice, "Wrong price");
        players.push(msg.sender);
    }
    
    // VULNERABILITY: Weak randomness using block variables
    function pickWinner() external {
        require(msg.sender == owner, "Not owner");
        require(players.length > 0, "No players");
        
        // INSECURE: Miners can manipulate these values!
        uint256 random = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.difficulty,
            blockhash(block.number - 1),
            players.length
        ))) % players.length;
        
        address winner = players[random];
        (bool success, ) = winner.call{value: address(this).balance}("");
        require(success, "Transfer failed");
        
        delete players;
    }
    
    // VULNERABILITY: Unbounded array deletion - gas issues
    function resetPlayers() external {
        require(msg.sender == owner, "Not owner");
        for (uint256 i = 0; i < players.length; i++) {
            delete players[i];
        }
    }
}
