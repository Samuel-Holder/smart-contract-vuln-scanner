# Vulnerability Reference Guide

This document provides detailed information about each vulnerability type detected by the scanner, including examples, impacts, and remediation guidance.

## Table of Contents

1. [Reentrancy Attacks](#reentrancy-attacks)
2. [Access Control Issues](#access-control-issues)
3. [Unchecked External Calls](#unchecked-external-calls)
4. [Timestamp Dependence](#timestamp-dependence)
5. [Weak Randomness](#weak-randomness)
6. [Denial of Service](#denial-of-service)
7. [Initialization Vulnerabilities](#initialization-vulnerabilities)
8. [Delegatecall Issues](#delegatecall-issues)
9. [Selfdestruct Risks](#selfdestruct-risks)
10. [Input Validation](#input-validation)

---

## Reentrancy Attacks

**OWASP Category:** SC03  
**CWE ID:** CWE-841  
**Severity:** Critical

### Description

Reentrancy occurs when an external call allows the called contract to make additional calls back to the calling contract before the first execution is complete. This can lead to unexpected state changes and fund drainage.

### Vulnerable Pattern

```solidity
// VULNERABLE - External call BEFORE state update
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    
    // External call - attacker can re-enter here
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    
    // State update AFTER call - vulnerable!
    balances[msg.sender] -= amount;
}
```

### Attack Scenario

1. Attacker deploys malicious contract with fallback function
2. Attacker calls `withdraw()` with their balance
3. During the `call`, attacker's fallback re-enters `withdraw()`
4. Since balance not yet updated, check passes again
5. Repeat until contract is drained

### Secure Pattern

```solidity
// SECURE - Checks-Effects-Interactions pattern
function withdraw(uint256 amount) external nonReentrant {
    // CHECKS
    require(balances[msg.sender] >= amount);
    
    // EFFECTS - State update BEFORE call
    balances[msg.sender] -= amount;
    
    // INTERACTIONS - External call AFTER state update
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
}
```

### Remediation

1. Follow Checks-Effects-Interactions pattern
2. Use `ReentrancyGuard` from OpenZeppelin
3. Consider using `transfer()` (2300 gas limit) for simple transfers

### References

- [SWC-107: Reentrancy](https://swcregistry.io/docs/SWC-107)
- [The DAO Hack](https://www.coindesk.com/understanding-dao-hack-journalists)

---

## Access Control Issues

**OWASP Category:** SC01  
**CWE ID:** CWE-284  
**Severity:** Critical

### Description

Missing or improper access control allows unauthorized users to execute privileged functions, potentially leading to complete contract takeover.

### Vulnerable Pattern

```solidity
// VULNERABLE - No access control
function pause() external {
    paused = true;  // Anyone can pause!
}

function mint(address to, uint256 amount) external {
    _mint(to, amount);  // Anyone can mint!
}
```

### Secure Pattern

```solidity
// SECURE - Proper access control
function pause() external onlyOwner {
    paused = true;
}

function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
    _mint(to, amount);
}
```

### Critical Functions That Need Protection

- `pause()` / `unpause()`
- `mint()` / `burn()`
- `withdraw()` / `transfer()`
- `setOracle()` / `setPrice()`
- `upgrade()` / `initialize()`
- Any function modifying contract state

### Remediation

1. Use `Ownable` for single-owner contracts
2. Use `AccessControl` for role-based permissions
3. Document which functions should be protected

### References

- [SWC-105: Unprotected Ether Withdrawal](https://swcregistry.io/docs/SWC-105)

---

## Unchecked External Calls

**OWASP Category:** SC07  
**CWE ID:** CWE-252  
**Severity:** Medium

### Description

External calls can fail silently if return values aren't checked, leading to inconsistent contract state.

### Vulnerable Pattern

```solidity
// VULNERABLE - Return value ignored
function unsafeSend(address to, uint256 amount) external {
    payable(to).send(amount);  // Can fail silently!
}

function unsafeCall(address to) external {
    to.call{value: 1 ether}("");  // Return not checked!
}
```

### Secure Pattern

```solidity
// SECURE - Check return values
function safeSend(address to, uint256 amount) external {
    bool success = payable(to).send(amount);
    require(success, "Send failed");
}

function safeCall(address to) external {
    (bool success, ) = to.call{value: 1 ether}("");
    require(success, "Call failed");
}
```

### Remediation

1. Always check return values of `call()`, `send()`, `delegatecall()`
2. Consider using `transfer()` which reverts on failure
3. Use try/catch for handling external calls gracefully

### References

- [SWC-104: Unchecked Call Return Value](https://swcregistry.io/docs/SWC-104)

---

## Timestamp Dependence

**OWASP Category:** SC02  
**CWE ID:** CWE-330  
**Severity:** Medium to High

### Description

Block timestamps can be manipulated by miners within a ~15 second range, making them unsuitable for critical logic or randomness.

### Vulnerable Pattern

```solidity
// VULNERABLE - Timestamp for critical logic
function claimReward() external {
    require(block.timestamp > lockEndTime);  // Miner can manipulate
    // ...
}

// VULNERABLE - Timestamp for randomness
function random() external view returns (uint256) {
    return uint256(keccak256(abi.encodePacked(block.timestamp))) % 100;
}
```

### Secure Pattern

```solidity
// MORE SECURE - Block number for time-sensitive logic
function claimReward() external {
    require(block.number > lockEndBlock);
    // ...
}

// SECURE - Chainlink VRF for randomness
function requestRandom() external returns (uint256 requestId) {
    return COORDINATOR.requestRandomWords(...);
}
```

### Remediation

1. Use block numbers instead of timestamps for timing
2. Accept ~15 second manipulation for non-critical timing
3. Use Chainlink VRF or commit-reveal for randomness

### References

- [SWC-116: Timestamp Dependence](https://swcregistry.io/docs/SWC-116)

---

## Weak Randomness

**OWASP Category:** SC10  
**CWE ID:** CWE-330  
**Severity:** High

### Description

On-chain randomness using block variables is predictable and manipulable by miners or validators.

### Vulnerable Sources

```solidity
// ALL VULNERABLE - Miners can predict/manipulate
block.timestamp
block.difficulty
blockhash(block.number)
blockhash(block.number - 1)
block.coinbase
block.gaslimit
```

### Secure Pattern

```solidity
// SECURE - Chainlink VRF
import "@chainlink/contracts/src/v0.8/VRFConsumerBaseV2.sol";

contract SecureLottery is VRFConsumerBaseV2 {
    function requestRandomWinner() external {
        // Request random from Chainlink
        uint256 requestId = COORDINATOR.requestRandomWords(
            keyHash,
            subscriptionId,
            requestConfirmations,
            callbackGasLimit,
            numWords
        );
    }
    
    function fulfillRandomWords(
        uint256 requestId,
        uint256[] memory randomWords
    ) internal override {
        uint256 winnerIndex = randomWords[0] % players.length;
        // Select winner...
    }
}
```

### Remediation

1. Use Chainlink VRF for verifiable randomness
2. Implement commit-reveal schemes
3. Never use block variables for randomness

### References

- [SWC-120: Weak Sources of Randomness](https://swcregistry.io/docs/SWC-120)
- [Chainlink VRF Docs](https://docs.chain.link/vrf)

---

## Denial of Service

**OWASP Category:** SC09  
**CWE ID:** CWE-400  
**Severity:** High

### Description

DoS vulnerabilities can make contract functions unusable by consuming excessive gas or blocking execution.

### Vulnerable Pattern

```solidity
// VULNERABLE - Unbounded loop
function distributeRewards() external {
    for (uint256 i = 0; i < users.length; i++) {  // Can exceed gas limit
        payable(users[i]).transfer(rewards[users[i]]);
    }
}

// VULNERABLE - External call can fail
function distributeAll() external {
    for (uint256 i = 0; i < users.length; i++) {
        (bool success, ) = users[i].call{value: 1 ether}("");
        require(success);  // One failure blocks all
    }
}
```

### Secure Pattern

```solidity
// SECURE - Pull pattern
mapping(address => uint256) public pendingWithdrawals;

function claimReward() external {
    uint256 amount = pendingWithdrawals[msg.sender];
    require(amount > 0);
    pendingWithdrawals[msg.sender] = 0;
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
}

// SECURE - Pagination
function processUsers(uint256 start, uint256 end) external {
    require(end <= users.length);
    require(end - start <= MAX_BATCH);
    
    for (uint256 i = start; i < end; i++) {
        // Process user
    }
}
```

### Remediation

1. Use pull-over-push pattern for payments
2. Implement pagination for loops
3. Don't let single failures block others

### References

- [SWC-128: DoS With Block Gas Limit](https://swcregistry.io/docs/SWC-128)

---

## Initialization Vulnerabilities

**OWASP Category:** SC01  
**CWE ID:** CWE-456  
**Severity:** Critical

### Description

Upgradeable contracts with unprotected `initialize` functions can be taken over by anyone calling them first.

### Vulnerable Pattern

```solidity
// VULNERABLE - Can be called by anyone, multiple times
function initialize(address _owner) external {
    owner = _owner;
}
```

### Secure Pattern

```solidity
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract SecureContract is Initializable {
    address public owner;
    
    // SECURE - initializer modifier prevents re-initialization
    function initialize(address _owner) external initializer {
        require(_owner != address(0), "Zero address");
        owner = _owner;
    }
}
```

### Remediation

1. Use OpenZeppelin's `Initializable` contract
2. Apply `initializer` modifier to init functions
3. Check for zero addresses in initialization

### References

- [SWC-118: Incorrect Constructor Name](https://swcregistry.io/docs/SWC-118)

---

## Delegatecall Issues

**OWASP Category:** SC01  
**CWE ID:** CWE-284  
**Severity:** Critical

### Description

`delegatecall` executes code in the caller's context. If the target is user-controlled, attackers can execute arbitrary code with full contract privileges.

### Vulnerable Pattern

```solidity
// VULNERABLE - User-controlled delegatecall
function execute(address target, bytes calldata data) external {
    target.delegatecall(data);  // Attacker controls target!
}
```

### Secure Pattern

```solidity
// SECURE - Whitelisted targets
mapping(address => bool) public allowedTargets;

function execute(address target, bytes calldata data) external onlyOwner {
    require(allowedTargets[target], "Target not allowed");
    (bool success, ) = target.delegatecall(data);
    require(success);
}
```

### Remediation

1. Never use user-controlled addresses with delegatecall
2. Whitelist allowed delegatecall targets
3. Consider if delegatecall is necessary

### References

- [SWC-112: Delegatecall to Untrusted Callee](https://swcregistry.io/docs/SWC-112)

---

## Selfdestruct Risks

**OWASP Category:** SC01  
**CWE ID:** CWE-284  
**Severity:** High

### Description

`selfdestruct` permanently destroys a contract and sends all remaining ETH to a specified address.

### Vulnerable Pattern

```solidity
// VULNERABLE - Weak protection
function destroy() external {
    require(msg.sender == owner);
    selfdestruct(payable(owner));
}
```

### Secure Pattern

```solidity
// Better - Multiple safeguards
function destroy() external onlyOwner {
    require(block.timestamp > destructionTime, "Too early");
    require(emergencyDestroy, "Not approved");
    selfdestruct(payable(owner));
}

// Best - Don't include selfdestruct at all
```

### Remediation

1. Consider if selfdestruct is necessary
2. Add multiple layers of protection
3. Implement timelock mechanism

### References

- [SWC-106: Unprotected Selfdestruct](https://swcregistry.io/docs/SWC-106)

---

## Input Validation

**OWASP Category:** SC05  
**CWE ID:** CWE-20  
**Severity:** Low to Medium

### Description

Missing input validation can lead to unexpected behavior, failed transactions, or vulnerabilities.

### Vulnerable Pattern

```solidity
// VULNERABLE - No validation
function setRecipient(address recipient) external {
    recipientAddress = recipient;  // Could be zero address
}

function transfer(address to, uint256 amount) external {
    balances[msg.sender] -= amount;  // Could underflow (pre-0.8)
    balances[to] += amount;
}
```

### Secure Pattern

```solidity
// SECURE - Proper validation
function setRecipient(address recipient) external {
    require(recipient != address(0), "Zero address");
    recipientAddress = recipient;
}

function transfer(address to, uint256 amount) external {
    require(to != address(0), "Zero address");
    require(amount > 0, "Zero amount");
    require(balances[msg.sender] >= amount, "Insufficient balance");
    
    balances[msg.sender] -= amount;
    balances[to] += amount;
}
```

### Remediation

1. Validate all external inputs
2. Check for zero addresses
3. Validate ranges and bounds

### References

- [SWC-101: Integer Overflow and Underflow](https://swcregistry.io/docs/SWC-101)

---

## Further Resources

### Official Documentation

- [Solidity Security Considerations](https://docs.soliditylang.org/en/latest/security-considerations.html)
- [OpenZeppelin Docs](https://docs.openzeppelin.com/)
- [Chainlink Security](https://docs.chain.link/resources/security)

### Security Registries

- [SWC Registry](https://swcregistry.io/)
- [OWASP Smart Contract Top 10](https://owasp.org/www-project-smart-contract-top-10/)

### Learning Resources

- [Damn Vulnerable DeFi](https://www.damnvulnerabledefi.xyz/)
- [Ethernaut](https://ethernaut.openzeppelin.com/)
- [Capture the Ether](https://capturetheether.com/)
