#!/usr/bin/env python3
"""
Unit tests for the Solidity Vulnerability Scanner
"""

import pytest
import tempfile
import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from scanner import VulnerabilityScanner, Vulnerability


class TestVulnerabilityScanner:
    """Test suite for the vulnerability scanner"""
    
    @pytest.fixture
    def scanner(self):
        """Create a fresh scanner instance"""
        return VulnerabilityScanner()
    
    @pytest.fixture
    def temp_contract(self):
        """Create a temporary contract file"""
        def _create(code: str) -> str:
            fd, path = tempfile.mkstemp(suffix='.sol')
            with os.fdopen(fd, 'w') as f:
                f.write(code)
            return path
        return _create
    
    def test_basic_scan(self, scanner, temp_contract):
        """Test basic scanning functionality"""
        code = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Simple {
    function hello() public pure returns (string memory) {
        return "Hello";
    }
}
'''
        path = temp_contract(code)
        try:
            report = scanner.scan(path)
            assert 'metadata' in report
            assert 'summary' in report
            assert 'vulnerabilities' in report
            assert report['metadata']['contract_name'] == 'Simple'
        finally:
            os.unlink(path)
    
    def test_detects_reentrancy(self, scanner, temp_contract):
        """Test reentrancy detection"""
        code = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vulnerable {
    mapping(address => uint256) public balances;
    
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Failed");
        balances[msg.sender] -= amount;
    }
}
'''
        path = temp_contract(code)
        try:
            report = scanner.scan(path)
            categories = [v['category'] for v in report['vulnerabilities']]
            assert 'Reentrancy' in categories
        finally:
            os.unlink(path)
    
    def test_no_reentrancy_with_guard(self, scanner, temp_contract):
        """Test that reentrancy guard prevents detection"""
        code = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Safe {
    mapping(address => uint256) public balances;
    bool private locked;
    
    modifier nonReentrant() {
        require(!locked, "Locked");
        locked = true;
        _;
        locked = false;
    }
    
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Failed");
    }
}
'''
        path = temp_contract(code)
        try:
            report = scanner.scan(path)
            reentrancy_vulns = [v for v in report['vulnerabilities'] 
                               if v['category'] == 'Reentrancy']
            assert len(reentrancy_vulns) == 0
        finally:
            os.unlink(path)
    
    def test_detects_unprotected_initialize(self, scanner, temp_contract):
        """Test unprotected initialize detection"""
        code = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Proxy {
    address public owner;
    
    function initialize(address newOwner) external {
        owner = newOwner;
    }
}
'''
        path = temp_contract(code)
        try:
            report = scanner.scan(path)
            init_vulns = [v for v in report['vulnerabilities'] 
                         if 'Initialize' in v['name']]
            assert len(init_vulns) > 0
        finally:
            os.unlink(path)
    
    def test_detects_access_control(self, scanner, temp_contract):
        """Test missing access control detection"""
        code = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Unsafe {
    bool public paused;
    
    function pause() external {
        paused = true;
    }
    
    function unpause() external {
        paused = false;
    }
}
'''
        path = temp_contract(code)
        try:
            report = scanner.scan(path)
            access_vulns = [v for v in report['vulnerabilities'] 
                          if v['category'] == 'Access Control']
            assert len(access_vulns) >= 2
        finally:
            os.unlink(path)
    
    def test_detects_timestamp_randomness(self, scanner, temp_contract):
        """Test timestamp-based randomness detection"""
        code = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Lottery {
    function random() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp))) % 100;
    }
}
'''
        path = temp_contract(code)
        try:
            report = scanner.scan(path)
            timestamp_vulns = [v for v in report['vulnerabilities'] 
                              if 'Timestamp' in v['category'] or 'Random' in v['name']]
            assert len(timestamp_vulns) > 0
        finally:
            os.unlink(path)
    
    def test_detects_unchecked_call(self, scanner, temp_contract):
        """Test unchecked call detection"""
        code = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Unsafe {
    function unsafeSend(address payable to) external {
        to.send(1 ether);
    }
}
'''
        path = temp_contract(code)
        try:
            report = scanner.scan(path)
            call_vulns = [v for v in report['vulnerabilities'] 
                         if 'Unchecked' in v['category']]
            assert len(call_vulns) > 0
        finally:
            os.unlink(path)
    
    def test_detects_selfdestruct(self, scanner, temp_contract):
        """Test selfdestruct detection"""
        code = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Destroyable {
    address public owner;
    
    function destroy() external {
        selfdestruct(payable(owner));
    }
}
'''
        path = temp_contract(code)
        try:
            report = scanner.scan(path)
            sd_vulns = [v for v in report['vulnerabilities'] 
                       if 'Selfdestruct' in v['category']]
            assert len(sd_vulns) > 0
        finally:
            os.unlink(path)
    
    def test_detects_tx_origin(self, scanner, temp_contract):
        """Test tx.origin detection"""
        code = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Phishable {
    address public owner;
    
    function dangerous() external {
        require(tx.origin == owner, "Not owner");
    }
}
'''
        path = temp_contract(code)
        try:
            report = scanner.scan(path)
            tx_vulns = [v for v in report['vulnerabilities'] 
                       if 'tx.origin' in v['name']]
            assert len(tx_vulns) > 0
        finally:
            os.unlink(path)
    
    def test_detects_unbounded_loop(self, scanner, temp_contract):
        """Test unbounded loop detection"""
        code = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DoS {
    address[] public users;
    
    function processAll() external {
        for (uint256 i = 0; i < users.length; i++) {
            // Process user
        }
    }
}
'''
        path = temp_contract(code)
        try:
            report = scanner.scan(path)
            dos_vulns = [v for v in report['vulnerabilities'] 
                        if v['category'] == 'DoS']
            assert len(dos_vulns) > 0
        finally:
            os.unlink(path)
    
    def test_detects_floating_pragma(self, scanner, temp_contract):
        """Test floating pragma detection"""
        code = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FloatingPragma {
    uint256 public value;
}
'''
        path = temp_contract(code)
        try:
            report = scanner.scan(path)
            pragma_vulns = [v for v in report['vulnerabilities'] 
                           if 'Pragma' in v['name']]
            assert len(pragma_vulns) > 0
        finally:
            os.unlink(path)
    
    def test_detects_delegatecall(self, scanner, temp_contract):
        """Test dangerous delegatecall detection"""
        code = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Proxy {
    function execute(address target, bytes calldata data) external {
        target.delegatecall(data);
    }
}
'''
        path = temp_contract(code)
        try:
            report = scanner.scan(path)
            dc_vulns = [v for v in report['vulnerabilities'] 
                       if 'Delegatecall' in v['category']]
            assert len(dc_vulns) > 0
        finally:
            os.unlink(path)
    
    def test_risk_score_calculation(self, scanner, temp_contract):
        """Test risk score is calculated correctly"""
        code = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MultiVuln {
    mapping(address => uint256) public balances;
    
    function initialize(address owner) external {
        // Unprotected init - Critical
    }
    
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Failed");
        balances[msg.sender] -= amount;  // Reentrancy - Critical
    }
    
    function random() external view returns (uint256) {
        return block.timestamp % 100;  // Timestamp - High
    }
}
'''
        path = temp_contract(code)
        try:
            report = scanner.scan(path)
            assert report['summary']['risk_score'] > 0
            assert report['summary']['risk_level'] in ['MINIMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        finally:
            os.unlink(path)
    
    def test_report_structure(self, scanner, temp_contract):
        """Test report has correct structure"""
        code = '''
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Simple {
    uint256 public value;
}
'''
        path = temp_contract(code)
        try:
            report = scanner.scan(path)
            
            # Check metadata
            assert 'contract_name' in report['metadata']
            assert 'file_path' in report['metadata']
            assert 'scan_date' in report['metadata']
            assert 'scanner_version' in report['metadata']
            
            # Check summary
            assert 'total_issues' in report['summary']
            assert 'critical' in report['summary']
            assert 'high' in report['summary']
            assert 'medium' in report['summary']
            assert 'low' in report['summary']
            assert 'info' in report['summary']
            assert 'risk_score' in report['summary']
            assert 'risk_level' in report['summary']
            
            # Check vulnerability structure
            for vuln in report['vulnerabilities']:
                assert 'category' in vuln
                assert 'name' in vuln
                assert 'severity' in vuln
                assert 'line_number' in vuln
                assert 'description' in vuln
                assert 'recommendation' in vuln
        finally:
            os.unlink(path)
    
    def test_file_not_found(self, scanner):
        """Test handling of missing files"""
        with pytest.raises(FileNotFoundError):
            scanner.scan('/nonexistent/path/contract.sol')
    
    def test_empty_contract(self, scanner, temp_contract):
        """Test handling of minimal contract"""
        code = '''
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract Empty {}
'''
        path = temp_contract(code)
        try:
            report = scanner.scan(path)
            assert report['metadata']['contract_name'] == 'Empty'
        finally:
            os.unlink(path)


class TestVulnerabilityDataclass:
    """Test the Vulnerability dataclass"""
    
    def test_vulnerability_creation(self):
        """Test creating a vulnerability"""
        vuln = Vulnerability(
            category="Reentrancy",
            name="Classic Reentrancy",
            severity="Critical",
            confidence="High",
            line_number=10,
            code_snippet="msg.sender.call{value: amount}('')",
            description="External call before state update",
            impact="Fund drainage",
            recommendation="Use ReentrancyGuard"
        )
        
        assert vuln.category == "Reentrancy"
        assert vuln.severity == "Critical"
        assert vuln.line_number == 10
    
    def test_vulnerability_defaults(self):
        """Test vulnerability default values"""
        vuln = Vulnerability(
            category="Test",
            name="Test",
            severity="Low",
            confidence="Low",
            line_number=1,
            code_snippet="",
            description="",
            impact="",
            recommendation=""
        )
        
        assert vuln.owasp_category == ""
        assert vuln.cwe_id == ""
        assert vuln.references == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
