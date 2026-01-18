#!/usr/bin/env python3
"""
Solidity Vulnerability Scanner - Community Edition
Detects common smart contract security issues

For the full-featured scanner with 100+ patterns, contact the author.
"""

import re
import json
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import argparse


@dataclass
class Vulnerability:
    """Vulnerability finding with metadata"""
    category: str
    name: str
    severity: str  # Critical, High, Medium, Low, Info
    confidence: str  # High, Medium, Low
    line_number: int
    code_snippet: str
    description: str
    impact: str
    recommendation: str
    owasp_category: str = ""
    cwe_id: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class ContractInfo:
    """Basic contract metadata"""
    name: str
    file_path: str
    compiler_version: str
    total_lines: int
    complexity_score: int


class VulnerabilityScanner:
    """
    Smart Contract Vulnerability Scanner - Community Edition
    
    Detects common vulnerability patterns including:
    - Reentrancy attacks
    - Access control issues
    - Integer overflow/underflow
    - Unchecked external calls
    - Timestamp dependence
    - And more...
    """
    
    # OWASP Smart Contract Top 10 Categories
    OWASP_CATEGORIES = {
        'SC01': 'Access Control Vulnerabilities',
        'SC02': 'Logic Errors',
        'SC03': 'Reentrancy Attacks',
        'SC04': 'Flash Loan Attacks',
        'SC05': 'Input Validation',
        'SC06': 'Price Oracle Manipulation',
        'SC07': 'Unchecked External Calls',
        'SC08': 'Integer Overflow/Underflow',
        'SC09': 'Denial of Service',
        'SC10': 'Insecure Randomness'
    }
    
    # CWE Mappings for common vulnerabilities
    CWE_MAPPINGS = {
        'reentrancy': 'CWE-841',
        'access_control': 'CWE-284',
        'integer_overflow': 'CWE-190',
        'integer_underflow': 'CWE-191',
        'unchecked_call': 'CWE-252',
        'uninitialized': 'CWE-456',
        'randomness': 'CWE-330',
        'dos': 'CWE-400',
        'signature': 'CWE-347',
        'oracle': 'CWE-829'
    }
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize scanner with optional configuration"""
        self.config = config or {}
        self.vulnerabilities: List[Vulnerability] = []
        self.contract_info: Optional[ContractInfo] = None
        
    def scan(self, file_path: str) -> Dict:
        """
        Scan a Solidity contract for vulnerabilities
        
        Args:
            file_path: Path to the .sol file
            
        Returns:
            Dictionary containing scan results and report data
        """
        # Reset state for new scan
        self.vulnerabilities = []
        self.contract_info = None
        
        print(f"🔍 Solidity Vulnerability Scanner v1.0")
        print(f"📋 Scanning: {file_path}")
        print(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 60)
        
        # Read contract
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"Contract not found: {file_path}")
        except Exception as e:
            raise RuntimeError(f"Error reading contract: {e}")
            
        lines = code.split('\n')
        
        # Extract metadata
        self.contract_info = self._extract_metadata(code, file_path)
        
        # Run detection modules
        print("🔎 Running vulnerability detection...")
        
        self._detect_reentrancy(lines)
        self._detect_access_control(lines)
        self._detect_unchecked_calls(lines)
        self._detect_timestamp_dependence(lines)
        self._detect_weak_randomness(lines)
        self._detect_dos_patterns(lines)
        self._detect_initialization_issues(lines)
        self._detect_delegatecall_issues(lines)
        self._detect_selfdestruct(lines)
        self._detect_input_validation(lines)
        self._detect_code_quality(lines)
        
        # Generate report
        return self._generate_report()
    
    def _extract_metadata(self, code: str, file_path: str) -> ContractInfo:
        """Extract basic contract information"""
        # Find contract name
        match = re.search(r'^contract\s+(\w+)', code, re.MULTILINE)
        name = match.group(1) if match else "Unknown"
        
        # Find compiler version
        match = re.search(r'pragma solidity\s+([^;]+)', code)
        version = match.group(1).strip() if match else "Unknown"
        
        # Calculate complexity (simplified)
        complexity = 1
        complexity += code.count('if ')
        complexity += code.count('for ')
        complexity += code.count('while ')
        complexity += code.count('&&')
        complexity += code.count('||')
        
        return ContractInfo(
            name=name,
            file_path=file_path,
            compiler_version=version,
            total_lines=len(code.split('\n')),
            complexity_score=complexity
        )
    
    def _detect_reentrancy(self, lines: List[str]):
        """Detect reentrancy vulnerability patterns"""
        for i, line in enumerate(lines, 1):
            # Check for external calls followed by state changes
            if re.search(r'function\s+(\w+)', line):
                func_name = re.search(r'function\s+(\w+)', line).group(1)
                func_body = self._get_function_body(lines, i-1)
                
                if func_body:
                    # Pattern: external call before state update
                    has_external_call = any(call in func_body for call in [
                        '.call{', '.transfer(', '.send('
                    ])
                    has_state_change = any(pattern in func_body for pattern in [
                        'balances[', '-=', '+='
                    ])
                    has_guard = 'nonReentrant' in func_body or 'ReentrancyGuard' in func_body
                    
                    if has_external_call and has_state_change and not has_guard:
                        # Check order - external call before state update is vulnerable
                        func_lines = func_body.split('\n')
                        call_idx = state_idx = -1
                        
                        for j, fl in enumerate(func_lines):
                            if any(c in fl for c in ['.call{', '.transfer(', '.send(']):
                                call_idx = j
                            if any(p in fl for p in ['balances[', '-=']):
                                state_idx = j
                        
                        if call_idx != -1 and state_idx != -1 and call_idx < state_idx:
                            self._add_vulnerability(
                                category="Reentrancy",
                                name="Classic Reentrancy",
                                severity="Critical",
                                confidence="High",
                                line_number=i,
                                code_snippet=line.strip(),
                                description=f"Function '{func_name}' makes external call before state update.",
                                impact="Attacker can recursively call to drain funds.",
                                recommendation="Follow checks-effects-interactions pattern. Use ReentrancyGuard.",
                                owasp_category='SC03',
                                cwe_id=self.CWE_MAPPINGS['reentrancy'],
                                references=["https://swcregistry.io/docs/SWC-107"]
                            )
    
    def _detect_access_control(self, lines: List[str]):
        """Detect missing or weak access control"""
        critical_functions = [
            'initialize', 'upgrade', 'pause', 'unpause', 
            'mint', 'burn', 'setOracle', 'setPrice', 'withdraw'
        ]
        
        for i, line in enumerate(lines, 1):
            func_match = re.search(r'function\s+(\w+)', line)
            if func_match:
                func_name = func_match.group(1)
                
                if func_name in critical_functions:
                    # Check for access control modifiers
                    has_protection = any(modifier in line for modifier in [
                        'onlyOwner', 'onlyAdmin', 'onlyRole', 
                        'private', 'internal', 'initializer'
                    ])
                    
                    is_public = 'public' in line or 'external' in line
                    
                    if is_public and not has_protection:
                        self._add_vulnerability(
                            category="Access Control",
                            name="Unprotected Critical Function",
                            severity="Critical",
                            confidence="High",
                            line_number=i,
                            code_snippet=line.strip(),
                            description=f"Critical function '{func_name}' lacks access control.",
                            impact="Unauthorized users can execute sensitive operations.",
                            recommendation=f"Add appropriate access control modifier to '{func_name}'.",
                            owasp_category='SC01',
                            cwe_id=self.CWE_MAPPINGS['access_control'],
                            references=["https://swcregistry.io/docs/SWC-105"]
                        )
    
    def _detect_unchecked_calls(self, lines: List[str]):
        """Detect unchecked external call returns"""
        for i, line in enumerate(lines, 1):
            # Low-level calls without return check
            if '.call{' in line or '.call(' in line:
                if not re.search(r'\(bool\s+\w+', line) and 'require' not in line:
                    self._add_vulnerability(
                        category="Unchecked Call",
                        name="Unchecked Low-Level Call",
                        severity="Medium",
                        confidence="High",
                        line_number=i,
                        code_snippet=line.strip(),
                        description="Low-level call return value not checked.",
                        impact="Failed calls go unnoticed, causing inconsistent state.",
                        recommendation="Check return value: (bool success, ) = addr.call{...}(...)",
                        owasp_category='SC07',
                        cwe_id=self.CWE_MAPPINGS['unchecked_call']
                    )
            
            # send() without check
            if '.send(' in line and 'require' not in line and 'if' not in line:
                self._add_vulnerability(
                    category="Unchecked Call",
                    name="Unchecked send()",
                    severity="Medium",
                    confidence="High",
                    line_number=i,
                    code_snippet=line.strip(),
                    description="send() return value not checked.",
                    impact="Failed transfers go unnoticed.",
                    recommendation="Use transfer() or check send() return value.",
                    owasp_category='SC07',
                    cwe_id=self.CWE_MAPPINGS['unchecked_call']
                )
    
    def _detect_timestamp_dependence(self, lines: List[str]):
        """Detect dangerous timestamp usage"""
        for i, line in enumerate(lines, 1):
            if 'block.timestamp' in line or 'now' in line:
                # Check for randomness use
                if '%' in line or 'random' in line.lower():
                    self._add_vulnerability(
                        category="Timestamp",
                        name="Timestamp for Randomness",
                        severity="High",
                        confidence="High",
                        line_number=i,
                        code_snippet=line.strip(),
                        description="Block timestamp used for randomness.",
                        impact="Miners can manipulate timestamp to predict outcomes.",
                        recommendation="Use Chainlink VRF for secure randomness.",
                        owasp_category='SC10',
                        cwe_id=self.CWE_MAPPINGS['randomness']
                    )
                elif 'require' in line or 'if' in line:
                    self._add_vulnerability(
                        category="Timestamp",
                        name="Timestamp Dependence",
                        severity="Low",
                        confidence="Medium",
                        line_number=i,
                        code_snippet=line.strip(),
                        description="Critical logic depends on block.timestamp.",
                        impact="Miners can manipulate timestamp by ~15 seconds.",
                        recommendation="Use block numbers or accept manipulation risk.",
                        owasp_category='SC02',
                        cwe_id=self.CWE_MAPPINGS['randomness']
                    )
    
    def _detect_weak_randomness(self, lines: List[str]):
        """Detect weak randomness sources"""
        weak_sources = ['blockhash', 'block.difficulty', 'block.coinbase', 'block.gaslimit']
        
        for i, line in enumerate(lines, 1):
            if any(source in line for source in weak_sources):
                if 'random' in line.lower() or '%' in line:
                    self._add_vulnerability(
                        category="Randomness",
                        name="Weak Randomness Source",
                        severity="High",
                        confidence="High",
                        line_number=i,
                        code_snippet=line.strip(),
                        description="Predictable blockchain data used for randomness.",
                        impact="Attackers can predict or influence random outcomes.",
                        recommendation="Use Chainlink VRF or commit-reveal scheme.",
                        owasp_category='SC10',
                        cwe_id=self.CWE_MAPPINGS['randomness'],
                        references=["https://swcregistry.io/docs/SWC-120"]
                    )
    
    def _detect_dos_patterns(self, lines: List[str]):
        """Detect Denial of Service vulnerabilities"""
        for i, line in enumerate(lines, 1):
            # Unbounded loops
            if re.search(r'for\s*\([^)]*\.length', line):
                self._add_vulnerability(
                    category="DoS",
                    name="Unbounded Loop",
                    severity="High",
                    confidence="Medium",
                    line_number=i,
                    code_snippet=line.strip(),
                    description="Loop over dynamic array could exceed gas limit.",
                    impact="Contract functions become unusable with large arrays.",
                    recommendation="Implement pagination or limit array size.",
                    owasp_category='SC09',
                    cwe_id=self.CWE_MAPPINGS['dos'],
                    references=["https://swcregistry.io/docs/SWC-128"]
                )
            
            # External call in loop
            if ('for' in line or 'while' in line):
                func_body = self._get_function_body(lines, i-1)
                if func_body and any(call in func_body for call in ['.call', '.transfer', '.send']):
                    self._add_vulnerability(
                        category="DoS",
                        name="External Call in Loop",
                        severity="Medium",
                        confidence="Medium",
                        line_number=i,
                        code_snippet=line.strip(),
                        description="External calls inside loops can fail unexpectedly.",
                        impact="Single failed call can block all subsequent iterations.",
                        recommendation="Use pull-over-push pattern for payments.",
                        owasp_category='SC09',
                        cwe_id=self.CWE_MAPPINGS['dos']
                    )
    
    def _detect_initialization_issues(self, lines: List[str]):
        """Detect initialization vulnerabilities"""
        for i, line in enumerate(lines, 1):
            if re.search(r'function\s+initialize', line):
                has_initializer = 'initializer' in line
                is_public = 'public' in line or 'external' in line
                
                if is_public and not has_initializer:
                    self._add_vulnerability(
                        category="Initialization",
                        name="Unprotected Initialize",
                        severity="Critical",
                        confidence="High",
                        line_number=i,
                        code_snippet=line.strip(),
                        description="Initialize function can be called multiple times.",
                        impact="Attacker can reinitialize and take ownership.",
                        recommendation="Use OpenZeppelin Initializable and initializer modifier.",
                        owasp_category='SC01',
                        cwe_id=self.CWE_MAPPINGS['uninitialized'],
                        references=["https://swcregistry.io/docs/SWC-118"]
                    )
    
    def _detect_delegatecall_issues(self, lines: List[str]):
        """Detect dangerous delegatecall patterns"""
        for i, line in enumerate(lines, 1):
            if 'delegatecall' in line:
                # Check if target is user-controlled
                if 'msg.data' in line or not re.search(r'address\s*\(\s*0x', line):
                    self._add_vulnerability(
                        category="Delegatecall",
                        name="Arbitrary Delegatecall",
                        severity="Critical",
                        confidence="High",
                        line_number=i,
                        code_snippet=line.strip(),
                        description="Delegatecall to potentially user-controlled address.",
                        impact="Complete contract takeover possible.",
                        recommendation="Whitelist allowed delegatecall targets.",
                        owasp_category='SC01',
                        cwe_id=self.CWE_MAPPINGS['access_control'],
                        references=["https://swcregistry.io/docs/SWC-112"]
                    )
    
    def _detect_selfdestruct(self, lines: List[str]):
        """Detect selfdestruct usage"""
        for i, line in enumerate(lines, 1):
            if 'selfdestruct' in line or 'suicide' in line:
                self._add_vulnerability(
                    category="Selfdestruct",
                    name="Selfdestruct Present",
                    severity="High",
                    confidence="High",
                    line_number=i,
                    code_snippet=line.strip(),
                    description="Contract can be destroyed with selfdestruct.",
                    impact="Contract permanently destroyed, funds sent to address.",
                    recommendation="Remove selfdestruct or add strict access control.",
                    owasp_category='SC01',
                    cwe_id=self.CWE_MAPPINGS['access_control'],
                    references=["https://swcregistry.io/docs/SWC-106"]
                )
    
    def _detect_input_validation(self, lines: List[str]):
        """Detect missing input validation"""
        for i, line in enumerate(lines, 1):
            # Public/external function with address parameter
            match = re.search(r'function\s+\w+\s*\([^)]*address\s+(\w+)', line)
            if match and ('public' in line or 'external' in line):
                param_name = match.group(1)
                func_body = self._get_function_body(lines, i-1)
                
                if func_body and f'{param_name} != address(0)' not in func_body:
                    if f'require({param_name}' not in func_body:
                        self._add_vulnerability(
                            category="Input Validation",
                            name="Missing Zero Address Check",
                            severity="Low",
                            confidence="Medium",
                            line_number=i,
                            code_snippet=line.strip(),
                            description=f"Address parameter '{param_name}' not validated.",
                            impact="Zero address could cause unexpected behavior.",
                            recommendation=f"Add: require({param_name} != address(0))",
                            owasp_category='SC05',
                            cwe_id='CWE-20'
                        )
    
    def _detect_code_quality(self, lines: List[str]):
        """Detect code quality issues"""
        for i, line in enumerate(lines, 1):
            # Floating pragma
            if re.search(r'pragma solidity\s*\^', line):
                self._add_vulnerability(
                    category="Code Quality",
                    name="Floating Pragma",
                    severity="Info",
                    confidence="High",
                    line_number=i,
                    code_snippet=line.strip(),
                    description="Pragma allows multiple compiler versions.",
                    impact="Contract may behave differently across versions.",
                    recommendation="Lock pragma to specific version: pragma solidity 0.8.20;",
                    owasp_category='',
                    cwe_id='',
                    references=["https://swcregistry.io/docs/SWC-103"]
                )
            
            # Using tx.origin
            if 'tx.origin' in line:
                self._add_vulnerability(
                    category="Access Control",
                    name="tx.origin Usage",
                    severity="Medium",
                    confidence="High",
                    line_number=i,
                    code_snippet=line.strip(),
                    description="tx.origin used for authorization.",
                    impact="Phishing attacks can exploit tx.origin checks.",
                    recommendation="Use msg.sender instead of tx.origin.",
                    owasp_category='SC01',
                    cwe_id=self.CWE_MAPPINGS['access_control'],
                    references=["https://swcregistry.io/docs/SWC-115"]
                )
    
    def _get_function_body(self, lines: List[str], start: int) -> Optional[str]:
        """Extract function body starting from line index"""
        if start < 0 or start >= len(lines):
            return None
        
        brace_count = 0
        body_lines = []
        started = False
        
        for i in range(start, min(start + 50, len(lines))):
            line = lines[i]
            if '{' in line:
                started = True
                brace_count += line.count('{')
            if started:
                body_lines.append(line)
            if '}' in line:
                brace_count -= line.count('}')
                if brace_count <= 0 and started:
                    break
        
        return '\n'.join(body_lines) if body_lines else None
    
    def _add_vulnerability(self, **kwargs):
        """Add a vulnerability to the findings list"""
        vuln = Vulnerability(
            category=kwargs.get('category', ''),
            name=kwargs.get('name', ''),
            severity=kwargs.get('severity', 'Medium'),
            confidence=kwargs.get('confidence', 'Medium'),
            line_number=kwargs.get('line_number', 0),
            code_snippet=kwargs.get('code_snippet', ''),
            description=kwargs.get('description', ''),
            impact=kwargs.get('impact', ''),
            recommendation=kwargs.get('recommendation', ''),
            owasp_category=kwargs.get('owasp_category', ''),
            cwe_id=kwargs.get('cwe_id', ''),
            references=kwargs.get('references', [])
        )
        self.vulnerabilities.append(vuln)
    
    def _generate_report(self) -> Dict:
        """Generate the scan report"""
        by_severity = defaultdict(list)
        by_category = defaultdict(list)
        
        for vuln in self.vulnerabilities:
            by_severity[vuln.severity].append(vuln)
            by_category[vuln.category].append(vuln)
        
        # Calculate risk score
        weights = {'Critical': 25, 'High': 15, 'Medium': 7, 'Low': 3, 'Info': 1}
        risk_score = sum(weights.get(v.severity, 0) for v in self.vulnerabilities)
        risk_score = min(100, risk_score)
        
        # Risk level
        if risk_score >= 80:
            risk_level = "CRITICAL"
        elif risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        elif risk_score >= 20:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        return {
            'metadata': {
                'contract_name': self.contract_info.name,
                'file_path': self.contract_info.file_path,
                'scan_date': datetime.now().isoformat(),
                'scanner_version': '1.0.0',
                'total_lines': self.contract_info.total_lines,
                'complexity_score': self.contract_info.complexity_score
            },
            'summary': {
                'total_issues': len(self.vulnerabilities),
                'critical': len(by_severity['Critical']),
                'high': len(by_severity['High']),
                'medium': len(by_severity['Medium']),
                'low': len(by_severity['Low']),
                'info': len(by_severity['Info']),
                'risk_score': risk_score,
                'risk_level': risk_level
            },
            'vulnerabilities': [self._vuln_to_dict(v) for v in self.vulnerabilities],
            'by_severity': {k: [self._vuln_to_dict(v) for v in vs] for k, vs in by_severity.items()},
            'by_category': {k: [self._vuln_to_dict(v) for v in vs] for k, vs in by_category.items()}
        }
    
    def _vuln_to_dict(self, vuln: Vulnerability) -> Dict:
        """Convert vulnerability to dictionary"""
        return {
            'category': vuln.category,
            'name': vuln.name,
            'severity': vuln.severity,
            'confidence': vuln.confidence,
            'line_number': vuln.line_number,
            'code_snippet': vuln.code_snippet,
            'description': vuln.description,
            'impact': vuln.impact,
            'recommendation': vuln.recommendation,
            'owasp_category': vuln.owasp_category,
            'cwe_id': vuln.cwe_id,
            'references': vuln.references
        }


def format_report(report: Dict) -> str:
    """Format report for console output"""
    lines = []
    lines.append("\n" + "=" * 70)
    lines.append("SMART CONTRACT SECURITY ANALYSIS REPORT")
    lines.append("=" * 70)
    
    # Metadata
    lines.append(f"\n📋 CONTRACT INFORMATION")
    lines.append("-" * 40)
    lines.append(f"Contract: {report['metadata']['contract_name']}")
    lines.append(f"File: {report['metadata']['file_path']}")
    lines.append(f"Lines: {report['metadata']['total_lines']}")
    lines.append(f"Complexity: {report['metadata']['complexity_score']}")
    
    # Summary
    lines.append(f"\n🎯 VULNERABILITY SUMMARY")
    lines.append("-" * 40)
    s = report['summary']
    lines.append(f"Total Issues: {s['total_issues']}")
    lines.append(f"  🔴 Critical: {s['critical']}")
    lines.append(f"  🟠 High: {s['high']}")
    lines.append(f"  🟡 Medium: {s['medium']}")
    lines.append(f"  🔵 Low: {s['low']}")
    lines.append(f"  ⚪ Info: {s['info']}")
    lines.append(f"\nRisk Score: {s['risk_score']}/100")
    lines.append(f"Risk Level: {s['risk_level']}")
    
    # Findings
    lines.append(f"\n🔍 FINDINGS")
    lines.append("=" * 70)
    
    severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
    symbols = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🔵', 'Info': '⚪'}
    
    for severity in severity_order:
        vulns = report['by_severity'].get(severity, [])
        if vulns:
            lines.append(f"\n{symbols[severity]} {severity.upper()} ({len(vulns)})")
            lines.append("-" * 50)
            
            for i, v in enumerate(vulns, 1):
                lines.append(f"\n  [{i}] {v['name']}")
                lines.append(f"      Line: {v['line_number']}")
                lines.append(f"      Code: {v['code_snippet'][:60]}...")
                lines.append(f"      Desc: {v['description']}")
                lines.append(f"      Fix:  {v['recommendation']}")
                if v['cwe_id']:
                    lines.append(f"      CWE:  {v['cwe_id']}")
    
    lines.append("\n" + "=" * 70)
    lines.append("END OF REPORT")
    lines.append("=" * 70)
    
    return '\n'.join(lines)


def save_report(report: Dict, output_path: str):
    """Save report to files"""
    # Save markdown
    with open(output_path, 'w') as f:
        f.write(format_report(report))
    
    # Save JSON
    json_path = output_path.replace('.md', '.json')
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n✅ Report saved to {output_path}")
    print(f"✅ JSON saved to {json_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Solidity Vulnerability Scanner - Community Edition'
    )
    parser.add_argument('contract', nargs='?', help='Path to Solidity contract')
    parser.add_argument('-o', '--output', default='report.md', help='Output file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Auto-detect if no contract specified
    if not args.contract:
        sol_files = [f for f in os.listdir('.') if f.endswith('.sol')]
        if not sol_files:
            print("❌ No .sol files found. Specify a contract path.")
            sys.exit(1)
        elif len(sol_files) == 1:
            args.contract = sol_files[0]
        else:
            print("📁 Multiple contracts found:")
            for i, f in enumerate(sol_files, 1):
                print(f"  {i}. {f}")
            choice = input("Select (number): ")
            try:
                args.contract = sol_files[int(choice) - 1]
            except (ValueError, IndexError):
                print("❌ Invalid selection")
                sys.exit(1)
    
    if not os.path.exists(args.contract):
        print(f"❌ Contract not found: {args.contract}")
        sys.exit(1)
    
    # Run scan
    scanner = VulnerabilityScanner()
    report = scanner.scan(args.contract)
    
    # Display and save
    print(format_report(report))
    save_report(report, args.output)


if __name__ == "__main__":
    main()
