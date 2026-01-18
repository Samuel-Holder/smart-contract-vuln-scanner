# Contributing to Solidity Vulnerability Scanner

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Adding New Detectors](#adding-new-detectors)
- [Reporting Issues](#reporting-issues)
- [Pull Request Process](#pull-request-process)
- [Code Style](#code-style)

## Code of Conduct

This project follows a standard code of conduct:

- Be respectful and inclusive
- Provide constructive feedback
- Focus on the work, not the person
- Welcome newcomers

## Getting Started

### Prerequisites

- Python 3.8+
- Git
- Basic understanding of Solidity and smart contract security

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/solidity-scanner.git
cd solidity-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # For development

# Run tests
pytest tests/ -v
```

## How to Contribute

### Types of Contributions

1. **Bug Fixes** - Fix issues in existing detectors
2. **New Detectors** - Add detection for new vulnerability patterns
3. **Documentation** - Improve docs, add examples
4. **Test Cases** - Add test coverage
5. **False Positive Reports** - Help reduce noise

### Finding Work

- Check [Issues](../../issues) for `good first issue` labels
- Look for `help wanted` tags
- Review open PRs that need testing

## Adding New Detectors

New vulnerability detectors are the most impactful contributions. Here's how to add one:

### 1. Research the Vulnerability

Before coding, understand:

- What is the vulnerability pattern?
- What makes code vulnerable vs. safe?
- Are there real-world exploit examples?
- What's the severity and impact?

### 2. Create the Detector

Add your detector method to `src/scanner.py`:

```python
def _detect_your_vulnerability(self, lines: List[str]):
    """
    Detect [Vulnerability Name] - [Brief Description]
    
    Pattern: [Description of vulnerable pattern]
    OWASP: SC0X
    CWE: CWE-XXX
    """
    for i, line in enumerate(lines, 1):
        # Your detection logic here
        if vulnerable_pattern_found:
            self._add_vulnerability(
                category="Category Name",
                name="Vulnerability Name",
                severity="Critical|High|Medium|Low|Info",
                confidence="High|Medium|Low",
                line_number=i,
                code_snippet=line.strip(),
                description="What is wrong and why",
                impact="What an attacker could do",
                recommendation="How to fix it",
                owasp_category='SC0X',
                cwe_id='CWE-XXX',
                references=["https://..."]
            )
```

### 3. Add the Detector to Scan Flow

Call your detector in the `scan()` method:

```python
def scan(self, file_path: str) -> Dict:
    # ... existing code ...
    
    # Add your detector
    self._detect_your_vulnerability(lines)
    
    # ... rest of scan ...
```

### 4. Write Tests

Add tests in `tests/test_scanner.py`:

```python
def test_detects_your_vulnerability(self, scanner, temp_contract):
    """Test [vulnerability] detection"""
    code = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vulnerable {
    // Vulnerable code example
}
'''
    path = temp_contract(code)
    try:
        report = scanner.scan(path)
        vulns = [v for v in report['vulnerabilities'] 
                if v['name'] == 'Your Vulnerability Name']
        assert len(vulns) > 0
    finally:
        os.unlink(path)

def test_no_false_positive_for_safe_pattern(self, scanner, temp_contract):
    """Test safe pattern doesn't trigger"""
    code = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Safe {
    // Safe code example
}
'''
    path = temp_contract(code)
    try:
        report = scanner.scan(path)
        vulns = [v for v in report['vulnerabilities'] 
                if v['name'] == 'Your Vulnerability Name']
        assert len(vulns) == 0
    finally:
        os.unlink(path)
```

### 5. Document the Vulnerability

Add documentation to `docs/VULNERABILITIES.md`:

```markdown
## Your Vulnerability Name

**OWASP Category:** SC0X  
**CWE ID:** CWE-XXX  
**Severity:** High

### Description

[Detailed description]

### Vulnerable Pattern

```solidity
// VULNERABLE - explain why
contract Example {
    // vulnerable code
}
```

### Secure Pattern

```solidity
// SECURE - explain fix
contract Example {
    // fixed code
}
```

### Remediation

1. Step one
2. Step two
3. Step three

### References

- [Link 1](url)
- [Link 2](url)
```

### 6. Create Example Contract

Add an example to `examples/contracts/`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Example demonstrating [vulnerability]
contract VulnerableExample {
    // Vulnerable implementation
}

contract SecureExample {
    // Secure implementation
}
```

## Reporting Issues

### Bug Reports

Include:

- Scanner version
- Python version
- Minimal contract that reproduces the issue
- Expected vs actual behavior
- Full error message/stack trace

### False Positives

Include:

- Contract code flagged incorrectly
- Why it's a false positive
- Suggested fix for detection logic

### False Negatives

Include:

- Vulnerable contract code
- Expected vulnerability to detect
- Why current detection misses it

## Pull Request Process

### Before Submitting

1. Run all tests: `pytest tests/ -v`
2. Check code style: `flake8 src/`
3. Update documentation if needed
4. Add tests for new features

### PR Checklist

- [ ] Tests pass locally
- [ ] New code has tests
- [ ] Documentation updated
- [ ] No unnecessary dependencies
- [ ] Commits are clean and descriptive

### Review Process

1. Submit PR with clear description
2. Maintainer reviews within 1 week
3. Address feedback
4. Maintainer merges when approved

## Code Style

### Python

- Follow PEP 8
- Use type hints
- Write docstrings for functions
- Keep functions focused and small

```python
def _detect_example(self, lines: List[str]) -> None:
    """
    Detect example vulnerability pattern.
    
    Args:
        lines: Source code lines
        
    Note:
        This detects XYZ pattern which is vulnerable because...
    """
    for i, line in enumerate(lines, 1):
        # Detection logic
        pass
```

### Commits

- Use present tense: "Add feature" not "Added feature"
- Reference issues: "Fix #123: Add reentrancy detector"
- Keep commits atomic and focused

### Documentation

- Use clear, simple language
- Include code examples
- Link to external resources
- Keep formatting consistent

## Questions?

- Open a [Discussion](../../discussions)
- Check existing issues
- Read the documentation

Thank you for contributing to making smart contracts more secure! 🛡️
