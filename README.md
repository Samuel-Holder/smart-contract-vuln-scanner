# 🛡️ Solidity Vulnerability Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.x-363636.svg)](https://docs.soliditylang.org/)

A comprehensive smart contract vulnerability scanner that detects security issues based on the latest research and real-world exploits. Built for developers, auditors, and security researchers.

## ✨ Features

- **50+ Vulnerability Patterns** - Covers OWASP Smart Contract Top 10
- **DeFi-Focused Detection** - Flash loan attacks, oracle manipulation, MEV vectors
- **Detailed Reports** - Markdown and JSON output with remediation guidance
- **CWE Mappings** - Industry-standard vulnerability classifications
- **Low False Positives** - Context-aware analysis reduces noise

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/solidity-scanner.git
cd solidity-scanner

# Scan a contract
python main.py contracts/VulnerableVault.sol

# Generate detailed report
python main.py contracts/VulnerableVault.sol -o report.md
```

## 📋 Detected Vulnerabilities

### Critical Severity
| Vulnerability | Description | OWASP |
|--------------|-------------|-------|
| Reentrancy | External calls before state updates | SC03 |
| Unprotected Initialize | Missing initializer modifier | SC01 |
| Arbitrary Delegatecall | User-controlled delegatecall targets | SC01 |
| Access Control Missing | Critical functions without protection | SC01 |

### High Severity
| Vulnerability | Description | OWASP |
|--------------|-------------|-------|
| Flash Loan Attacks | Unprotected flash loan callbacks | SC04 |
| Oracle Manipulation | Single oracle source dependency | SC06 |
| Integer Overflow | Arithmetic without SafeMath (<0.8) | SC08 |
| Weak Randomness | Predictable block-based randomness | SC10 |

### Medium Severity
| Vulnerability | Description | OWASP |
|--------------|-------------|-------|
| Timestamp Dependence | Block timestamp for critical logic | SC02 |
| Unchecked Calls | Missing return value checks | SC07 |
| DoS Vulnerabilities | Unbounded loops, gas griefing | SC09 |
| Front-running | Missing slippage protection | SC04 |

## 📊 Sample Output

```
================================================================================
SMART CONTRACT SECURITY ANALYSIS REPORT
================================================================================

📋 CONTRACT INFORMATION
----------------------------------------
Contract: VulnerableVault
Lines of Code: 156
Complexity Score: 23

🎯 VULNERABILITY SUMMARY
----------------------------------------
Total Issues Found: 8
  🔴 Critical: 2
  🟠 High: 3
  🟡 Medium: 2
  🔵 Low: 1

Risk Score: 67/100
Risk Level: HIGH
```

## 📁 Project Structure

```
solidity-scanner/
├── main.py             # Entry point - run this
├── README.md
├── LICENSE
├── requirements.txt
├── pytest.ini
├── src/
│   ├── __init__.py
│   └── scanner.py      # Main scanner logic
├── tests/
│   ├── __init__.py
│   └── test_scanner.py # Unit tests
├── contracts/          # Example contracts
│   ├── VulnerableVault.sol
│   └── SecureVault.sol
└── docs/
    ├── VULNERABILITIES.md
    └── CONTRIBUTING.md
```

## 🧪 Running Tests

```bash
# Install test dependencies
pip install -r requirements-dev.txt

# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=src --cov-report=html
```

## 📖 Documentation

- [Vulnerability Reference](docs/VULNERABILITIES.md) - Detailed explanations of each vulnerability
- [Contributing Guide](docs/CONTRIBUTING.md) - How to contribute new detectors

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](docs/CONTRIBUTING.md) for details on:

- Adding new vulnerability detectors
- Improving detection accuracy
- Reporting false positives/negatives
- Documentation improvements

## ⚠️ Disclaimer

This scanner is a security tool to assist in identifying potential vulnerabilities. It should not be the only security measure used:

- **Not a replacement for professional audits**
- **May produce false positives/negatives**
- **Always verify findings manually**
- **Use in combination with other tools**

## 📜 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [OWASP Smart Contract Top 10](https://owasp.org/www-project-smart-contract-top-10/)
- [SWC Registry](https://swcregistry.io/)
- [Damn Vulnerable DeFi](https://www.damnvulnerabledefi.xyz/)

---

**Built with ❤️ by Raven Tech Solutions Ltd**
