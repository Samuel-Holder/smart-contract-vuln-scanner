#!/usr/bin/env python3
"""
Solidity Vulnerability Scanner - Main Entry Point

Usage:
    python main.py <contract.sol>
    python main.py <contract.sol> -o report.md
    python main.py --help

Examples:
    python main.py examples/contracts/VulnerableVault.sol
    python main.py examples/contracts/VulnerableVault.sol -o audit_report.md -v
"""

import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from scanner import main

if __name__ == "__main__":
    main()
