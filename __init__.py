"""
Solidity Vulnerability Scanner - Community Edition

A comprehensive smart contract security scanner that detects
common vulnerability patterns based on industry standards.
"""

from .scanner import VulnerabilityScanner, Vulnerability

__version__ = "1.0.0"
__all__ = ["VulnerabilityScanner", "Vulnerability"]
