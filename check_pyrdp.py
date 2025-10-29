#!/usr/bin/env python3
"""
Test if pyrdp library works better for RDP screenshots
"""

import sys

try:
    # Check if pyrdp is available
    import pyrdp
    print(f"✓ pyrdp found (version: {pyrdp.__version__ if hasattr(pyrdp, '__version__') else 'unknown'})")
    print("\nInstallation: pip install pyrdp")
    print("\nNote: pyrdp is primarily a RDP proxy/MITM tool,")
    print("      but has solid RDP protocol implementation")
except ImportError:
    print("✗ pyrdp not found")
    print("\nInstall with: pip install pyrdp")
    print("\nAlternative libraries to try:")
    print("  - rdpy: pip install rdpy3")
    print("  - twisted-based RDP implementations")
    sys.exit(1)
