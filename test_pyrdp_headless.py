#!/usr/bin/env python3
"""
Test if pyrdp can work for headless RDP screenshots
pyrdp is designed for MITM/proxy but has a solid RDP client implementation
"""

import sys

try:
    import pyrdp
    print(f"✓ pyrdp available")

    # Check what's available in pyrdp
    print("\nAvailable modules:")
    print(f"  - pyrdp.core: {hasattr(pyrdp, 'core')}")
    print(f"  - pyrdp.player: {hasattr(pyrdp, 'player')}")
    print(f"  - pyrdp.mitm: {hasattr(pyrdp, 'mitm')}")

    # Try to import client components
    try:
        from pyrdp.core import Observer
        print("  ✓ Can import Observer")
    except:
        pass

    try:
        from pyrdp.player import RDPPlayerMessageHandler
        print("  ✓ Can import RDPPlayerMessageHandler")
    except:
        pass

    print("\nNote: pyrdp may work for screenshots but requires more investigation")
    print("Install: pip install pyrdp")

except ImportError:
    print("✗ pyrdp not available")
    print("\nInstall with: pip install pyrdp")
    print("\nAlternatives:")
    print("  1. Fix our manual MCS implementation")
    print("  2. Use rdpy library: pip install rdpy3")
    print("  3. Capture working xfreerdp packets and replicate")
