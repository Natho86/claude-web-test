#!/usr/bin/env python3
"""Test aardwolf usage - understand how to create connections"""

print("=== Checking RDPConnection signature ===")
from aardwolf.connection import RDPConnection, RDPTarget
from aardwolf.commons.iosettings import RDPIOSettings
import inspect

print(f"RDPConnection: {RDPConnection}")
print(f"RDPConnection signature: {inspect.signature(RDPConnection.__init__)}")

print(f"\nRDPTarget: {RDPTarget}")
print(f"RDPTarget signature: {inspect.signature(RDPTarget.__init__)}")

print(f"\nRDPIOSettings: {RDPIOSettings}")
print(f"RDPIOSettings signature: {inspect.signature(RDPIOSettings.__init__)}")

# Check for class methods
print("\n=== RDPConnection methods ===")
methods = [m for m in dir(RDPConnection) if not m.startswith('_') and callable(getattr(RDPConnection, m))]
print(f"Public methods: {methods[:20]}")  # First 20

print("\n=== RDPTarget methods/attributes ===")
attrs = [m for m in dir(RDPTarget) if not m.startswith('_')]
print(f"Public attributes: {attrs[:20]}")

# Check if there's a from_url or similar
if hasattr(RDPTarget, 'from_url'):
    print("\n✓ RDPTarget has 'from_url' method")
    print(f"  Signature: {inspect.signature(RDPTarget.from_url)}")

if hasattr(RDPTarget, '__init__'):
    init_params = inspect.signature(RDPTarget.__init__).parameters
    print(f"\nRDPTarget.__init__ parameters: {list(init_params.keys())}")

print("\n=== Checking commons.target ===")
try:
    from aardwolf.commons.target import RDPTarget as RDPTarget2
    print(f"Found RDPTarget in commons.target: {RDPTarget2}")
    print(f"Signature: {inspect.signature(RDPTarget2.__init__)}")

    # Check for from_url
    if hasattr(RDPTarget2, 'from_url'):
        print("✓ commons.target.RDPTarget has 'from_url'")
        print(f"  Signature: {inspect.signature(RDPTarget2.from_url)}")
except ImportError as e:
    print(f"Could not import from commons.target: {e}")

print("\n=== Looking for URL parsing ===")
# Sometimes there's a URL module
try:
    from aardwolf.commons import target
    print(f"commons.target contents: {[x for x in dir(target) if not x.startswith('_')]}")
except:
    pass

print("\n=== Checking for amain (async main) ===")
from aardwolf.connection import amain
print(f"amain function found: {amain}")
print(f"amain signature: {inspect.signature(amain)}")
