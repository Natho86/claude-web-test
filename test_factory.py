#!/usr/bin/env python3
"""Test RDPConnectionFactory methods"""

from aardwolf.commons.factory import RDPConnectionFactory
from aardwolf.commons.iosettings import RDPIOSettings
import inspect

print("=== RDPConnectionFactory methods ===")
factory_methods = [m for m in dir(RDPConnectionFactory) if not m.startswith('_')]
print(f"Methods: {factory_methods}")

print("\n=== from_url signature ===")
print(f"from_url: {inspect.signature(RDPConnectionFactory.from_url)}")

# Check if there's a create_connection method
if hasattr(RDPConnectionFactory, 'create_connection'):
    print("\n✓ Has create_connection method")
    print(f"Signature: {inspect.signature(RDPConnectionFactory.create_connection)}")

if hasattr(RDPConnectionFactory, 'create_connection_newtarget'):
    print("\n✓ Has create_connection_newtarget method")
    print(f"Signature: {inspect.signature(RDPConnectionFactory.create_connection_newtarget)}")

print("\n=== Testing factory creation ===")
iosettings = RDPIOSettings()
url = "rdp+simple://172.16.20.191:3389"

try:
    factory = RDPConnectionFactory.from_url(url, iosettings)
    print(f"✓ Factory created: {factory}")
    print(f"Factory type: {type(factory)}")
    print(f"Factory attributes: {[x for x in dir(factory) if not x.startswith('_')]}")

    # Check what target the factory has
    if hasattr(factory, 'target'):
        print(f"\nFactory has target: {factory.target}")
        print(f"Target type: {type(factory.target)}")

    if hasattr(factory, 'credential'):
        print(f"\nFactory has credential: {factory.credential}")

except Exception as e:
    print(f"✗ Error creating factory: {e}")
    import traceback
    traceback.print_exc()
