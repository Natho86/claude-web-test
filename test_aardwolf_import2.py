#!/usr/bin/env python3
"""Test aardwolf imports - Part 2: Find the right classes"""

print("=== Exploring aardwolf.connection ===")
try:
    from aardwolf import connection
    print(f"Contents: {dir(connection)}")

    # Try to find RDPConnection or similar
    if hasattr(connection, 'RDPConnection'):
        print("✓ Found RDPConnection")
    if hasattr(connection, 'RDPConnectionURL'):
        print("✓ Found RDPConnectionURL")
        from aardwolf.connection import RDPConnectionURL
        print(f"  RDPConnectionURL: {RDPConnectionURL}")
except Exception as e:
    print(f"Error: {e}")

print("\n=== Exploring aardwolf.commons ===")
try:
    from aardwolf import commons
    print(f"Contents: {dir(commons)}")

    # Check submodules
    if hasattr(commons, 'iosettings'):
        print("✓ Found commons.iosettings")
        from aardwolf.commons.iosettings import RDPIOSettings
        print(f"  RDPIOSettings: {RDPIOSettings}")
except Exception as e:
    print(f"Error: {e}")

print("\n=== Looking for client/connection classes ===")
try:
    # Try different possible locations
    locations = [
        'aardwolf.connection',
        'aardwolf.protocol',
        'aardwolf.network',
    ]

    for loc in locations:
        try:
            mod = __import__(loc, fromlist=[''])
            print(f"\n{loc}:")
            relevant = [x for x in dir(mod) if 'RDP' in x or 'Client' in x or 'Connection' in x]
            print(f"  Relevant classes: {relevant}")
        except:
            pass

except Exception as e:
    print(f"Error: {e}")

print("\n=== Checking examples/documentation ===")
try:
    # Sometimes packages have examples
    import aardwolf
    import os
    pkg_dir = os.path.dirname(aardwolf.__file__)
    print(f"Package directory: {pkg_dir}")

    # Look for examples or __main__
    if os.path.exists(os.path.join(pkg_dir, '__main__.py')):
        print("Found __main__.py - might have usage examples")

except Exception as e:
    print(f"Error: {e}")
