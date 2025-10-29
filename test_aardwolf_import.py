#!/usr/bin/env python3
"""Test aardwolf imports to see exact error"""

print("Testing aardwolf imports...")

try:
    import aardwolf
    print(f"✓ aardwolf imported (version: {aardwolf.__version__ if hasattr(aardwolf, '__version__') else 'unknown'})")
except ImportError as e:
    print(f"✗ Cannot import aardwolf: {e}")
    exit(1)

try:
    from aardwolf.commons.url import RDPConnectionURL
    print("✓ RDPConnectionURL imported")
except ImportError as e:
    print(f"✗ Cannot import RDPConnectionURL: {e}")
    print("\nTrying alternative import paths...")
    try:
        from aardwolf.connection import RDPConnectionURL
        print("✓ Found RDPConnectionURL at aardwolf.connection")
    except:
        pass
    try:
        from aardwolf import RDPConnectionURL
        print("✓ Found RDPConnectionURL at aardwolf")
    except:
        pass

try:
    from aardwolf.commons.iosettings import RDPIOSettings
    print("✓ RDPIOSettings imported")
except ImportError as e:
    print(f"✗ Cannot import RDPIOSettings: {e}")

try:
    from aardwolf.client import RDPClient
    print("✓ RDPClient imported")
except ImportError as e:
    print(f"✗ Cannot import RDPClient: {e}")

print("\n--- Exploring aardwolf module structure ---")
import aardwolf
print(f"aardwolf location: {aardwolf.__file__}")
print(f"aardwolf contents: {dir(aardwolf)}")

# Try to find what's available
import pkgutil
print("\naardwolf submodules:")
for importer, modname, ispkg in pkgutil.walk_packages(path=aardwolf.__path__, prefix=aardwolf.__name__+'.'):
    print(f"  {modname}")
