#!/usr/bin/env python3
"""Test get_connection method"""

from aardwolf.commons.factory import RDPConnectionFactory
from aardwolf.commons.iosettings import RDPIOSettings
import inspect

print("=== Testing get_connection ===")
iosettings = RDPIOSettings()
url = "rdp+simple://172.16.20.191:3389"

factory = RDPConnectionFactory.from_url(url, iosettings)
print(f"Factory created with target: {factory.target.ip}")

print("\n=== get_connection signature ===")
print(f"Signature: {inspect.signature(factory.get_connection)}")

print("\n=== Attempting to create connection ===")
try:
    connection = factory.get_connection()
    print(f"✓ Connection created: {connection}")
    print(f"Connection type: {type(connection)}")
    print(f"Connection methods: {[x for x in dir(connection) if not x.startswith('_') and callable(getattr(connection, x))][:20]}")
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()

print("\n=== Checking create_connection_newtarget ===")
print(f"Signature: {inspect.signature(factory.create_connection_newtarget)}")
print("Parameter 1 should be: ip_or_hostname (string)")
print("Parameter 2 should be: iosettings")

# Try it correctly
print("\n=== Testing create_connection_newtarget with IP string ===")
try:
    connection2 = factory.create_connection_newtarget("172.16.20.191", iosettings)
    print(f"✓ Connection created: {connection2}")
except Exception as e:
    print(f"✗ Error: {e}")
