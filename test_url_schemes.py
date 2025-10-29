#!/usr/bin/env python3
"""Test different RDP URL schemes and parameters"""

from aardwolf.commons.factory import RDPConnectionFactory
from aardwolf.commons.iosettings import RDPIOSettings

iosettings = RDPIOSettings()

# Test different URL formats
urls = [
    "rdp+simple://172.16.20.191:3389",
    "rdp+tls://172.16.20.191:3389",
    "rdp+ssl://172.16.20.191:3389",
    "rdp+ntlm://172.16.20.191:3389",
    "rdp://172.16.20.191:3389",
]

print("=== Testing different URL schemes ===\n")
for url in urls:
    try:
        print(f"URL: {url}")
        factory = RDPConnectionFactory.from_url(url, iosettings)
        print(f"  ✓ Factory created")
        print(f"  Target dialect: {factory.target.dialect}")
        print(f"  Target protocol: {factory.target.protocol}")
        print(f"  Unsafe SSL: {factory.target.unsafe_ssl}")
        print()
    except Exception as e:
        print(f"  ✗ Error: {e}\n")

print("\n=== Testing URL with parameters ===")
# Try with query parameters
param_urls = [
    "rdp+simple://172.16.20.191:3389?timeout=15",
    "rdp+simple://172.16.20.191:3389?ssl=true",
    "rdp+simple://172.16.20.191:3389?tls=true",
]

for url in param_urls:
    try:
        print(f"URL: {url}")
        factory = RDPConnectionFactory.from_url(url, iosettings)
        print(f"  ✓ Factory created")
        print(f"  Target: {factory.target}")
        print()
    except Exception as e:
        print(f"  ✗ Error: {e}\n")

print("\n=== Checking RDPTarget.from_url directly ===")
from aardwolf.commons.target import RDPTarget
import inspect

print(f"RDPTarget.from_url signature: {inspect.signature(RDPTarget.from_url)}")

# Check the source or documentation
if hasattr(RDPTarget.from_url, '__doc__'):
    print(f"Documentation: {RDPTarget.from_url.__doc__}")
