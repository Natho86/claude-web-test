#!/usr/bin/env python3
"""
Validate that our fixed MCS Connect Initial matches xfreerdp's working implementation
"""

import struct

# Import our RDP implementation
import sys
sys.path.insert(0, '/home/user/claude-web-test')
from rdp_screenshot import RDPScreenshot

# Working xfreerdp MCS Connect Initial (starting from MCS tag 0x7f65)
xfreerdp_mcs = bytes.fromhex("""
7f 65 82 01 b7 04 01
01 04 01 01 01 01 ff 30 1a 02 01 22 02 01 02 02
01 00 02 01 01 02 01 00 02 01 01 02 02 ff ff 02
01 02 30 19 02 01 01 02 01 01 02 01 01 02 01 01
02 01 00 02 01 01 02 02 04 20 02 01 02 30 1c 02
02 ff ff 02 02 fc 17 02 01 ff 02 01 01 02 01 00
02 01 01 02 02 ff ff 02 01 02
""".replace('\n', ''))

print("=" * 70)
print("VALIDATING MCS CONNECT INITIAL FIX")
print("=" * 70)

# Create RDP instance and generate MCS Connect Initial
rdp = RDPScreenshot("test", 3389)

# Get just the MCS portion (skip TPKT and X.224 headers)
full_packet = rdp.create_mcs_connect_initial()

# Skip TPKT (4 bytes) and X.224 (3 bytes: LI, Code, EOT)
our_mcs = full_packet[7:]

print(f"\n[Raw Headers]")
print(f"  TPKT:  {full_packet[0:4].hex()}")
print(f"  X.224: {full_packet[4:7].hex()}")
print(f"  MCS start: {full_packet[7:17].hex()}")

print(f"\n[Packet Lengths]")
print(f"  xfreerdp MCS length: {len(xfreerdp_mcs)} bytes")
print(f"  Our MCS length:      {len(our_mcs)} bytes")

# Compare the MCS Domain Parameters section (first ~100 bytes)
# This is the part we just fixed
domain_params_len = 100

print(f"\n[MCS Domain Parameters Comparison]")
print(f"  Comparing first {domain_params_len} bytes (MCS tag + domain parameters)...")

xf_domain = xfreerdp_mcs[:domain_params_len]
our_domain = our_mcs[:domain_params_len]

if xf_domain == our_domain:
    print(f"  ✓ MATCH! Domain parameters are identical")
else:
    print(f"  ✗ MISMATCH in domain parameters")
    print(f"\n  Byte-by-byte comparison:")
    for i in range(min(len(xf_domain), len(our_domain))):
        if xf_domain[i] != our_domain[i]:
            print(f"    Offset {i:3d}: xfreerdp=0x{xf_domain[i]:02x}  ours=0x{our_domain[i]:02x}  ← DIFFERENT")
        else:
            if i < 20 or i > min(len(xf_domain), len(our_domain)) - 10:
                print(f"    Offset {i:3d}: 0x{xf_domain[i]:02x}")

# Parse and compare specific values
def parse_mcs_params(data, offset):
    """Parse MCS Connect-Initial domain parameters"""
    params = {}

    # Skip tag (2 bytes) and length
    offset = 2
    if data[offset] & 0x80:
        num_octets = data[offset] & 0x7f
        offset += 1 + num_octets
    else:
        offset += 1

    # Skip callingDomainSelector (4 bytes)
    offset += 4
    # Skip calledDomainSelector (4 bytes)
    offset += 4
    # Skip upwardFlag (3 bytes)
    offset += 3

    # Parse targetParameters
    offset += 2  # SEQUENCE tag + length
    target_params = []
    for i in range(8):
        offset += 1  # INTEGER tag
        length = data[offset]
        offset += 1
        if length == 1:
            value = data[offset]
            offset += 1
        elif length == 2:
            value = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
        target_params.append(value)

    params['target'] = target_params

    # Parse minimumParameters
    offset += 2  # SEQUENCE tag + length
    min_params = []
    for i in range(8):
        offset += 1  # INTEGER tag
        length = data[offset]
        offset += 1
        if length == 1:
            value = data[offset]
            offset += 1
        elif length == 2:
            value = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
        min_params.append(value)

    params['minimum'] = min_params

    # Parse maximumParameters
    offset += 2  # SEQUENCE tag + length
    max_params = []
    for i in range(8):
        offset += 1  # INTEGER tag
        length = data[offset]
        offset += 1
        if length == 1:
            value = data[offset]
            offset += 1
        elif length == 2:
            value = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
        max_params.append(value)

    params['maximum'] = max_params

    return params

print(f"\n[Parsed Domain Parameters]")

xf_params = parse_mcs_params(xfreerdp_mcs, 0)
our_params = parse_mcs_params(our_mcs, 0)

param_names = [
    'maxChannelIds',
    'maxUserIds',
    'maxTokenIds',
    'numPriorities',
    'minThroughput',
    'maxHeight',
    'maxMCSPDUsize',
    'protocolVersion'
]

for param_type in ['target', 'minimum', 'maximum']:
    print(f"\n  {param_type}Parameters:")
    all_match = True
    for i, name in enumerate(param_names):
        xf_val = xf_params[param_type][i]
        our_val = our_params[param_type][i]
        match = "✓" if xf_val == our_val else "✗"
        status = "" if xf_val == our_val else " ← MISMATCH"
        print(f"    {match} {name:18s}: xfreerdp={xf_val:5d}  ours={our_val:5d}{status}")
        if xf_val != our_val:
            all_match = False

    if all_match:
        print(f"    ✓ All {param_type} parameters match!")

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)

if xf_domain == our_domain:
    print("\n✓ SUCCESS! MCS Domain Parameters match xfreerdp exactly.")
    print("  The fix is correct. The connection issues might be due to:")
    print("    1. GCC Conference Create Request encoding (Client Core Data, etc.)")
    print("    2. Network connectivity to test targets")
    print("    3. Other protocol-level issues")
else:
    print("\n✗ Domain parameters still don't match. Additional fixes needed.")

print("\n" + "=" * 70)
