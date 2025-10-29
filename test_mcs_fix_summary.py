#!/usr/bin/env python3
"""
Quick test to show the MCS Domain Parameters fix is correct
"""

import sys
sys.path.insert(0, '/home/user/claude-web-test')
from rdp_screenshot import RDPScreenshot

# Working xfreerdp domain parameters portion (just the domain params, not full packet)
xfreerdp_domain_params = bytes.fromhex("""
7f 65 82 01 b7 04 01
01 04 01 01 01 01 ff 30 1a 02 01 22 02 01 02 02
01 00 02 01 01 02 01 00 02 01 01 02 02 ff ff 02
01 02 30 19 02 01 01 02 01 01 02 01 01 02 01 01
02 01 00 02 01 01 02 02 04 20 02 01 02 30 1c 02
02 ff ff 02 02 fc 17 02 01 ff 02 01 01 02 01 00
02 01 01 02 02 ff ff 02 01 02
""".replace('\n', ''))

# Generate our MCS Connect Initial
rdp = RDPScreenshot("test", 3389)
full_packet = rdp.create_mcs_connect_initial()
our_mcs = full_packet[7:]  # Skip TPKT + X.224

print("=" * 70)
print("MCS DOMAIN PARAMETERS FIX - VALIDATION")
print("=" * 70)

# Extract just the domain parameters portion (skip length differences)
# Compare bytes 0-96 (MCS tag through end of maximumParameters)
domain_params_end = 97

xf_params = xfreerdp_domain_params[:domain_params_end]
our_params = our_mcs[:domain_params_end]

print(f"\nComparing MCS Domain Parameters:")
print(f"  xfreerdp: {len(xf_params)} bytes")
print(f"  ours:     {len(our_params)} bytes")

# Check byte-by-byte, ignoring the length field
match_count = 0
mismatch_count = 0
length_field_mismatch = False

for i in range(min(len(xf_params), len(our_params))):
    if xf_params[i] != our_params[i]:
        # Bytes 4-5 (or 4-6 depending on encoding) are the length field
        if i == 4:
            length_field_mismatch = True
            print(f"\n  Byte {i}: Length field differs (expected - contains client data)")
        elif i >= 5:
            # After length field, everything should match
            mismatch_count += 1
            if mismatch_count <= 5:  # Show first 5 mismatches
                print(f"  Byte {i}: xfreerdp=0x{xf_params[i]:02x} ours=0x{our_params[i]:02x} ← MISMATCH")
    else:
        match_count += 1

print(f"\n  Matching bytes: {match_count}/{domain_params_end}")
if length_field_mismatch:
    print(f"  Note: Length field differs due to different client data content")

if mismatch_count == 0:
    print("\n" + "=" * 70)
    print("✓ SUCCESS! MCS DOMAIN PARAMETERS ARE CORRECT!")
    print("=" * 70)
    print("\nAll domain parameters (targetParameters, minimumParameters,")
    print("maximumParameters) now match xfreerdp exactly.")
    print("\nThe length field differs only because our Client Data blocks")
    print("(CS_CORE, CS_SECURITY, CS_NET, CS_CLUSTER) have different content,")
    print("which is expected and acceptable.")
    print("\n" + "=" * 70)
else:
    print(f"\n✗ Still have {mismatch_count} mismatches beyond length field")

print(f"\n[X.224 Header Fix]")
print(f"  Our X.224 Data: {full_packet[4:7].hex()}")
print(f"  Expected:       02f080")
if full_packet[4:7].hex() == "02f080":
    print(f"  ✓ X.224 header is correct (includes EOT flag 0x80)")
else:
    print(f"  ✗ X.224 header mismatch")
