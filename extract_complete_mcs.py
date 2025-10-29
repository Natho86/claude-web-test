#!/usr/bin/env python3
"""
Extract complete MCS Connect Initial from xfreerdp packet
"""

# Full xfreerdp packet
xfreerdp_packet = bytes.fromhex("""
03 00 01 c3 02 f0 80 7f 65 82 01 b7 04 01
01 04 01 01 01 01 ff 30 1a 02 01 22 02 01 02 02
01 00 02 01 01 02 01 00 02 01 01 02 02 ff ff 02
01 02 30 19 02 01 01 02 01 01 02 01 01 02 01 01
02 01 00 02 01 01 02 02 04 20 02 01 02 30 1c 02
02 ff ff 02 02 fc 17 02 01 ff 02 01 01 02 01 00
02 01 01 02 02 ff ff 02 01 02 04 82 01 4b 00 05
00 14 7c 00 01 2a 14 76 0a 01 01 00 01 c0 00 4d
53 54 53 43 00 0e 00 00 00 01 00 00 00 01 00 00
00 01 00 00 00 00 00 00 00 ff ff ff ff ff ff ff
ff 00 00 00 00 07 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 01 ca 01 00 00 00 00 00 18 00 0f 00 09 00 08
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 04 c0 0c 00 0d 00 00 00 00 00 00
00 02 c0 0c 00 03 00 00 00 00 00 00 00 03 c0 2c
00 03 00 00 00 72 64 70 64 72 00 00 00 00 00 80
80 72 64 70 73 6e 64 00 00 00 00 00 c0 00 73 6e
64 64 62 67 00 00 00 00 c0 00 72 64 70 64 79 6e
76 63 00 00 80 80
""".replace('\n', ''))

print(f"Total xfreerdp packet: {len(xfreerdp_packet)} bytes")
print()

# Extract complete MCS Connect Initial (starting from MCS tag 0x7f65)
# Skip: TPKT (4 bytes) + X.224 (3 bytes) = 7 bytes
mcs_offset = 7
mcs_data = xfreerdp_packet[mcs_offset:]

print(f"MCS Connect Initial: {len(mcs_data)} bytes")
print()

# Format for code integration
print("MCS Connect Initial hex (for integration):")
print()
hex_str = mcs_data.hex()
for i in range(0, len(hex_str), 32):
    line = " ".join([hex_str[j:j+2] for j in range(i, min(i+32, len(hex_str)), 2)])
    print(f"    {line}")

print()
print(f"Save to file...")
with open('/home/user/claude-web-test/xfreerdp_mcs_connect_initial.bin', 'wb') as f:
    f.write(mcs_data)

print(f"Saved {len(mcs_data)} bytes to xfreerdp_mcs_connect_initial.bin")
