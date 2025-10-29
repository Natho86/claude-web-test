#!/usr/bin/env python3
"""
Extract Client Data blocks from working xfreerdp packet
"""

# Full xfreerdp packet (TPKT + X.224 + MCS Connect Initial)
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

print("Extracting Client Data from xfreerdp packet...")
print(f"Total packet size: {len(xfreerdp_packet)} bytes")

# Skip to userData in MCS Connect Initial
# Structure:
# - TPKT (4 bytes): 03 00 01 c3
# - X.224 (3 bytes): 02 f0 80
# - MCS tag (2 bytes): 7f 65
# - MCS length (3 bytes): 82 01 b7
# - callingDomainSelector (4 bytes): 04 01 01
# - calledDomainSelector (4 bytes): 04 01 01
# - upwardFlag (3 bytes): 01 01 ff
# - targetParameters (28 bytes): 30 1a ...
# - minimumParameters (27 bytes): 30 19 ...
# - maximumParameters (30 bytes): 30 1c ...
# - userData tag+length: 04 82 01 4b

# Calculate offset to userData content
offset = 7  # TPKT + X.224
offset += 2  # MCS tag
offset += 3  # MCS length (82 01 b7)
offset += 4  # callingDomainSelector
offset += 4  # calledDomainSelector
offset += 3  # upwardFlag
offset += 28  # targetParameters
offset += 27  # minimumParameters
offset += 30  # maximumParameters
offset += 4  # userData tag+length (04 82 01 4b)

print(f"Offset to userData content: {offset} (0x{offset:02x})")
print(f"Expected offset: 112 (0x70)")

# userData starts at byte 112
userdata_start = 112
userdata = xfreerdp_packet[userdata_start:]

print(f"\nUserData length: {len(userdata)} bytes")
print(f"UserData hex:\n{userdata.hex()}")

# The userData contains:
# - H.221 key (7 bytes): 00 05 00 14 7c 00 01
# - GCC data with Client Data blocks

h221_key = userdata[:7]
print(f"\nH.221 key: {h221_key.hex()}")

client_data_start = 7
client_data = userdata[client_data_start:]

print(f"\nClient Data blocks: {len(client_data)} bytes")
print(f"Client Data hex for integration:\n")

# Format for easy integration
hex_str = client_data.hex()
formatted = ""
for i in range(0, len(hex_str), 32):
    formatted += "    " + " ".join([hex_str[j:j+2] for j in range(i, min(i+32, len(hex_str)), 2)]) + "\n"

print(formatted)

# Also save to file
with open('/home/user/claude-web-test/xfreerdp_client_data.bin', 'wb') as f:
    f.write(client_data)

print(f"Saved to xfreerdp_client_data.bin ({len(client_data)} bytes)")
