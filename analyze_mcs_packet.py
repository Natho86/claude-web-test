#!/usr/bin/env python3
"""
Analyze the working xfreerdp MCS Connect Initial packet
to understand what values are being used
"""

import struct

# Raw packet from xfreerdp capture (starting from TPKT header)
# This is the working packet that successfully connects
packet_hex = """
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
"""

# Convert hex string to bytes
packet = bytes.fromhex(packet_hex.replace('\n', ''))

print("=" * 70)
print("ANALYZING WORKING XFREERDP MCS CONNECT INITIAL PACKET")
print("=" * 70)

# Parse TPKT
tpkt_version = packet[0]
tpkt_reserved = packet[1]
tpkt_length = struct.unpack('>H', packet[2:4])[0]

print(f"\n[TPKT Header]")
print(f"  Version: 0x{tpkt_version:02x}")
print(f"  Reserved: 0x{tpkt_reserved:02x}")
print(f"  Length: {tpkt_length} bytes (0x{tpkt_length:04x})")

# Parse X.224 Data TPDU
x224_length = packet[4]
x224_code = packet[5]

print(f"\n[X.224 Data TPDU]")
print(f"  Length Indicator: {x224_length}")
print(f"  Code: 0x{x224_code:02x}")

# MCS Connect-Initial starts at offset 7
offset = 7

# MCS tag
mcs_tag = struct.unpack('>H', packet[offset:offset+2])[0]
offset += 2

print(f"\n[MCS Connect-Initial]")
print(f"  Tag: 0x{mcs_tag:04x}")

# BER length
length_byte1 = packet[offset]
offset += 1

if length_byte1 & 0x80:
    # Long form
    num_octets = length_byte1 & 0x7f
    if num_octets == 1:
        mcs_length = packet[offset]
        offset += 1
    elif num_octets == 2:
        mcs_length = struct.unpack('>H', packet[offset:offset+2])[0]
        offset += 2
    print(f"  Length: {mcs_length} bytes (0x{mcs_length:04x}) [BER long form]")
else:
    mcs_length = length_byte1
    print(f"  Length: {mcs_length} bytes [BER short form]")

# callingDomainSelector (OCTET STRING)
tag = packet[offset]
length = packet[offset+1]
value = packet[offset+2:offset+2+length]
print(f"\n  callingDomainSelector: {value.hex()}")
offset += 2 + length

# calledDomainSelector (OCTET STRING)
tag = packet[offset]
length = packet[offset+1]
value = packet[offset+2:offset+2+length]
print(f"  calledDomainSelector: {value.hex()}")
offset += 2 + length

# upwardFlag (BOOLEAN)
tag = packet[offset]
length = packet[offset+1]
value = packet[offset+2]
print(f"  upwardFlag: {value == 0xff}")
offset += 2 + length

# targetParameters (DomainParameters SEQUENCE)
def parse_domain_parameters(data, offset, name):
    print(f"\n  [{name}]")
    seq_tag = data[offset]
    seq_length = data[offset+1]
    print(f"    SEQUENCE tag: 0x{seq_tag:02x}, length: {seq_length}")
    offset += 2

    params = {}
    field_names = [
        'maxChannelIds',
        'maxUserIds',
        'maxTokenIds',
        'numPriorities',
        'minThroughput',
        'maxHeight',
        'maxMCSPDUsize',
        'protocolVersion'
    ]

    field_idx = 0
    while offset < len(data) and field_idx < len(field_names):
        tag = data[offset]
        if tag != 0x02 and tag != 0x30:  # INTEGER or SEQUENCE
            break

        if tag == 0x02:  # INTEGER
            int_length = data[offset+1]
            if int_length == 1:
                value = data[offset+2]
            elif int_length == 2:
                value = struct.unpack('>H', data[offset+2:offset+4])[0]
            else:
                value = 0

            field_name = field_names[field_idx]
            params[field_name] = value
            print(f"    {field_name}: {value} (0x{value:02x})")
            offset += 2 + int_length
            field_idx += 1

    return offset, params

offset, target_params = parse_domain_parameters(packet, offset, "targetParameters")

# minimumParameters
offset, min_params = parse_domain_parameters(packet, offset, "minimumParameters")

# maximumParameters
offset, max_params = parse_domain_parameters(packet, offset, "maximumParameters")

# userData (OCTET STRING)
tag = packet[offset]
length_byte1 = packet[offset+1]
offset += 2

if length_byte1 & 0x80:
    num_octets = length_byte1 & 0x7f
    if num_octets == 1:
        userdata_length = packet[offset]
        offset += 1
    elif num_octets == 2:
        userdata_length = struct.unpack('>H', packet[offset:offset+2])[0]
        offset += 2
else:
    userdata_length = length_byte1

print(f"\n  [userData]")
print(f"    Tag: 0x{tag:02x}")
print(f"    Length: {userdata_length} bytes")

# Parse GCC Conference Create Request
userdata_start = offset

# H.221 key for T.124
h221_key = packet[offset:offset+7]
print(f"\n  [GCC Conference Create Request]")
print(f"    H.221 key: {h221_key.hex()}")
offset += 7

# Look for Client Core Data (0xc001)
print(f"\n  [Client Data Blocks]")

while offset < len(packet):
    if offset + 4 > len(packet):
        break

    # Check for client data block header
    block_type = struct.unpack('<H', packet[offset:offset+2])[0]
    block_length = struct.unpack('<H', packet[offset+2:offset+4])[0]

    block_names = {
        0xc001: "CS_CORE",
        0xc002: "CS_SECURITY",
        0xc003: "CS_NET",
        0xc004: "CS_CLUSTER"
    }

    if block_type in block_names:
        print(f"\n    [{block_names[block_type]}]")
        print(f"      Type: 0x{block_type:04x}")
        print(f"      Length: {block_length} bytes")

        if block_type == 0xc001:  # CS_CORE
            # Parse interesting fields
            if offset + 12 < len(packet):
                version = struct.unpack('<I', packet[offset+4:offset+8])[0]
                width = struct.unpack('<H', packet[offset+8:offset+10])[0]
                height = struct.unpack('<H', packet[offset+10:offset+12])[0]
                print(f"      RDP Version: 0x{version:08x}")
                print(f"      Desktop Size: {width}x{height}")

                if offset + 14 < len(packet):
                    color_depth = struct.unpack('<H', packet[offset+12:offset+14])[0]
                    print(f"      Color Depth: 0x{color_depth:04x}")

        elif block_type == 0xc002:  # CS_SECURITY
            if offset + 8 < len(packet):
                enc_methods = struct.unpack('<I', packet[offset+8:offset+12])[0]
                print(f"      Encryption Methods: 0x{enc_methods:08x}")

        elif block_type == 0xc003:  # CS_NET
            if offset + 8 < len(packet):
                channel_count = struct.unpack('<I', packet[offset+8:offset+12])[0]
                print(f"      Channel Count: {channel_count}")

        elif block_type == 0xc004:  # CS_CLUSTER
            if offset + 8 < len(packet):
                flags = struct.unpack('<I', packet[offset+8:offset+12])[0]
                print(f"      Flags: 0x{flags:08x}")

        offset += block_length
    else:
        break

print("\n" + "=" * 70)
print("KEY FINDINGS FOR OUR IMPLEMENTATION:")
print("=" * 70)
print(f"\ntargetParameters:")
for key, value in target_params.items():
    print(f"  {key}: {value}")

print(f"\nminimumParameters:")
for key, value in min_params.items():
    print(f"  {key}: {value}")

print(f"\nmaximumParameters:")
for key, value in max_params.items():
    print(f"  {key}: {value}")

print("\n" + "=" * 70)
