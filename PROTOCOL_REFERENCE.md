# RDP Protocol Implementation Reference

## Protocol Stack

```
┌─────────────────────────────────────┐
│         Application Layer           │
│  (Bitmap Updates, Input Events)     │
├─────────────────────────────────────┤
│         RDP Layer                   │
│  (PDUs: Demand Active, Confirm      │
│   Active, Synchronize, Control)     │
├─────────────────────────────────────┤
│       Security Layer                │
│  (Encryption: RC4, RSA)             │
├─────────────────────────────────────┤
│         MCS Layer                   │
│  (Multipoint Communication Service) │
├─────────────────────────────────────┤
│         X.224 Layer                 │
│  (Connection-Oriented Transport)    │
├─────────────────────────────────────┤
│         TPKT Layer                  │
│  (Transport Service on TCP)         │
├─────────────────────────────────────┤
│         TCP                         │
│  (Port 3389)                        │
└─────────────────────────────────────┘
```

---

## Working Packet Formats

### 1. X.224 Connection Request (42 bytes)

```
TPKT Header (4 bytes):
  03 00 00 2a                    Version=3, Length=42

X.224 Connection Request (7 bytes):
  25                             LI (Length Indicator) = 37
  e0                             CR (Connection Request) = 0xe0
  00 00                          DST-REF = 0 (uint16 big-endian)
  00 00                          SRC-REF = 0 (uint16 big-endian)
  00                             CLASS = 0

Cookie (24 bytes):
  43 6f 6f 6b 69 65 3a 20        "Cookie: "
  6d 73 74 73 68 61 73 68        "mstshash"
  3d 75 73 65 72                 "=user"
  0d 0a                          CRLF

RDP Negotiation Request (8 bytes):
  01                             Type = RDP_NEG_REQ
  00                             Flags = 0
  08 00                          Length = 8 (little-endian)
  00 00 00 00                    Protocols = PROTOCOL_RDP (0x00000000)
```

**Python Implementation:**
```python
def create_x224_connection_request(protocol=0x00000000):
    cookie = b"Cookie: mstshash=user\r\n"
    neg_req = struct.pack('<BBHI', 0x01, 0x00, 0x0008, protocol)
    payload = cookie + neg_req

    x224_length = len(payload) + 6
    x224_header = struct.pack('>BBHHB', x224_length, 0xe0, 0x0000, 0x0000, 0x00)

    tpkt_length = len(x224_header) + len(payload) + 4
    tpkt_header = struct.pack('>BBH', 0x03, 0x00, tpkt_length)

    return tpkt_header + x224_header + payload
```

---

### 2. X.224 Connection Confirm (19 bytes)

```
TPKT Header:
  03 00 00 13                    Version=3, Length=19

X.224 Connection Confirm:
  0e                             LI = 14
  d0                             CC (Connection Confirm) = 0xd0
  00 00                          DST-REF = 0
  12 34                          SRC-REF = 0x1234
  00                             CLASS = 0

RDP Negotiation Response:
  02                             Type = RDP_NEG_RSP
  09                             Flags = 0x09
  08 00                          Length = 8
  00 00 00 00                    Selected Protocol = PROTOCOL_RDP
```

**Parsing:**
```python
def parse_x224_response(data):
    if data[0] != 0x03 or data[5] != 0xd0:
        return False

    # Look for negotiation response (0x02)
    for i in range(11, len(data)):
        if i + 8 > len(data):
            break
        if data[i] == 0x02:
            protocol = struct.unpack('<I', data[i+4:i+8])[0]
            return True, protocol

    return True, 0x00000000  # Default to standard RDP
```

---

### 3. MCS Connect Initial (451 bytes)

```
TPKT Header:
  03 00 01 c3                    Length = 451

X.224 Data:
  02 f0 80                       LI=2, Code=0xf0 (DT), EOT=0x80

MCS Connect-Initial:
  7f 65                          Tag = Connect-Initial
  82 01 b7                       Length = 439 (BER long form)

  callingDomainSelector:
    04 01 01                     OCTET STRING, length 1, value 0x01

  calledDomainSelector:
    04 01 01                     OCTET STRING, length 1, value 0x01

  upwardFlag:
    01 01 ff                     BOOLEAN, length 1, value TRUE

  targetParameters (SEQUENCE):
    30 1a                        SEQUENCE, length 26
    02 01 22                     maxChannelIds = 34
    02 01 02                     maxUserIds = 2
    02 01 00                     maxTokenIds = 0
    02 01 01                     numPriorities = 1
    02 01 00                     minThroughput = 0
    02 01 01                     maxHeight = 1
    02 03 00 ff ff               maxMCSPDUsize = 65535 (3-byte BER)
    02 01 02                     protocolVersion = 2

  minimumParameters (SEQUENCE):
    30 19                        SEQUENCE, length 25
    02 01 01                     maxChannelIds = 1
    02 01 01                     maxUserIds = 1
    02 01 01                     maxTokenIds = 1
    02 01 01                     numPriorities = 1
    02 01 00                     minThroughput = 0
    02 01 01                     maxHeight = 1
    02 02 04 20                  maxMCSPDUsize = 1056
    02 01 02                     protocolVersion = 2

  maximumParameters (SEQUENCE):
    30 20                        SEQUENCE, length 32
    02 03 00 ff ff               maxChannelIds = 65535
    02 03 00 fc 17               maxUserIds = 64535
    02 03 00 ff ff               maxTokenIds = 65535
    02 01 01                     numPriorities = 1
    02 01 00                     minThroughput = 0
    02 01 01                     maxHeight = 1
    02 03 00 ff ff               maxMCSPDUsize = 65535
    02 01 02                     protocolVersion = 2

  userData (OCTET STRING):
    04 82 01 51                  Tag=0x04, Length=337 (BER)

    [337 bytes of GCC Conference Create Request]
    - H.221 key: 00 05 00 14 7c 00 01
    - Client Core Data (CS_CORE)
    - Client Security Data (CS_SECURITY)
    - Client Network Data (CS_NET)
    - Client Cluster Data (CS_CLUSTER)
```

**Key Points:**
- Total: 444 bytes MCS + 7 bytes headers = 451 bytes
- BER encoding: Values > 255 need 2+ byte encoding
- Use exact working bytes from xfreerdp capture

---

### 4. MCS Erect Domain Request (12 bytes)

```
TPKT: 03 00 00 0c                Length = 12
X.224: 02 f0 80                  LI=2, Code=0xf0, EOT=0x80
MCS: 04 01 00 01 00              Erect Domain: subHeight=0, subInterval=0
```

**Python:**
```python
def create_mcs_erect_domain_request():
    mcs_data = bytes.fromhex('04 01 00 01 00')
    x224_data = struct.pack('BBB', 2, 0xf0, 0x80)
    total_length = 4 + len(x224_data) + len(mcs_data)
    tpkt_header = struct.pack('>BBH', 0x03, 0x00, total_length)
    return tpkt_header + x224_data + mcs_data
```

---

### 5. MCS Attach User Request (8 bytes)

```
TPKT: 03 00 00 08                Length = 8
X.224: 02 f0 80                  LI=2, Code=0xf0, EOT=0x80
MCS: 28                          Attach User Request
```

---

### 6. MCS Attach User Confirm (11 bytes)

```
TPKT: 03 00 00 0b                Length = 11
X.224: 02 f0 80                  LI=2, Code=0xf0, EOT=0x80
MCS: 2e 00 00 07                 Attach User Confirm, result=0, userID=7
```

**Parsing:**
```python
def parse_mcs_attach_user_confirm(data):
    for i in range(len(data)):
        if data[i] == 0x2e:  # Attach User Confirm tag
            if i + 3 < len(data):
                user_channel = struct.unpack('>H', data[i+2:i+4])[0]
                return user_channel
    return None
```

---

### 7. MCS Channel Join Request (12 bytes)

```
TPKT: 03 00 00 0c                Length = 12
X.224: 02 f0 80                  LI=2, Code=0xf0, EOT=0x80
MCS: 38 00 07 03 f0              Channel Join: userID=7, channelID=1008
```

**Channel Sequence** (xfreerdp joins 6 channels):
1. 1008 (0x03f0) - User channel + 1001
2. 1003 (0x03eb) - I/O channel
3. 1004 (0x03ec) - Virtual channel 1
4. 1005 (0x03ed) - Virtual channel 2
5. 1006 (0x03ee) - Virtual channel 3
6. 1007 (0x03ef) - Virtual channel 4

---

### 8. MCS Channel Join Confirm (15 bytes)

```
TPKT: 03 00 00 0f
X.224: 02 f0 80
MCS: 3e 00 00 07 03 f0 03 f0     Join Confirm: result=0, userID=7,
                                  requested=1008, actual=1008
```

---

### 9. Security Exchange (88 bytes with encryption)

**Structure:**
```
TPKT: 03 00 00 58                Length = 88
X.224: 02 f0 80

MCS Send Data:
  64                             Send Data Request
  00 07                          userID = 7
  03 eb                          channelID = 1003 (I/O)
  70 80                          Priority=high, Length follows
  50                             Length = 80 bytes

Security Header:
  01 02 00 00                    flags = SEC_EXCHANGE_PKT (0x0201)

Client Random Length:
  48 00 00 00                    Length = 72 bytes

RSA Encrypted Random:
  [72 bytes of encrypted client random]
  - Generated: 32 random bytes
  - Padded: PKCS#1 v1.5 padding
  - Encrypted: RSA with server's public key
  - Size: Matches server key length - 11
```

**Our Current (Wrong):**
```python
# Sends 32 bytes of zeros (unencrypted)
client_random = b'\x00' * 32
sec_pdu = struct.pack('<IHI', 0x0001, 0x00, len(client_random)) + client_random
```

**Required:**
```python
# Generate random
import secrets
client_random = secrets.token_bytes(32)

# Parse server certificate from MCS Connect Response
server_cert = parse_server_certificate(mcs_response)
public_key = extract_rsa_public_key(server_cert)

# RSA encrypt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
cipher = PKCS1_v1_5.new(public_key)
encrypted_random = cipher.encrypt(client_random)

# Send encrypted data
sec_pdu = struct.pack('<IHI', 0x0201, 0x00, len(encrypted_random)) + encrypted_random
```

---

### 10. Client Info (332 bytes with encryption)

**Structure:**
```
TPKT: 03 00 01 50                Length = 336
X.224: 02 f0 80

MCS Send Data:
  64                             Send Data Request
  00 07                          userID = 7
  03 eb                          channelID = 1003
  70 81 44                       Priority=high, Length=324

Security Header:
  48 08 00 00                    flags = SEC_INFO_PKT (0x0848)

RC4 Encrypted Payload:
  [324 bytes of encrypted client info]

  Decrypted structure:
    CodePage: 4 bytes
    flags: 4 bytes (INFO_MOUSE | INFO_UNICODE, etc.)
    cbDomain: 2 bytes
    cbUserName: 2 bytes
    cbPassword: 2 bytes
    cbAlternateShell: 2 bytes
    cbWorkingDir: 2 bytes
    Domain: variable (Unicode)
    UserName: variable (Unicode)
    Password: variable (Unicode)
    AlternateShell: variable (Unicode)
    WorkingDir: variable (Unicode)
    ... extended info fields ...
```

**Encryption Required:**
```python
# Derive keys from client_random and server_random
initial_key = sha1(client_random + server_random)
session_key = md5(initial_key + client_random + server_random)

# Initialize RC4
from Crypto.Cipher import ARC4
cipher = ARC4.new(session_key)

# Encrypt client info
encrypted_info = cipher.encrypt(plaintext_info)
```

---

## BER Encoding Reference

### Integer Encoding
```
Value ≤ 127:    02 01 XX                    (3 bytes)
Value ≤ 255:    02 01 XX                    (3 bytes)
Value ≤ 65535:  02 02 XX XX                 (4 bytes, big-endian)
Value > 65535:  02 03 XX XX XX              (5 bytes, big-endian)
```

### Length Encoding
```
Length < 128:   XX                          (1 byte)
Length < 256:   81 XX                       (2 bytes)
Length < 65536: 82 XX XX                    (3 bytes, big-endian)
```

### Examples
```
Integer 34:      02 01 22
Integer 255:     02 01 ff
Integer 256:     02 02 01 00
Integer 65535:   02 02 ff ff
Integer 64535:   02 02 fc 17

Length 26:       1a
Length 200:      81 c8
Length 337:      82 01 51
Length 439:      82 01 b7
```

---

## Common Issues & Solutions

### Issue 1: Connection Reset at X.224
**Symptom**: Reset immediately after X.224 request
**Cause**: Wrong header size (5 bytes instead of 7)
**Fix**: Use `struct.pack('>BBHHB', ...)` for DST-REF/SRC-REF

### Issue 2: MCS Connect Initial Timeout
**Symptom**: No response to MCS Connect Initial
**Cause**: Incorrect domain parameters or packet size
**Fix**: Use exact 444-byte MCS data from xfreerdp capture

### Issue 3: Channel Join Reset
**Symptom**: Reset during channel joins
**Cause**: Missing EOT flag or wrong channels
**Fix**: Add 0x80 to X.224 header, join channels [1008, 1003-1007]

### Issue 4: Security Exchange Reset
**Symptom**: Reset after Security Exchange
**Cause**: Server expects RSA-encrypted random, we send zeros
**Fix**: Implement RSA encryption with server's public key

### Issue 5: Empty Range Bug
**Symptom**: Protocol negotiation not detected
**Cause**: `range(11, len(data) - 8)` empty for 19-byte packets
**Fix**: Use `range(11, len(data))` with bounds checking

---

## Testing Methodology

### 1. Capture Working Connection
```bash
# Start tcpdump
sudo tcpdump -i any -s 0 -w capture.pcap "tcp port 3389"

# Connect with xfreerdp
xfreerdp /v:172.21.2.32 /cert-ignore /sec:rdp

# Stop tcpdump (Ctrl+C)
```

### 2. Extract Packets
```bash
# View packets
tshark -r capture.pcap -Y "tcp.port == 3389" -T fields -e data

# Filter by size (e.g., MCS Connect Initial ~451 bytes)
tshark -r capture.pcap -Y "tcp.dstport == 3389 and tcp.len > 400" \
  -T fields -e data
```

### 3. Compare with Implementation
```python
# Generate our packet
our_packet = create_mcs_connect_initial()

# Load xfreerdp packet
xf_packet = bytes.fromhex(captured_hex)

# Compare byte-by-byte
for i in range(min(len(our_packet), len(xf_packet))):
    if our_packet[i] != xf_packet[i]:
        print(f"Byte {i}: ours=0x{our_packet[i]:02x} xf=0x{xf_packet[i]:02x}")
```

### 4. Integrate Working Bytes
```python
def create_mcs_connect_initial():
    mcs_data = bytes.fromhex("""
        7f 65 82 01 b7 ...
        [exact bytes from capture]
    """.replace('\n', '').replace(' ', ''))

    x224_data = struct.pack('BBB', 2, 0xf0, 0x80)
    total_length = 4 + len(x224_data) + len(mcs_data)
    tpkt_header = struct.pack('>BBH', 0x03, 0x00, total_length)

    return tpkt_header + x224_data + mcs_data
```

---

## Protocol Constants

```python
# Protocol Selection
PROTOCOL_RDP = 0x00000000        # Standard RDP Security
PROTOCOL_SSL = 0x00000001        # TLS 1.0
PROTOCOL_HYBRID = 0x00000002     # CredSSP (NLA)
PROTOCOL_RDSTLS = 0x00000004     # RDSTLS
PROTOCOL_HYBRID_EX = 0x00000008  # CredSSP with Early User Auth

# X.224 Codes
X224_CR = 0xe0                   # Connection Request
X224_CC = 0xd0                   # Connection Confirm
X224_DT = 0xf0                   # Data
X224_EOT = 0x80                  # End of Transmission

# MCS Tags
MCS_CONNECT_INITIAL = 0x7f65
MCS_CONNECT_RESPONSE = 0x7f66
MCS_ERECT_DOMAIN = 0x04
MCS_ATTACH_USER = 0x28
MCS_ATTACH_USER_CONFIRM = 0x2e
MCS_CHANNEL_JOIN = 0x38
MCS_CHANNEL_JOIN_CONFIRM = 0x3e
MCS_SEND_DATA = 0x64

# Security Flags
SEC_EXCHANGE_PKT = 0x0201
SEC_INFO_PKT = 0x0848
SEC_LICENSE_PKT = 0x0080

# Channels
CHANNEL_IO = 1003                # Main I/O channel
CHANNEL_USER_BASE = 1008         # User channel base
```

---

## References

- **[MS-RDPBCGR]**: Remote Desktop Protocol: Basic Connectivity and Graphics Remoting
- **[MS-RDPELE]**: Remote Desktop Protocol: Licensing Extension
- **[MS-RDPEGDI]**: Remote Desktop Protocol: Graphics Device Interface (GDI) Acceleration Extensions
- **FreeRDP Source**: https://github.com/FreeRDP/FreeRDP
- **xfreerdp**: Reference implementation used for packet captures

---

*Last Updated: 2025-10-29*
*Protocol Version: RDP 5.0+ (compatible with Windows Server 2008+)*
