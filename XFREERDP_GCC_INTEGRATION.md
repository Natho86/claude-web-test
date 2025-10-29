# xfreerdp GCC Data Integration

## Summary

Integrated working xfreerdp GCC Conference Create Request data to fix MCS Connect Initial timeouts.

## Problem

After fixing the MCS Domain Parameters, the connection was still timing out at the MCS Connect Initial stage:
- X.224 handshake: ✓ SUCCESS
- MCS Connect Initial sent: ✓ SENT (364 bytes)
- MCS Connect Response: ✗ TIMEOUT (no response from server)

The server was silently rejecting our MCS Connect Initial PDU.

## Root Cause

Our Client Data blocks (CS_CORE, CS_SECURITY, CS_NET, CS_CLUSTER) differed from xfreerdp's working implementation:
- **Packet size difference**: Our 364 bytes vs xfreerdp's 451 bytes (87 byte difference)
- **Missing virtual channels**: Our CS_NET had 0 channels, xfreerdp defines 4 channels
- **Different GCC structure**: Our simplified GCC encoding was incomplete

## Solution

Extracted and integrated the complete GCC Conference Create Request from working xfreerdp packet:

### xfreerdp GCC Data (312 bytes)
- **H.221 key**: `00 05 00 14 7c 00 01`
- **GCC structure**: Complete Conference Create Request
- **CS_CLUSTER** (0xc004): Flags 0x0d, no session ID
- **CS_SECURITY** (0xc002): Encryption methods 0x03
- **CS_NET** (0xc003): 3 virtual channels:
  - `rdpdr` - Drive Redirection (flags: 0x8080)
  - `rdpsnd` - Sound Redirection (flags: 0xc000)
  - `snddbg` - Sound Debug (flags: 0xc000)
  - `rdpdynvc` - Dynamic Virtual Channels (flags: 0x8080)

### Implementation

Added `_encode_gcc_ccr_xfreerdp()` method that returns the exact working GCC data:

```python
def _encode_gcc_ccr_xfreerdp(self) -> bytes:
    """Return GCC Conference Create Request using xfreerdp's working bytes"""
    gcc_data = bytes.fromhex("""
        00 05 00 14 7c 00 01 2a 14 76 0a 01 01 00 01 c0
        00 4d 53 54 53 43 ...
        ... rdpdr, rdpsnd, snddbg, rdpdynvc ...
    """)
    return gcc_data
```

Modified `create_mcs_connect_initial()` to use this working data instead of building from scratch.

## Results

**New Packet Size**: 420 bytes (0x01a4)
- TPKT: 4 bytes
- X.224 Data: 3 bytes
- MCS Connect-Initial: 413 bytes
  - Domain Parameters: 97 bytes ✓ (matching xfreerdp)
  - userData: 312 bytes ✓ (from xfreerdp)

## Testing

To test the fix:

```bash
python3 rdp_screenshot.py -t 172.21.2.32 --protocol rdp -v
```

Expected behavior:
1. ✓ TCP connection established
2. ✓ X.224 Connection Request/Confirm
3. ✓ MCS Connect Initial sent (420 bytes)
4. ✓ **MCS Connect Response received** ← Should now work!
5. Continue with MCS Erect Domain, Attach User, etc.

## Files Modified

- `rdp_screenshot.py`:
  - Added `_encode_gcc_ccr_xfreerdp()` method (line 358-393)
  - Modified `create_mcs_connect_initial()` to use xfreerdp GCC data (line 290-299)

## Files Created

- `extract_client_data.py` - Script to extract GCC data from packet captures
- `XFREERDP_GCC_INTEGRATION.md` - This documentation

## Next Steps

If the MCS Connect Response is now received:
1. Implement MCS Erect Domain Request
2. Implement MCS Attach User Request/Confirm
3. Implement Channel Join Requests
4. Continue with RDP security exchange and client info
5. Receive and process bitmap updates

If still timing out:
1. Capture full xfreerdp packet (all 451 bytes) to ensure no data was truncated
2. Compare byte-by-byte to identify any remaining differences
3. Consider increasing timeout value (currently 10-15 seconds)
