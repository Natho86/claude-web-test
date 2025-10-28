# RDP Screenshot Tool

A Python 3 tool for capturing screenshots of Remote Desktop Protocol (RDP) services without authentication. Similar to Nessus plugin 66173, this tool performs a pre-authentication RDP handshake to capture the login screen of systems running Microsoft Terminal Services.

## Purpose

This is a **defensive security tool** designed for:
- Network security assessments
- Asset discovery and identification
- Vulnerability scanning and compliance checking
- Identifying exposed RDP services on networks
- Security auditing and reconnaissance

## Features

- **No Authentication Required**: Captures screenshots during pre-authentication phase
- **Multiple Input Formats**: Supports Nessus XML, Nmap XML, IP lists, and single targets
- **Headless Operation**: Works on Linux servers without display/GUI
- **Modern Python 3**: Built with Python 3.7+ and up-to-date libraries
- **RDP Protocol Implementation**: Custom implementation of RDP handshake protocol
- **Flexible Output**: Save screenshots as PNG or JPEG
- **Batch Processing**: Process multiple targets from scan results

## Requirements

- Python 3.7 or higher
- Pillow (PIL) library for image processing
- Network access to RDP port (default: 3389/tcp)

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd claude-web-test
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Make the script executable:
```bash
chmod +x rdp_screenshot.py
```

## Usage

### Basic Usage

**Scan a single target:**
```bash
python3 rdp_screenshot.py -t 192.168.1.100
```

**Scan with custom port:**
```bash
python3 rdp_screenshot.py -t 192.168.1.100 -p 3389
```

### Input from Files

**IP list file (one IP per line):**
```bash
python3 rdp_screenshot.py -i targets.txt
```

Example `targets.txt`:
```
192.168.1.100
192.168.1.101:3389
10.0.0.50
```

**Nmap XML output:**
```bash
python3 rdp_screenshot.py -n nmap_scan.xml
```

**Nessus XML output:**
```bash
python3 rdp_screenshot.py -N nessus_scan.nessus
```

### Advanced Options

**Custom output directory and format:**
```bash
python3 rdp_screenshot.py -t 192.168.1.100 -o screenshots/ -f jpeg
```

**Adjust timeout and resolution:**
```bash
python3 rdp_screenshot.py -t 192.168.1.100 --timeout 15 --width 1280 --height 720
```

**Advanced mode (full protocol implementation):**
```bash
python3 rdp_screenshot.py -t 192.168.1.100 --advanced
```

### Complete Examples

**Security assessment workflow:**
```bash
# Step 1: Scan network with Nmap
nmap -p 3389 -sV -oX rdp_hosts.xml 192.168.1.0/24

# Step 2: Capture RDP screenshots
python3 rdp_screenshot.py -n rdp_hosts.xml -o rdp_screenshots/

# Step 3: Review screenshots
ls -lh rdp_screenshots/
```

**Process multiple input sources:**
```bash
python3 rdp_screenshot.py -i targets.txt -n nmap.xml -N nessus.nessus -o all_screenshots/
```

## Command-Line Options

### Input Options
- `-t, --target`: Single target IP address
- `-i, --ip-list`: File containing list of IPs (one per line)
- `-n, --nmap-xml`: Nmap XML output file
- `-N, --nessus-xml`: Nessus XML output file
- `-p, --port`: RDP port (default: 3389)

### Output Options
- `-o, --output-dir`: Output directory (default: rdp_screenshots)
- `-f, --format`: Image format - png, jpeg, jpg (default: png)

### Connection Options
- `--timeout`: Connection timeout in seconds (default: 15)
- `--width`: Screenshot width in pixels (default: 1024)
- `--height`: Screenshot height in pixels (default: 768)
- `--advanced`: Use advanced mode with full protocol implementation

## How It Works

The tool implements the RDP protocol handshake sequence:

1. **X.224 Connection Request/Confirm**: Establishes transport connection
2. **MCS Connect Initial/Response**: Multipoint Communication Service negotiation
3. **MCS Channel Setup**: Establishes user channels and joins required channels
4. **Security Exchange**: Negotiates security (no encryption for screenshot)
5. **Client Info**: Sends client information (no credentials)
6. **Capability Exchange**: Server sends Demand Active, client responds with Confirm Active
7. **Finalization**: Synchronize, Control, Font List PDUs
8. **Bitmap Capture**: Server sends screen bitmap update

The tool performs this handshake without providing credentials, capturing the pre-authentication screen (typically the Windows login screen or logon banner).

## Implementation Details

### Two Modes

1. **Standard Mode** (default):
   - Performs basic RDP handshake
   - Validates RDP service availability
   - Creates placeholder images
   - Faster and more reliable for service detection

2. **Advanced Mode** (`--advanced` flag):
   - Implements complete RDP protocol stack
   - Attempts to capture actual bitmap updates
   - More comprehensive but may timeout on some servers
   - Better for actual screenshot capture

### Protocol Implementation

The tool implements:
- **TPKT** (RFC 1006): Packet framing
- **X.224** (ISO 8073): Transport connection
- **MCS** (T.125): Multipoint Communication Service
- **RDP**: Remote Desktop Protocol (basic capability exchange)
- **Bitmap Parsing**: Extracts and decodes screen images

## Troubleshooting

### Connection Issues

**Connection timeout:**
- Increase timeout: `--timeout 30`
- Check firewall rules and network connectivity
- Verify target is running RDP service

**Connection refused:**
- Confirm RDP service is running on target
- Check if port 3389 is open
- Try custom port if RDP runs on non-standard port

### Screenshot Issues

**No bitmap received:**
- Use `--advanced` mode for full protocol implementation
- Some RDP servers require complete authentication sequence
- Network Security Level (NLA) may prevent pre-auth screenshots

**Black/blank screenshots:**
- Server may not send bitmap during pre-authentication
- Try adjusting resolution: `--width 800 --height 600`
- Some modern Windows versions with NLA enabled don't provide bitmaps

## Limitations

1. **Network Level Authentication (NLA)**: Modern Windows servers with NLA may not provide bitmaps during pre-authentication
2. **Protocol Complexity**: Full RDP protocol is complex; this tool implements enough for basic screenshot capture
3. **Bitmap Encoding**: Some advanced bitmap encodings may not be fully supported
4. **No Credential Handling**: Tool does not attempt authentication (by design)

## Security Considerations

### Legitimate Use Only

This tool is intended for **defensive security purposes only**:
- Authorized security assessments
- Penetration testing with proper authorization
- Network inventory and asset management
- Vulnerability identification and remediation

### Legal and Ethical Guidelines

- **Authorization Required**: Only scan systems you own or have explicit permission to test
- **Responsible Disclosure**: Report vulnerabilities to system owners
- **Compliance**: Follow all applicable laws and regulations
- **Privacy**: Handle captured screenshots securely and delete when no longer needed

**Unauthorized access to computer systems is illegal. Use this tool responsibly.**

## Technical References

- [Microsoft RDP Protocol Documentation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/)
- [T.125 Multipoint Communication Service](https://www.itu.int/rec/T-REC-T.125)
- [RFC 1006 - ISO Transport Service on TCP](https://tools.ietf.org/html/rfc1006)
- [X.224 ISO Transport Protocol](https://www.itu.int/rec/T-REC-X.224)

## Comparison with Nessus Plugin 66173

This tool replicates the functionality of Nessus plugin 66173 (RDP Screenshots) with improvements:

| Feature | Nessus Plugin 66173 | This Tool |
|---------|---------------------|-----------|
| Pre-auth screenshots | Yes | Yes |
| Python 3 | - | Yes |
| Standalone | No | Yes |
| Open source | No | Yes |
| Multiple input formats | Limited | Yes (Nmap, Nessus, lists) |
| Headless operation | Yes | Yes |
| Customizable | Limited | Yes |

## Contributing

Contributions are welcome! Please consider:
- Bug fixes and improvements
- Additional input format parsers
- Enhanced bitmap decoding
- Better error handling
- Documentation improvements

## License

This tool is provided for educational and authorized security testing purposes. Use responsibly and legally.

## Disclaimer

This tool is provided "as is" without warranty of any kind. The authors are not responsible for any misuse or damage caused by this tool. Users are responsible for complying with all applicable laws and regulations.

## Author

Created as a modern Python 3 replacement for legacy RDP screenshot tools.

## Version

Version 1.0.0 - Initial release

## Changelog

### v1.0.0 (2025-10-28)
- Initial release
- Basic RDP protocol implementation
- Support for Nessus XML, Nmap XML, and IP lists
- Standard and advanced capture modes
- PNG and JPEG output formats
- Headless operation support
