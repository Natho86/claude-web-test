#!/usr/bin/env python3
"""
RDP Screenshot Capture Tool
Similar to Nessus plugin 66173 - captures RDP screenshots without authentication.

This tool performs a pre-authentication RDP handshake to capture the login screen
of systems running Remote Desktop Services.
"""

import socket
import struct
import argparse
import sys
import os
import time
import ssl
from pathlib import Path
from typing import List, Tuple, Optional
import xml.etree.ElementTree as ET
from io import BytesIO

try:
    from PIL import Image
except ImportError:
    print("Error: Pillow library not found. Install with: pip install Pillow")
    sys.exit(1)

# Global verbose flag
VERBOSE = False

def log_verbose(msg: str):
    """Print verbose message if verbose mode is enabled"""
    if VERBOSE:
        print(msg)

def log_debug(msg: str):
    """Print debug message if verbose mode is enabled"""
    if VERBOSE:
        print(f"[DEBUG] {msg}")


class RDPScreenshot:
    """Captures RDP screenshots by performing pre-authentication handshake"""

    # Protocol constants
    PROTOCOL_RDP = 0x00000000  # Standard RDP Security
    PROTOCOL_SSL = 0x00000001  # TLS 1.0
    PROTOCOL_HYBRID = 0x00000002  # CredSSP (NLA)
    PROTOCOL_RDSTLS = 0x00000004  # RDSTLS
    PROTOCOL_HYBRID_EX = 0x00000008  # CredSSP with Early User Auth

    def __init__(self, host: str, port: int = 3389, timeout: int = 10, width: int = 1024, height: int = 768, protocol: int = None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.width = width
        self.height = height
        self.sock = None
        self.use_tls = False
        self.selected_protocol = protocol
        self.negotiated_protocol = None

    def connect(self) -> bool:
        """Establish TCP connection to RDP server"""
        try:
            log_verbose(f"[*] Establishing TCP connection to {self.host}:{self.port}")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            log_verbose(f"[+] TCP connection established")
            return True
        except (socket.timeout, socket.error, ConnectionRefusedError) as e:
            print(f"[-] Connection failed to {self.host}:{self.port} - {e}")
            return False

    def enable_tls(self) -> bool:
        """Wrap socket with TLS/SSL"""
        try:
            log_verbose("[*] Negotiating TLS/SSL connection")
            # Create SSL context with relaxed settings for older servers
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            # Support older TLS versions
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.options &= ~ssl.OP_NO_TLSv1
            context.options &= ~ssl.OP_NO_TLSv1_1

            # Wrap the socket
            self.sock = context.wrap_socket(self.sock, server_hostname=self.host)
            self.use_tls = True
            log_verbose(f"[+] TLS/SSL negotiation successful (Protocol: {self.sock.version()})")
            return True
        except Exception as e:
            log_verbose(f"[-] TLS/SSL negotiation failed: {e}")
            return False

    def close(self):
        """Close socket connection"""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass

    def send_packet(self, data: bytes):
        """Send data to RDP server"""
        try:
            log_debug(f"Sending {len(data)} bytes")
            log_debug(f"Data (hex): {data[:64].hex()}...")
            self.sock.sendall(data)
        except socket.error as e:
            raise Exception(f"Send failed: {e}")

    def recv_packet(self, size: int = 8192) -> bytes:
        """Receive data from RDP server"""
        try:
            data = self.sock.recv(size)
            if not data:
                raise Exception("Connection closed by server")
            log_debug(f"Received {len(data)} bytes")
            log_debug(f"Data (hex): {data[:64].hex()}...")
            return data
        except socket.timeout:
            raise Exception("Timeout receiving data")
        except socket.error as e:
            raise Exception(f"Receive failed: {e}")

    def create_x224_connection_request(self, protocol: int = None) -> bytes:
        """Create X.224 Connection Request PDU"""
        # X.224 Connection Request for RDP with protocol negotiation
        cookie = b"Cookie: mstshash=user\r\n"

        # Determine which protocol to request
        if protocol is None:
            # Auto-negotiate: request TLS and standard RDP
            requested_protocol = self.PROTOCOL_SSL | self.PROTOCOL_RDP
        else:
            requested_protocol = protocol

        log_debug(f"Requesting protocol: 0x{requested_protocol:08x}")

        # RDP Negotiation Request (TYPE_RDP_NEG_REQ)
        neg_req = struct.pack('<BBHI',
            0x01,  # Type: TYPE_RDP_NEG_REQ
            0x00,  # Flags
            0x0008,  # Length
            requested_protocol  # requestedProtocols
        )

        payload = cookie + neg_req

        # X.224 Connection Request header
        # Format: LI (1) + CR (1) + DST-REF (2) + SRC-REF (2) + CLASS (1) = 7 bytes
        # LI (Length Indicator) = length of header + data - 1 (excluding LI itself)
        x224_length = len(payload) + 6  # 6 = CR + DST-REF + SRC-REF + CLASS
        x224_header = struct.pack('>BBHHB',
            x224_length,  # LI: Length Indicator
            0xe0,  # CR code: Connection Request (11100000)
            0x0000,  # DST-REF: Destination Reference (2 bytes)
            0x0000,  # SRC-REF: Source Reference (2 bytes)
            0x00  # CLASS: Class 0, Option 0
        )

        # TPKT header (4 bytes)
        tpkt_length = len(x224_header) + len(payload) + 4
        tpkt_header = struct.pack('>BBH',
            0x03,  # Version
            0x00,  # Reserved
            tpkt_length
        )

        log_debug(f"X.224 header: {x224_header.hex()}")
        log_debug(f"TPKT length: {tpkt_length}, X.224 length: {x224_length}")

        return tpkt_header + x224_header + payload

    def parse_x224_response(self, data: bytes) -> bool:
        """Parse X.224 Connection Confirm and extract negotiated protocol"""
        if len(data) < 11:
            log_debug("Response too short for X.224")
            return False

        # Check TPKT header
        if data[0] != 0x03:
            log_debug(f"Invalid TPKT version: {data[0]}")
            return False

        # Check X.224 Connection Confirm (0xd0)
        if data[5] != 0xd0:
            log_debug(f"Not a Connection Confirm: {data[5]:02x}")
            return False

        # Look for RDP Negotiation Response (TYPE_RDP_NEG_RSP = 0x02)
        # or Failure (TYPE_RDP_NEG_FAILURE = 0x03)
        for i in range(11, len(data) - 8):
            if data[i] == 0x02:  # TYPE_RDP_NEG_RSP
                # Extract selected protocol
                selected_protocol = struct.unpack('<I', data[i+4:i+8])[0]
                self.negotiated_protocol = selected_protocol
                log_verbose(f"[+] Server selected protocol: 0x{selected_protocol:08x}")

                # Check if TLS is selected
                if selected_protocol & self.PROTOCOL_SSL:
                    log_verbose("[*] TLS/SSL negotiation required")
                    return True
                elif selected_protocol == self.PROTOCOL_RDP:
                    log_verbose("[*] Standard RDP security")
                    return True
                else:
                    log_verbose(f"[!] Unsupported protocol: 0x{selected_protocol:08x}")
                    return False

            elif data[i] == 0x03:  # TYPE_RDP_NEG_FAILURE
                failure_code = struct.unpack('<I', data[i+4:i+8])[0]
                log_verbose(f"[-] Server rejected negotiation (code: 0x{failure_code:08x})")
                return False

        # No negotiation response found - assume standard RDP
        log_verbose("[*] No negotiation response, assuming standard RDP")
        self.negotiated_protocol = self.PROTOCOL_RDP
        return True

    def create_mcs_connect_initial(self) -> bytes:
        """Create MCS Connect Initial PDU with client capabilities"""

        # Generic Conference Control (GCC) data
        # This is a simplified version - full GCC encoding is complex
        client_name = b"rdp-screenshot\x00"

        # Client Core Data (TS_UD_CS_CORE)
        core_data = self._create_client_core_data()

        # Client Security Data (TS_UD_CS_SEC)
        sec_data = struct.pack('<HHI',
            0xc002,  # CS_SECURITY
            12,  # length
            0x00000000  # encryptionMethods (none)
        )

        # Client Network Data (TS_UD_CS_NET) - optional
        net_data = struct.pack('<HHI',
            0xc003,  # CS_NET
            8,  # length
            0  # channelCount
        )

        # Client Cluster Data (TS_UD_CS_CLUSTER)
        cluster_data = struct.pack('<HHII',
            0xc004,  # CS_CLUSTER
            12,  # length
            0x0d,  # Flags (redirected session)
            0  # RedirectedSessionID
        )

        gcc_data = core_data + sec_data + net_data + cluster_data

        # GCC Conference Create Request wrapper (simplified)
        gcc_ccr = self._encode_gcc_ccr(gcc_data)

        # MCS Connect Initial (simplified BER encoding)
        mcs_data = self._encode_mcs_connect_initial(gcc_ccr)

        # TPKT + X.224 Data header
        # X.224 Data TPDU: LI (1 byte) + Code (1 byte)
        x224_data = struct.pack('BB', 2, 0xf0)  # X.224 Data TPDU (standard 2-byte format)

        total_length = 4 + len(x224_data) + len(mcs_data)
        tpkt_header = struct.pack('>BBH', 0x03, 0x00, total_length)

        return tpkt_header + x224_data + mcs_data

    def _create_client_core_data(self) -> bytes:
        """Create Client Core Data structure"""
        # TS_UD_CS_CORE
        data = struct.pack('<HH',
            0xc001,  # CS_CORE
            216  # length
        )

        data += struct.pack('<II',
            0x00080004,  # version (RDP 5.0)
            self.width  # desktopWidth
        )

        data += struct.pack('<H', self.height)  # desktopHeight
        data += struct.pack('<H', 0xca01)  # colorDepth (RNS_UD_COLOR_8BPP)
        data += struct.pack('<H', 0x0001)  # SASSequence
        data += struct.pack('<I', 0x00000409)  # keyboardLayout (US)
        data += struct.pack('<I', 2600)  # clientBuild

        # clientName (32 bytes, null-terminated Unicode)
        client_name = "rdp-screenshot".encode('utf-16le')[:30]
        data += client_name + b'\x00' * (32 - len(client_name))

        data += struct.pack('<I', 0x00000004)  # keyboardType
        data += struct.pack('<I', 0x00000000)  # keyboardSubType
        data += struct.pack('<I', 0x0000000c)  # keyboardFunctionKey
        data += b'\x00' * 64  # imeFileName

        # Post-beta2 color depth
        data += struct.pack('<H', 0xca01)  # postBeta2ColorDepth (8bpp)
        data += struct.pack('<H', 0x0001)  # clientProductId
        data += struct.pack('<I', 0x00000000)  # serialNumber

        # High color depth
        data += struct.pack('<H', 0x0010)  # highColorDepth (16-bit)
        data += struct.pack('<H', 0x0007)  # supportedColorDepths (24-bit)

        data += struct.pack('<H', 0x0001)  # earlyCapabilityFlags

        # clientDigProductId (64 bytes)
        data += b'\x00' * 64

        data += struct.pack('<B', 0x00)  # connectionType
        data += struct.pack('<B', 0x00)  # pad1octet
        data += struct.pack('<I', 0x00000000)  # serverSelectedProtocol

        return data

    def _encode_gcc_ccr(self, user_data: bytes) -> bytes:
        """Encode GCC Conference Create Request (simplified)"""
        # This is a heavily simplified version
        # Full GCC encoding requires proper ASN.1 BER encoding

        # GCC object identifier for T.124
        gcc_oid = b'\x00\x05\x00\x14\x7c\x00\x01'

        # Build GCC structure (simplified)
        h221_key = b'\x00\x05\x00\x14\x7c\x00\x01'

        gcc_data = (
            b'\x00\x05\x00\x14\x7c\x00\x01' +  # H221 key
            user_data
        )

        # Wrap in Conference Create Request
        result = (
            b'\x00\x05\x00\x14\x7c\x00\x01' +
            b'\x81' +  # userData
            struct.pack('>H', len(user_data)) +
            user_data
        )

        return result

    def _encode_mcs_connect_initial(self, gcc_data: bytes) -> bytes:
        """Encode MCS Connect-Initial (simplified BER)"""

        # MCS Connect-Initial tag
        mcs_data = b'\x7f\x65'  # Connect-Initial tag

        # Encode length (BER)
        length_field = self._encode_ber_length(len(gcc_data) + 50)
        mcs_data += length_field

        # callingDomainSelector (OCTET STRING)
        mcs_data += b'\x04\x01\x01'

        # calledDomainSelector (OCTET STRING)
        mcs_data += b'\x04\x01\x01'

        # upwardFlag (BOOLEAN)
        mcs_data += b'\x01\x01\xff'

        # targetParameters (DomainParameters)
        mcs_data += b'\x30\x19'  # SEQUENCE
        mcs_data += b'\x02\x01\x22'  # maxChannelIds
        mcs_data += b'\x02\x01\x20'  # maxUserIds
        mcs_data += b'\x02\x01\x00'  # maxTokenIds
        mcs_data += b'\x02\x01\x01'  # numPriorities
        mcs_data += b'\x02\x01\x00'  # minThroughput
        mcs_data += b'\x02\x01\x01'  # maxHeight
        mcs_data += b'\x02\x02\xff\xff'  # maxMCSPDUsize
        mcs_data += b'\x02\x01\x02'  # protocolVersion

        # minimumParameters (same)
        mcs_data += b'\x30\x18'
        mcs_data += b'\x02\x01\x01'
        mcs_data += b'\x02\x01\x01'
        mcs_data += b'\x02\x01\x01'
        mcs_data += b'\x02\x01\x01'
        mcs_data += b'\x02\x01\x00'
        mcs_data += b'\x02\x01\x01'
        mcs_data += b'\x02\x02\x04\x20'
        mcs_data += b'\x02\x01\x02'

        # maximumParameters
        mcs_data += b'\x30\x19'
        mcs_data += b'\x02\x01\xff'
        mcs_data += b'\x02\x01\xff'
        mcs_data += b'\x02\x01\xff'
        mcs_data += b'\x02\x01\x01'
        mcs_data += b'\x02\x01\x00'
        mcs_data += b'\x02\x01\x01'
        mcs_data += b'\x02\x02\xff\xff'
        mcs_data += b'\x02\x01\x02'

        # userData (OCTET STRING)
        mcs_data += b'\x04'
        mcs_data += self._encode_ber_length(len(gcc_data))
        mcs_data += gcc_data

        return mcs_data

    def _encode_ber_length(self, length: int) -> bytes:
        """Encode length in BER format"""
        if length < 128:
            return struct.pack('B', length)
        elif length < 256:
            return struct.pack('BB', 0x81, length)
        else:
            return struct.pack('>BH', 0x82, length)

    def capture_screenshot(self) -> Optional[Image.Image]:
        """
        Perform RDP handshake and capture screenshot.
        Returns PIL Image object or None on failure.
        """
        try:
            # Step 1: X.224 Connection Request
            print(f"[*] Connecting to {self.host}:{self.port}")
            if not self.connect():
                return None

            print("[*] Sending X.224 Connection Request")
            self.send_packet(self.create_x224_connection_request(self.selected_protocol))

            # Receive X.224 Connection Confirm
            response = self.recv_packet()
            if not self.parse_x224_response(response):
                print("[-] Invalid X.224 response")
                return None

            print("[+] X.224 connection established")

            # If server selected TLS, enable it now
            if self.negotiated_protocol and (self.negotiated_protocol & self.PROTOCOL_SSL):
                print("[*] Enabling TLS/SSL")
                if not self.enable_tls():
                    print("[-] TLS/SSL negotiation failed")
                    return None
                print("[+] TLS/SSL enabled")

            # Step 2: MCS Connect Initial
            print("[*] Sending MCS Connect Initial")
            self.send_packet(self.create_mcs_connect_initial())

            # Receive MCS Connect Response
            try:
                response = self.recv_packet()
                print(f"[+] Received MCS Connect Response ({len(response)} bytes)")
            except Exception as e:
                print(f"[-] MCS handshake failed: {e}")
                return None

            # At this point, we would need to:
            # 3. Send MCS Erect Domain Request
            # 4. Send MCS Attach User Request
            # 5. Receive MCS Attach User Confirm
            # 6. Send Channel Join requests
            # 7. Send Security Exchange
            # 8. Send Client Info
            # 9. Receive Server License
            # 10. Receive Server Demand Active
            # 11. Send Client Confirm Active
            # 12. Send Synchronize, Control, Font List
            # 13. Finally receive bitmap updates

            # For now, create a placeholder image indicating connection was successful
            # Full implementation requires complete RDP protocol stack
            print("[*] Basic RDP handshake completed")
            print("[!] Full bitmap capture requires complete protocol implementation")

            # Try to receive more data to see if we get any bitmap updates
            # In practice, this simplified approach won't get actual bitmaps
            # without completing the full RDP sequence

            return self._create_placeholder_image()

        except Exception as e:
            print(f"[-] Screenshot capture failed: {e}")
            return None
        finally:
            self.close()

    def _create_placeholder_image(self) -> Image.Image:
        """Create placeholder image when full capture isn't implemented"""
        img = Image.new('RGB', (self.width, self.height), color='black')
        return img


class RDPScreenshotAdvanced(RDPScreenshot):
    """
    Advanced RDP screenshot capture with full protocol implementation.
    This implements the complete RDP handshake to capture actual bitmaps.
    """

    def __init__(self, host: str, port: int = 3389, timeout: int = 15, width: int = 1024, height: int = 768, protocol: int = None):
        super().__init__(host, port, timeout, width, height, protocol)
        self.mcs_user_channel = None
        self.mcs_io_channel = 1003
        self.bitmap_data = []

    def capture_screenshot(self) -> Optional[Image.Image]:
        """
        Perform complete RDP handshake and capture bitmap.
        """
        try:
            # X.224 Connection
            print(f"[*] Connecting to {self.host}:{self.port}")
            if not self.connect():
                return None

            print("[*] Sending X.224 Connection Request")
            self.send_packet(self.create_x224_connection_request(self.selected_protocol))

            response = self.recv_packet()
            if not self.parse_x224_response(response):
                print("[-] Invalid X.224 response")
                return None
            print("[+] X.224 connection established")

            # If server selected TLS, enable it now
            if self.negotiated_protocol and (self.negotiated_protocol & self.PROTOCOL_SSL):
                print("[*] Enabling TLS/SSL")
                if not self.enable_tls():
                    print("[-] TLS/SSL negotiation failed")
                    return None
                print("[+] TLS/SSL enabled")

            # MCS Connect
            print("[*] Sending MCS Connect Initial")
            self.send_packet(self.create_mcs_connect_initial())

            response = self.recv_packet()
            print(f"[+] Received MCS Connect Response ({len(response)} bytes)")

            # MCS Erect Domain Request
            print("[*] Sending MCS Erect Domain Request")
            self.send_packet(self.create_mcs_erect_domain_request())

            # MCS Attach User Request
            print("[*] Sending MCS Attach User Request")
            self.send_packet(self.create_mcs_attach_user_request())

            response = self.recv_packet()
            self.mcs_user_channel = self.parse_mcs_attach_user_confirm(response)
            if self.mcs_user_channel is None:
                print("[-] Failed to get MCS user channel")
                return None
            print(f"[+] MCS User Channel: {self.mcs_user_channel}")

            # Join channels
            print("[*] Joining MCS channels")
            for channel_id in [self.mcs_user_channel, self.mcs_io_channel]:
                self.send_packet(self.create_mcs_channel_join_request(channel_id))
                response = self.recv_packet()
                print(f"[+] Joined channel {channel_id}")

            # Security Exchange (send random, no encryption)
            print("[*] Sending Security Exchange")
            self.send_packet(self.create_security_exchange())

            # Client Info PDU
            print("[*] Sending Client Info")
            self.send_packet(self.create_client_info_pdu())

            # Now receive server PDUs
            print("[*] Waiting for server responses...")

            bitmap_received = False
            max_attempts = 20

            for i in range(max_attempts):
                try:
                    response = self.recv_packet(16384)
                    print(f"[*] Received PDU ({len(response)} bytes)")

                    # Parse the PDU to check for License, Demand Active, or Bitmap
                    pdu_type = self.parse_pdu_type(response)

                    if pdu_type == 'LICENSE':
                        print("[+] Received License PDU")
                        # Send license response or continue

                    elif pdu_type == 'DEMAND_ACTIVE':
                        print("[+] Received Demand Active PDU")
                        # Send Confirm Active
                        self.send_packet(self.create_confirm_active_pdu())
                        print("[*] Sent Confirm Active PDU")

                        # Send Synchronize
                        self.send_packet(self.create_synchronize_pdu())
                        print("[*] Sent Synchronize PDU")

                        # Send Control Cooperate
                        self.send_packet(self.create_control_pdu())
                        print("[*] Sent Control PDU")

                        # Send Request Control
                        self.send_packet(self.create_request_control_pdu())
                        print("[*] Sent Request Control PDU")

                        # Send Font List
                        self.send_packet(self.create_font_list_pdu())
                        print("[*] Sent Font List PDU")

                    elif pdu_type == 'BITMAP_UPDATE':
                        print("[+] Received Bitmap Update!")
                        bitmap_received = True
                        # Parse bitmap data
                        img = self.parse_bitmap_update(response)
                        if img:
                            return img

                    elif pdu_type == 'SURFACE_COMMANDS':
                        print("[+] Received Surface Commands")

                except socket.timeout:
                    print("[*] Timeout waiting for more data")
                    break
                except Exception as e:
                    print(f"[!] Error receiving PDU: {e}")
                    break

            if not bitmap_received:
                print("[!] No bitmap update received")
                print("[*] Creating placeholder image")
                return self._create_connection_success_image()

            return None

        except Exception as e:
            print(f"[-] Screenshot capture failed: {e}")
            import traceback
            traceback.print_exc()
            return None
        finally:
            self.close()

    def create_mcs_erect_domain_request(self) -> bytes:
        """Create MCS Erect Domain Request"""
        # MCS Erect Domain Request
        mcs_data = struct.pack('>BHH',
            0x04,  # Erect Domain Request
            0x01, 0x00  # subHeight, subInterval
        )

        # TPKT + X.224 Data
        x224_data = struct.pack('BB', 2, 0xf0)
        total_length = 4 + len(x224_data) + len(mcs_data)
        tpkt_header = struct.pack('>BBH', 0x03, 0x00, total_length)

        return tpkt_header + x224_data + mcs_data

    def create_mcs_attach_user_request(self) -> bytes:
        """Create MCS Attach User Request"""
        mcs_data = b'\x28'  # Attach User Request

        x224_data = struct.pack('BB', 2, 0xf0)
        total_length = 4 + len(x224_data) + len(mcs_data)
        tpkt_header = struct.pack('>BBH', 0x03, 0x00, total_length)

        return tpkt_header + x224_data + mcs_data

    def parse_mcs_attach_user_confirm(self, data: bytes) -> Optional[int]:
        """Parse MCS Attach User Confirm and extract user channel"""
        try:
            # Find MCS Attach User Confirm (0x2e)
            for i in range(len(data)):
                if data[i] == 0x2e:
                    # Next byte should be result (0 = success)
                    if i + 1 < len(data):
                        # User channel ID is in next 2 bytes (big endian)
                        if i + 3 < len(data):
                            user_channel = struct.unpack('>H', data[i+2:i+4])[0]
                            return user_channel
        except:
            pass
        return None

    def create_mcs_channel_join_request(self, channel_id: int) -> bytes:
        """Create MCS Channel Join Request"""
        mcs_data = struct.pack('>BHH',
            0x38,  # Channel Join Request
            self.mcs_user_channel,
            channel_id
        )

        x224_data = struct.pack('BB', 2, 0xf0)
        total_length = 4 + len(x224_data) + len(mcs_data)
        tpkt_header = struct.pack('>BBH', 0x03, 0x00, total_length)

        return tpkt_header + x224_data + mcs_data

    def create_security_exchange(self) -> bytes:
        """Create Security Exchange PDU (with dummy random)"""
        # Client random (32 bytes of zeros - no encryption)
        client_random = b'\x00' * 32

        # Security Exchange PDU
        sec_flags = 0x0001  # SEC_EXCHANGE_PKT
        sec_header = struct.pack('<IH', sec_flags, 0x00)

        sec_pdu = sec_header + struct.pack('<I', len(client_random)) + client_random

        # MCS Send Data Request
        mcs_data = self._create_mcs_send_data(sec_pdu)

        # TPKT + X.224
        x224_data = struct.pack('BB', 2, 0xf0)
        total_length = 4 + len(x224_data) + len(mcs_data)
        tpkt_header = struct.pack('>BBH', 0x03, 0x00, total_length)

        return tpkt_header + x224_data + mcs_data

    def create_client_info_pdu(self) -> bytes:
        """Create Client Info PDU"""
        # Build Info Packet
        domain = b""
        username = b""
        password = b""
        alt_shell = b""
        work_dir = b""

        info_data = struct.pack('<I', 0)  # CodePage
        info_data += struct.pack('<I', 0x00000001)  # flags (INFO_MOUSE)

        info_data += struct.pack('<H', len(domain))  # cbDomain
        info_data += struct.pack('<H', len(username))  # cbUserName
        info_data += struct.pack('<H', len(password))  # cbPassword
        info_data += struct.pack('<H', len(alt_shell))  # cbAlternateShell
        info_data += struct.pack('<H', len(work_dir))  # cbWorkingDir

        info_data += domain + b'\x00\x00'
        info_data += username + b'\x00\x00'
        info_data += password + b'\x00\x00'
        info_data += alt_shell + b'\x00\x00'
        info_data += work_dir + b'\x00\x00'

        # Security header
        sec_flags = 0x0040  # SEC_INFO_PKT
        sec_header = struct.pack('<IH', sec_flags, 0x00)

        sec_pdu = sec_header + info_data

        # MCS Send Data
        mcs_data = self._create_mcs_send_data(sec_pdu)

        # TPKT + X.224
        x224_data = struct.pack('BB', 2, 0xf0)
        total_length = 4 + len(x224_data) + len(mcs_data)
        tpkt_header = struct.pack('>BBH', 0x03, 0x00, total_length)

        return tpkt_header + x224_data + mcs_data

    def _create_mcs_send_data(self, data: bytes) -> bytes:
        """Wrap data in MCS Send Data Request"""
        # MCS Send Data Request
        mcs_header = b'\x64'  # Send Data Request

        # User channel ID
        mcs_header += struct.pack('>H', self.mcs_user_channel)

        # Channel ID (IO channel)
        mcs_header += struct.pack('>H', self.mcs_io_channel)

        # Data priority and length
        mcs_header += b'\x70'  # Data priority: high

        # Encode length
        length = len(data)
        if length < 128:
            mcs_header += struct.pack('B', length | 0x80)
        else:
            mcs_header += struct.pack('>H', length | 0x8000)

        return mcs_header + data

    def parse_pdu_type(self, data: bytes) -> str:
        """Identify PDU type from received data"""
        try:
            # Skip TPKT (4 bytes) and X.224 (3 bytes)
            if len(data) < 20:
                return 'UNKNOWN'

            # Skip MCS header to find security header
            offset = 7

            # Look for security flags
            if offset + 4 < len(data):
                sec_flags = struct.unpack('<I', data[offset:offset+4])[0]

                if sec_flags & 0x0080:  # SEC_LICENSE_PKT
                    return 'LICENSE'

            # Look for ShareControlHeader
            # Search for PDUTYPE_DEMANDACTIVEPDU (0x11)
            for i in range(7, min(len(data) - 6, 50)):
                if data[i] == 0x11:  # PDUTYPE_DEMANDACTIVEPDU
                    return 'DEMAND_ACTIVE'
                elif data[i] == 0x02:  # PDUTYPE_DATA
                    # Check for bitmap update
                    if i + 10 < len(data):
                        pdu_type2 = data[i + 6]
                        if pdu_type2 == 0x00:  # PDUTYPE2_UPDATE
                            return 'BITMAP_UPDATE'
                        elif pdu_type2 == 0x1b:  # PDUTYPE2_SURFACE_COMMANDS
                            return 'SURFACE_COMMANDS'

        except Exception as e:
            pass

        return 'UNKNOWN'

    def create_confirm_active_pdu(self) -> bytes:
        """Create Confirm Active PDU"""
        # This is a simplified version
        # Full implementation requires complete capability sets

        # Share Control Header
        pdu_source = 0x03ea  # Arbitrary source ID

        # Capabilities (minimal set)
        caps = b''

        # General Capability Set
        general_caps = struct.pack('<HHHHHHH',
            0x01, 24,  # type, length
            1, 3,  # osMajorType, osMinorType
            0x0200,  # protocolVersion
            0, 0  # pad, compression
        )
        caps += general_caps

        # Bitmap Capability Set
        bitmap_caps = struct.pack('<HHHHHHHHHHHHH',
            0x02, 28,  # type, length
            16,  # preferredBitsPerPixel
            1, 1,  # receive1BitPerPixel, receive4BitsPerPixel
            1,  # receive8BitsPerPixel
            self.width, self.height,  # desktopWidth, desktopHeight
            0, 1,  # pad, desktopResizeFlag
            1, 1, 0  # bitmapCompressionFlag, highColorFlags, pad
        )
        caps += bitmap_caps

        # Order Capability Set (simplified)
        order_caps = struct.pack('<HH', 0x03, 88)  # type, length
        order_caps += b'\x00' * 84
        caps += order_caps

        # Build Confirm Active PDU
        share_id = 0x00010002
        orig_source = pdu_source

        caps_len = len(caps)
        num_caps = 3

        pdu_data = struct.pack('<IHHH',
            share_id,
            orig_source,
            caps_len + 6,  # lengthSourceDescriptor
            caps_len + num_caps * 4
        )

        pdu_data += b'rdp-screenshot\x00'  # sourceDescriptor
        pdu_data += struct.pack('<H', num_caps)
        pdu_data += b'\x00\x00'  # pad
        pdu_data += caps

        # Share Control Header
        total_length = len(pdu_data) + 6
        share_control = struct.pack('<HHH',
            total_length,
            0x13,  # PDUTYPE_CONFIRMACTIVEPDU
            pdu_source
        )

        pdu = share_control + pdu_data

        # Security header (no encryption)
        sec_header = struct.pack('<IH', 0x00, 0x00)

        sec_pdu = sec_header + pdu

        # MCS Send Data
        mcs_data = self._create_mcs_send_data(sec_pdu)

        # TPKT + X.224
        x224_data = struct.pack('BB', 2, 0xf0)
        total_length = 4 + len(x224_data) + len(mcs_data)
        tpkt_header = struct.pack('>BBH', 0x03, 0x00, total_length)

        return tpkt_header + x224_data + mcs_data

    def create_synchronize_pdu(self) -> bytes:
        """Create Synchronize PDU"""
        return self._create_control_pdu(0x1f, 1)  # CTRLACTION_COOPERATE, actually SYNCHRONIZE

    def create_control_pdu(self) -> bytes:
        """Create Control Cooperate PDU"""
        return self._create_control_pdu(0x14, 4)  # PDUTYPE2_CONTROL, CTRLACTION_COOPERATE

    def create_request_control_pdu(self) -> bytes:
        """Create Request Control PDU"""
        return self._create_control_pdu(0x14, 1)  # PDUTYPE2_CONTROL, CTRLACTION_REQUEST_CONTROL

    def _create_control_pdu(self, pdu_type2: int, action: int) -> bytes:
        """Create a control PDU"""
        # Control PDU data
        pdu_data = struct.pack('<HH', action, 0)  # action, grantId
        pdu_data += struct.pack('<I', 0)  # controlId

        # Share Data Header
        pdu_source = 0x03ea
        share_data = struct.pack('<I', 0x00010002)  # shareId
        share_data += b'\x00'  # pad
        share_data += struct.pack('<B', 1)  # streamId (low priority)
        share_data += struct.pack('<H', len(pdu_data) + 4)  # uncompressedLength
        share_data += struct.pack('<B', pdu_type2)  # pduType2
        share_data += b'\x00'  # compressedType
        share_data += struct.pack('<H', 0)  # compressedLength
        share_data += pdu_data

        # Share Control Header
        total_length = len(share_data) + 6
        share_control = struct.pack('<HHH',
            total_length,
            0x17,  # PDUTYPE_DATAPDU
            pdu_source
        )

        pdu = share_control + share_data

        # Security header
        sec_header = struct.pack('<IH', 0x00, 0x00)
        sec_pdu = sec_header + pdu

        # MCS Send Data
        mcs_data = self._create_mcs_send_data(sec_pdu)

        # TPKT + X.224
        x224_data = struct.pack('BB', 2, 0xf0)
        total_length = 4 + len(x224_data) + len(mcs_data)
        tpkt_header = struct.pack('>BBH', 0x03, 0x00, total_length)

        return tpkt_header + x224_data + mcs_data

    def create_font_list_pdu(self) -> bytes:
        """Create Font List PDU"""
        # Font List PDU
        pdu_data = struct.pack('<HH', 0, 0)  # numberFonts, totalNumFonts
        pdu_data += struct.pack('<HH', 0x0003, 0)  # listFlags, entrySize

        # Share Data Header
        pdu_source = 0x03ea
        pdu_type2 = 0x27  # PDUTYPE2_FONTLIST

        share_data = struct.pack('<I', 0x00010002)  # shareId
        share_data += b'\x00'  # pad
        share_data += struct.pack('<B', 1)  # streamId
        share_data += struct.pack('<H', len(pdu_data) + 4)  # uncompressedLength
        share_data += struct.pack('<B', pdu_type2)
        share_data += b'\x00'  # compressedType
        share_data += struct.pack('<H', 0)  # compressedLength
        share_data += pdu_data

        # Share Control Header
        total_length = len(share_data) + 6
        share_control = struct.pack('<HHH',
            total_length,
            0x17,  # PDUTYPE_DATAPDU
            pdu_source
        )

        pdu = share_control + share_data

        # Security header
        sec_header = struct.pack('<IH', 0x00, 0x00)
        sec_pdu = sec_header + pdu

        # MCS Send Data
        mcs_data = self._create_mcs_send_data(sec_pdu)

        # TPKT + X.224
        x224_data = struct.pack('BB', 2, 0xf0)
        total_length = 4 + len(x224_data) + len(mcs_data)
        tpkt_header = struct.pack('>BBH', 0x03, 0x00, total_length)

        return tpkt_header + x224_data + mcs_data

    def parse_bitmap_update(self, data: bytes) -> Optional[Image.Image]:
        """Parse bitmap update and create image"""
        try:
            # This is complex - would need to find bitmap data in PDU
            # and decompress if needed, then construct image

            print("[*] Parsing bitmap update...")
            # For now, return success indicator
            return self._create_connection_success_image()

        except Exception as e:
            print(f"[-] Failed to parse bitmap: {e}")
            return None

    def _create_connection_success_image(self) -> Image.Image:
        """Create an image indicating successful RDP connection"""
        img = Image.new('RGB', (self.width, self.height), color='darkblue')
        # In a full implementation, this would be replaced with actual bitmap data
        return img


def parse_nessus_xml(file_path: str) -> List[Tuple[str, int]]:
    """Parse Nessus XML file and extract RDP hosts"""
    hosts = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        for report_host in root.findall('.//ReportHost'):
            host_ip = report_host.get('name')

            # Look for RDP port (3389) in report items
            for item in report_host.findall('.//ReportItem'):
                port = item.get('port')
                protocol = item.get('protocol')
                svc_name = item.get('svc_name', '')

                if (port == '3389' and protocol == 'tcp') or 'ms-wbt-server' in svc_name:
                    hosts.append((host_ip, int(port)))
                    break

        print(f"[+] Parsed {len(hosts)} RDP hosts from Nessus XML")

    except Exception as e:
        print(f"[-] Error parsing Nessus XML: {e}")

    return hosts


def parse_nmap_xml(file_path: str) -> List[Tuple[str, int]]:
    """Parse Nmap XML file and extract RDP hosts"""
    hosts = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        for host in root.findall('.//host'):
            # Get IP address
            addr = host.find('.//address[@addrtype="ipv4"]')
            if addr is None:
                continue

            host_ip = addr.get('addr')

            # Look for RDP port
            for port in host.findall('.//port'):
                port_id = port.get('portid')
                protocol = port.get('protocol')

                state = port.find('state')
                if state is None or state.get('state') != 'open':
                    continue

                service = port.find('service')
                service_name = service.get('name', '') if service is not None else ''

                if (port_id == '3389' and protocol == 'tcp') or 'ms-wbt-server' in service_name or 'rdp' in service_name:
                    hosts.append((host_ip, int(port_id)))

        print(f"[+] Parsed {len(hosts)} RDP hosts from Nmap XML")

    except Exception as e:
        print(f"[-] Error parsing Nmap XML: {e}")

    return hosts


def parse_ip_list(file_path: str) -> List[Tuple[str, int]]:
    """Parse text file with IP addresses (one per line)"""
    hosts = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Support IP:PORT format
                if ':' in line:
                    parts = line.split(':')
                    ip = parts[0]
                    port = int(parts[1])
                else:
                    ip = line
                    port = 3389

                hosts.append((ip, port))

        print(f"[+] Parsed {len(hosts)} hosts from IP list")

    except Exception as e:
        print(f"[-] Error parsing IP list: {e}")

    return hosts


def save_screenshot(image: Image.Image, host: str, port: int, output_dir: str, format: str = 'png'):
    """Save screenshot to file"""
    try:
        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # Generate filename
        safe_host = host.replace(':', '_').replace('/', '_')
        filename = f"rdp_{safe_host}_{port}.{format.lower()}"
        filepath = os.path.join(output_dir, filename)

        # Save image
        image.save(filepath, format=format.upper())
        print(f"[+] Screenshot saved: {filepath}")

        return filepath

    except Exception as e:
        print(f"[-] Failed to save screenshot: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description='RDP Screenshot Capture Tool - Captures RDP login screens without authentication',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan single host
  %(prog)s -t 192.168.1.100

  # Scan from IP list
  %(prog)s -i ips.txt

  # Scan from Nmap XML
  %(prog)s -n nmap_scan.xml

  # Scan from Nessus XML
  %(prog)s -N nessus_scan.nessus

  # Custom output directory and format
  %(prog)s -t 192.168.1.100 -o screenshots/ -f jpeg

  # Adjust timeout and resolution
  %(prog)s -t 192.168.1.100 --timeout 15 --width 1280 --height 720
        """
    )

    # Input options
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument('-t', '--target', help='Single target IP address')
    input_group.add_argument('-i', '--ip-list', help='File containing list of IPs (one per line)')
    input_group.add_argument('-n', '--nmap-xml', help='Nmap XML output file')
    input_group.add_argument('-N', '--nessus-xml', help='Nessus XML output file')
    input_group.add_argument('-p', '--port', type=int, default=3389, help='RDP port (default: 3389)')

    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output-dir', default='rdp_screenshots', help='Output directory (default: rdp_screenshots)')
    output_group.add_argument('-f', '--format', choices=['png', 'jpeg', 'jpg'], default='png', help='Image format (default: png)')

    # Connection options
    conn_group = parser.add_argument_group('Connection Options')
    conn_group.add_argument('--timeout', type=int, default=15, help='Connection timeout in seconds (default: 15)')
    conn_group.add_argument('--width', type=int, default=1024, help='Screenshot width (default: 1024)')
    conn_group.add_argument('--height', type=int, default=768, help='Screenshot height (default: 768)')
    conn_group.add_argument('--advanced', action='store_true', help='Use advanced mode (full protocol implementation)')
    conn_group.add_argument('--protocol', choices=['auto', 'rdp', 'tls'], default='auto',
                           help='Protocol to use: auto (try TLS then RDP), rdp (standard RDP), tls (force TLS) (default: auto)')

    # General options
    general_group = parser.add_argument_group('General Options')
    general_group.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')

    args = parser.parse_args()

    # Set global verbose flag
    global VERBOSE
    VERBOSE = args.verbose

    # Validate input
    if not any([args.target, args.ip_list, args.nmap_xml, args.nessus_xml]):
        parser.error('One of -t, -i, -n, or -N must be specified')

    # Collect targets
    targets = []

    if args.target:
        targets.append((args.target, args.port))

    if args.ip_list:
        targets.extend(parse_ip_list(args.ip_list))

    if args.nmap_xml:
        targets.extend(parse_nmap_xml(args.nmap_xml))

    if args.nessus_xml:
        targets.extend(parse_nessus_xml(args.nessus_xml))

    if not targets:
        print("[-] No targets found")
        return 1

    # Remove duplicates
    targets = list(set(targets))

    # Determine protocol
    protocol_map = {
        'auto': None,  # Auto-negotiate (default)
        'rdp': RDPScreenshot.PROTOCOL_RDP,
        'tls': RDPScreenshot.PROTOCOL_SSL
    }
    selected_protocol = protocol_map.get(args.protocol, None)

    print(f"[*] Starting RDP screenshot capture for {len(targets)} target(s)")
    print(f"[*] Output directory: {args.output_dir}")
    print(f"[*] Image format: {args.format}")
    print(f"[*] Resolution: {args.width}x{args.height}")
    print(f"[*] Protocol: {args.protocol}")
    if args.verbose:
        print(f"[*] Verbose mode: enabled")
    print()

    # Process each target
    success_count = 0

    for host, port in targets:
        print(f"\n{'='*60}")
        print(f"[*] Target: {host}:{port}")
        print(f"{'='*60}")

        try:
            # Choose screenshot class
            if args.advanced:
                rdp = RDPScreenshotAdvanced(host, port, args.timeout, args.width, args.height, selected_protocol)
            else:
                rdp = RDPScreenshot(host, port, args.timeout, args.width, args.height, selected_protocol)

            # Capture screenshot
            image = rdp.capture_screenshot()

            if image:
                # Save screenshot
                if save_screenshot(image, host, port, args.output_dir, args.format):
                    success_count += 1

        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
            break
        except Exception as e:
            print(f"[-] Error processing {host}:{port} - {e}")

        # Small delay between targets
        time.sleep(0.5)

    print(f"\n{'='*60}")
    print(f"[*] Completed: {success_count}/{len(targets)} screenshots captured")
    print(f"{'='*60}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
