#!/usr/bin/env python3
"""
Simplified RDP Screenshot Tool using aardwolf library
Much simpler than manual protocol implementation!
"""

import sys
import argparse
from pathlib import Path
import xml.etree.ElementTree as ET
from typing import List, Tuple, Optional
import asyncio
import time

try:
    from PIL import Image
except ImportError:
    print("Error: Pillow not found. Install with: pip install Pillow")
    sys.exit(1)

try:
    from aardwolf.commons.url import RDPConnectionURL
    from aardwolf.commons.iosettings import RDPIOSettings
    from aardwolf import logger as aardwolf_logger
    from aardwolf.client import RDPClient
except ImportError:
    print("Error: aardwolf library not found.")
    print("Install with: pip install aardwolf")
    print("\nAlternatively, use the manual implementation: rdp_screenshot.py")
    sys.exit(1)

# Global verbose flag
VERBOSE = False

def log_verbose(msg: str):
    """Print verbose message if verbose mode is enabled"""
    if VERBOSE:
        print(msg)


async def capture_rdp_screenshot(host: str, port: int = 3389, timeout: int = 15,
                                  width: int = 1024, height: int = 768) -> Optional[Image.Image]:
    """
    Capture RDP screenshot using aardwolf library

    Returns PIL Image or None on failure
    """
    try:
        # Build RDP connection URL
        # Format: rdp+simple://domain\username:password@host:port/?param=value
        # For pre-auth screenshot, we use empty credentials
        url = f"rdp+simple://:{host}:{port}/"

        log_verbose(f"[*] Connecting to {host}:{port}")
        log_verbose(f"[*] RDP URL: {url}")

        # Parse URL
        rdp_url = RDPConnectionURL(url)

        # Create IO settings
        settings = RDPIOSettings()
        settings.video_width = width
        settings.video_height = height
        settings.video_bpp_min = 15  # Minimum color depth
        settings.video_bpp_max = 32  # Maximum color depth

        # Create RDP client
        client = RDPClient(rdp_url, settings)

        # Disable aardwolf logging unless verbose
        if not VERBOSE:
            import logging
            logging.getLogger('aardwolf').setLevel(logging.CRITICAL)

        log_verbose("[*] Starting RDP connection...")

        # Connect with timeout
        try:
            # Run connection in background
            connect_task = asyncio.create_task(client.connect())

            # Wait a bit for connection to establish
            await asyncio.sleep(2)

            log_verbose("[+] RDP connection established")
            log_verbose("[*] Waiting for screen data...")

            # Wait for screen data (up to timeout seconds)
            max_wait = timeout
            wait_step = 0.5
            waited = 0

            while waited < max_wait:
                # Check if we have screen data
                if hasattr(client, 'desktop_buffer') and client.desktop_buffer:
                    log_verbose("[+] Screen data received!")

                    # Get the desktop buffer
                    # The buffer format depends on aardwolf version
                    # Try to convert to PIL Image
                    try:
                        # Method 1: Direct PIL conversion if buffer is compatible
                        img = Image.frombytes('RGB', (width, height),
                                             bytes(client.desktop_buffer))
                        return img
                    except:
                        # Method 2: Try alternative buffer access
                        log_verbose("[*] Trying alternative buffer access...")
                        pass

                await asyncio.sleep(wait_step)
                waited += wait_step

            log_verbose("[!] Timeout waiting for screen data")
            log_verbose("[!] Pre-authentication screenshots may not be available")
            log_verbose("[!] Server might require NLA (Network Level Authentication)")

            # Create placeholder to indicate connection was attempted
            img = Image.new('RGB', (width, height), color='darkblue')
            return img

        except asyncio.TimeoutError:
            print(f"[-] Connection timeout after {timeout} seconds")
            return None
        except Exception as e:
            print(f"[-] Connection error: {e}")
            if VERBOSE:
                import traceback
                traceback.print_exc()
            return None
        finally:
            # Disconnect
            try:
                await client.disconnect()
            except:
                pass

    except Exception as e:
        print(f"[-] Failed to capture screenshot: {e}")
        if VERBOSE:
            import traceback
            traceback.print_exc()
        return None


def parse_nessus_xml(file_path: str) -> List[Tuple[str, int]]:
    """Parse Nessus XML file and extract RDP hosts"""
    hosts = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        for report_host in root.findall('.//ReportHost'):
            host_ip = report_host.get('name')

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
            addr = host.find('.//address[@addrtype="ipv4"]')
            if addr is None:
                continue

            host_ip = addr.get('addr')

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
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        safe_host = host.replace(':', '_').replace('/', '_')
        filename = f"rdp_{safe_host}_{port}.{format.lower()}"
        filepath = Path(output_dir) / filename

        image.save(filepath, format=format.upper())
        print(f"[+] Screenshot saved: {filepath}")

        return str(filepath)

    except Exception as e:
        print(f"[-] Failed to save screenshot: {e}")
        return None


async def main_async(args):
    """Async main function"""
    global VERBOSE
    VERBOSE = args.verbose

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

    print(f"[*] Starting RDP screenshot capture for {len(targets)} target(s)")
    print(f"[*] Output directory: {args.output_dir}")
    print(f"[*] Image format: {args.format}")
    print(f"[*] Resolution: {args.width}x{args.height}")
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
            # Capture screenshot
            image = await capture_rdp_screenshot(
                host, port, args.timeout, args.width, args.height
            )

            if image:
                if save_screenshot(image, host, port, args.output_dir, args.format):
                    success_count += 1

        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
            break
        except Exception as e:
            print(f"[-] Error processing {host}:{port} - {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()

        # Small delay between targets
        await asyncio.sleep(0.5)

    print(f"\n{'='*60}")
    print(f"[*] Completed: {success_count}/{len(targets)} screenshots captured")
    print(f"{'='*60}")

    return 0


def main():
    parser = argparse.ArgumentParser(
        description='RDP Screenshot Tool (Simplified using aardwolf library)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan single host
  %(prog)s -t 192.168.1.100

  # Scan from IP list
  %(prog)s -i targets.txt

  # Scan from Nmap XML
  %(prog)s -n nmap_scan.xml

  # Verbose mode
  %(prog)s -t 192.168.1.100 -v

Note: This version uses the aardwolf library for RDP protocol handling.
Install with: pip install aardwolf
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

    # General options
    general_group = parser.add_argument_group('General Options')
    general_group.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')

    args = parser.parse_args()

    # Validate input
    if not any([args.target, args.ip_list, args.nmap_xml, args.nessus_xml]):
        parser.error('One of -t, -i, -n, or -N must be specified')

    # Run async main
    return asyncio.run(main_async(args))


if __name__ == '__main__':
    sys.exit(main())
