#!/bin/bash
# Capture complete xfreerdp MCS Connect Initial packet

echo "Starting packet capture for xfreerdp connection..."
echo "This will capture the MCS Connect Initial packet (should be 451 bytes)"
echo ""

# Start tcpdump in background
sudo tcpdump -i any -s 0 -w /tmp/rdp_capture_full.pcap "tcp port 3389" 2>&1 &
TCPDUMP_PID=$!

echo "Waiting 2 seconds for tcpdump to start..."
sleep 2

echo "Connecting with xfreerdp..."
timeout 5 xfreerdp /v:172.21.2.32 /cert-ignore /sec:rdp +auth-only 2>&1 | head -5 || true

echo "Waiting 2 seconds for packets to be captured..."
sleep 2

echo "Stopping tcpdump..."
sudo kill $TCPDUMP_PID 2>/dev/null || true
sleep 1

echo ""
echo "Extracting MCS Connect Initial packet..."

# Extract the MCS Connect Initial (look for pattern: 03 00 01 c3 02 f0 80 7f 65)
sudo tshark -r /tmp/rdp_capture_full.pcap -Y "tcp.dstport == 3389 and tcp.len > 400" \
    -T fields -e data 2>/dev/null | head -1 | sed 's/://g' > /tmp/mcs_packet.hex

if [ -s /tmp/mcs_packet.hex ]; then
    PACKET_HEX=$(cat /tmp/mcs_packet.hex)
    PACKET_LEN=$((${#PACKET_HEX} / 2))

    echo "Captured packet: $PACKET_LEN bytes"
    echo ""
    echo "Hex dump (first 100 bytes):"
    echo "$PACKET_HEX" | fold -w 64 | head -10
    echo ""
    echo "Full packet saved to: /tmp/mcs_packet.hex"
    echo ""
    echo "To see full packet:"
    echo "  cat /tmp/mcs_packet.hex"
else
    echo "ERROR: No packet captured!"
    echo "Make sure 172.21.2.32:3389 is accessible and xfreerdp can connect."
fi

echo ""
echo "Cleaning up..."
rm -f /tmp/rdp_capture_full.pcap
