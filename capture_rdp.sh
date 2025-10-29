#!/bin/bash
# Capture RDP packets from working xfreerdp connection

TARGET="172.21.2.32"
OUTPUT="xfreerdp_capture.pcap"

echo "[*] Capturing packets from xfreerdp connection to $TARGET"
echo "[*] Output: $OUTPUT"
echo "[*] Press Ctrl+C after the RDP window appears"
echo ""

# Start tcpdump in background
sudo tcpdump -i any -w "$OUTPUT" "host $TARGET and port 3389" &
TCPDUMP_PID=$!

# Wait a moment for tcpdump to start
sleep 1

# Run xfreerdp
echo "[*] Starting xfreerdp..."
xfreerdp /v:$TARGET /cert-ignore /sec:rdp +auth-only 2>/dev/null

# Stop tcpdump
sudo kill $TCPDUMP_PID 2>/dev/null

echo ""
echo "[*] Capture complete: $OUTPUT"
echo "[*] Analyze with: tshark -r $OUTPUT -V"
echo "[*] Or: tcpdump -r $OUTPUT -X"
