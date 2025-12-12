#!/bin/bash
#
# simulate_waveform.sh - Simulate serial waveform data using socat
#
# This script creates a virtual serial port pair (PTY) and generates
# simulated multi-variable data in the format Variable:Value
#
# Usage:
#   ./simulate_waveform.sh
#
# The script will output the path to the slave PTY device that you should
# use to connect from the WebSerial terminal (via browser's serial port selection).
#
# Requirements:
#   - socat (apt install socat)
#   - Python 3 or bash with bc for math functions
#
# Author: Generated for Entrance Server Management Dashboard

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INTERVAL=0.02  # 50 Hz update rate (20ms interval)

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}       ${GREEN}Waveform Simulation for WebSerial Terminal${NC}           ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check for socat
if ! command -v socat &> /dev/null; then
    echo -e "${RED}Error: socat is not installed.${NC}"
    echo "Install it with: sudo apt install socat"
    exit 1
fi

# Check for Python3 (preferred) or bc (fallback)
USE_PYTHON=false
if command -v python3 &> /dev/null; then
    USE_PYTHON=true
    echo -e "${GREEN}✓ Using Python 3 for data generation${NC}"
elif command -v bc &> /dev/null; then
    echo -e "${YELLOW}✓ Using bc for data generation (Python 3 preferred)${NC}"
else
    echo -e "${RED}Error: Neither python3 nor bc is available.${NC}"
    echo "Install Python 3: sudo apt install python3"
    exit 1
fi

# Create a cleanup handler
cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"
    # Kill background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    # Remove symbolic link if created
    [ -L /tmp/vserial ] && rm -f /tmp/vserial
    echo -e "${GREEN}Done.${NC}"
}
trap cleanup EXIT INT TERM

# Create PTY pair using socat
echo -e "${BLUE}Creating virtual serial port pair...${NC}"

# Create a PTY pair - one end for our data generator, one for the browser
# PTY0 = Master (our data generator writes here)
# PTY1 = Slave (browser connects here)
socat -d -d pty,raw,echo=0,link=/tmp/vserial_master pty,raw,echo=0,link=/tmp/vserial_slave &
SOCAT_PID=$!

# Wait for socat to create the links
sleep 1

if [ ! -L /tmp/vserial_master ] || [ ! -L /tmp/vserial_slave ]; then
    echo -e "${RED}Error: Failed to create virtual serial ports${NC}"
    exit 1
fi

MASTER_PTY=$(readlink -f /tmp/vserial_master)
SLAVE_PTY=$(readlink -f /tmp/vserial_slave)

echo -e "${GREEN}✓ Virtual serial port pair created${NC}"
echo ""
echo -e "╭──────────────────────────────────────────────────────────────╮"
echo -e "│ ${YELLOW}Connect to this device in your browser:${NC}                      │"
echo -e "│                                                              │"
echo -e "│   ${GREEN}${SLAVE_PTY}${NC}"
echo -e "│                                                              │"
echo -e "│ The WebSerial API should show this device in the selection  │"
echo -e "│ dialog when you click 'Connect Serial Port' button.         │"
echo -e "╰──────────────────────────────────────────────────────────────╯"
echo ""
echo -e "${BLUE}Generating waveform data (Ctrl+C to stop)...${NC}"
echo ""

# Data generation function using Python (more accurate)
generate_data_python() {
    python3 << 'PYEOF'
import math
import time
import random
import sys

t = 0.0
interval = 0.02  # 50 Hz

# Open the master PTY for writing
with open('/tmp/vserial_master', 'w', buffering=1) as f:
    while True:
        try:
            # Generate sine wave (1 Hz)
            sin_val = math.sin(2 * math.pi * 1.0 * t)

            # Generate cosine wave (1 Hz, phase shifted)
            cos_val = math.cos(2 * math.pi * 1.0 * t)

            # Generate a higher frequency sine (3 Hz)
            sin3_val = 0.5 * math.sin(2 * math.pi * 3.0 * t)

            # Generate simulated ADC values (0-4095 range with noise)
            adc_base = 2048 + 1800 * math.sin(2 * math.pi * 0.5 * t)
            adc_val = int(adc_base + random.gauss(0, 50))
            adc_val = max(0, min(4095, adc_val))  # Clamp to 12-bit range

            # Generate simulated temperature (20-30 range with slow drift)
            temp_val = 25.0 + 5.0 * math.sin(2 * math.pi * 0.1 * t) + random.gauss(0, 0.2)

            # Output in Variable:Value format
            f.write(f"Sin:{sin_val:.3f}\n")
            f.write(f"Cos:{cos_val:.3f}\n")
            f.write(f"Sin3Hz:{sin3_val:.3f}\n")
            f.write(f"ADC:{adc_val}\n")
            f.write(f"Temp:{temp_val:.2f}\n")
            f.flush()

            # Increment time
            t += interval

            # Sleep
            time.sleep(interval)

        except BrokenPipeError:
            # Browser disconnected, continue waiting
            time.sleep(0.5)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            time.sleep(1)
PYEOF
}

# Data generation function using bash/bc (fallback)
generate_data_bc() {
    local t=0
    local pi="3.14159265358979"

    while true; do
        # Generate values using bc
        sin_val=$(echo "scale=3; s(2*$pi*1.0*$t)" | bc -l)
        cos_val=$(echo "scale=3; c(2*$pi*1.0*$t)" | bc -l)
        sin3_val=$(echo "scale=3; 0.5*s(2*$pi*3.0*$t)" | bc -l)

        # Simplified ADC (triangular wave approximation)
        adc_base=$(echo "scale=0; 2048 + 1800*s(2*$pi*0.5*$t)" | bc -l)
        noise=$((RANDOM % 100 - 50))
        adc_val=$((adc_base + noise))
        [ $adc_val -lt 0 ] && adc_val=0
        [ $adc_val -gt 4095 ] && adc_val=4095

        # Temperature
        temp_base=$(echo "scale=2; 25.0 + 5.0*s(2*$pi*0.1*$t)" | bc -l)
        temp_noise=$(echo "scale=2; ($RANDOM % 40 - 20) / 100" | bc -l)
        temp_val=$(echo "scale=2; $temp_base + $temp_noise" | bc -l)

        # Output to master PTY
        {
            echo "Sin:${sin_val}"
            echo "Cos:${cos_val}"
            echo "Sin3Hz:${sin3_val}"
            echo "ADC:${adc_val}"
            echo "Temp:${temp_val}"
        } > /tmp/vserial_master

        # Increment time
        t=$(echo "scale=4; $t + $INTERVAL" | bc)

        sleep $INTERVAL
    done
}

# Display live info
echo "Data format examples:"
echo "  Sin:-0.866"
echo "  Cos:0.500"
echo "  Sin3Hz:0.433"
echo "  ADC:2847"
echo "  Temp:27.35"
echo ""
echo -e "${YELLOW}Generating data at 50 Hz (5 variables)...${NC}"
echo ""

# Start data generation
if [ "$USE_PYTHON" = true ]; then
    generate_data_python
else
    generate_data_bc
fi
