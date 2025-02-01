#!/bin/bash

# Parse command-line arguments
while getopts "i:p:m:t:q:" opt; do
  case $opt in
    i) INTERFACE=$OPTARG ;;
    p) PPS=$OPTARG ;;
    m) MBPS=$OPTARG ;;
    t) TIMEOUT=$OPTARG ;;
    q) QUESTION=$OPTARG ;;
    \?) echo "Invalid option -$OPTARG" >&2; exit 1 ;;
  esac
done

# Validate required inputs
if [ -z "$INTERFACE" ]; then
  echo "Usage: $0 -i <interface> -p <pps> [-m <mbps>] [-t <timeout>] [-q <question>]"
  exit 1
fi

# Get the current directory where the script was executed
SCRIPT_DIR=$(pwd)

# If a virtual environment exists in the current directory, prepare the source command.
if [ -d "$SCRIPT_DIR/venv" ]; then
  VENV_CMD="source $SCRIPT_DIR/venv/bin/activate && "
else
  VENV_CMD=""
fi

# Construct sniffer command.
# Use sudo $(which python3) so that the correct python is used.
SNIFFER_CMD="${VENV_CMD}sudo $(which python3) sniffer_speed.py -i $INTERFACE"
[ -n "$TIMEOUT" ] && SNIFFER_CMD+=" -t $TIMEOUT"
[ -n "$QUESTION" ] && SNIFFER_CMD+=" -q $QUESTION"

# Determine replay speed: Use Mbps if provided, otherwise use PPS
if [ -n "$MBPS" ]; then
  REPLAY_CMD="${VENV_CMD}sudo tcpreplay -i $INTERFACE --mbps=$MBPS --quiet 0.pcap"
elif [ -n "$PPS" ]; then
  REPLAY_CMD="${VENV_CMD}sudo tcpreplay -i $INTERFACE --pps=$PPS --quiet 0.pcap"
else
  echo "Error: Either -p (pps) or -m (mbps) must be specified."
  exit 1
fi

# Start sniffer in a new terminal in the same directory with venv activated
if [[ "$OSTYPE" == "darwin"* ]]; then
  # macOS: Open Terminal window
  osascript -e "tell application \"Terminal\" to do script \"cd '$SCRIPT_DIR' && $SNIFFER_CMD\""
else
  # Linux: Open a new terminal
  gnome-terminal --working-directory="$SCRIPT_DIR" -- bash -c "$SNIFFER_CMD; exec bash"
fi

# Wait for sniffer to start
sleep 2

# Start tcpreplay in a new terminal in the same directory with venv activated
if [[ "$OSTYPE" == "darwin"* ]]; then
  osascript -e "tell application \"Terminal\" to do script \"cd '$SCRIPT_DIR' && $REPLAY_CMD\""
else
  gnome-terminal --working-directory="$SCRIPT_DIR" -- bash -c "$REPLAY_CMD; exec bash"
fi

# If timeout was provided, wait for the duration before stopping replay
if [ -n "$TIMEOUT" ]; then
  sleep "$TIMEOUT"
fi

# Kill all tcpreplay processes matching the interface
TCREPLAY_PIDS=$(pgrep -f "tcpreplay -i $INTERFACE")
if [ -n "$TCREPLAY_PIDS" ]; then
  echo "Stopping tcpreplay..."
  for pid in $TCREPLAY_PIDS; do
    kill "$pid"
  done
fi

echo "Sniffer and replay session completed."
