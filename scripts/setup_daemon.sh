#!/bin/bash

set -e

PLIST_LABEL="com.hashnet.csid"
PLIST_SOURCE="$(dirname "$0")/com.hashnet.csid.plist"
PLIST_DEST="$HOME/Library/LaunchAgents/$PLIST_LABEL.plist"
LOG_DIR="$HOME/Library/Logs/Hashnet"

if [ -z "$CSID_BINARY_PATH" ]; then
    echo "Usage: CSID_BINARY_PATH=/path/to/csid $0 [install|uninstall]"
    exit 1
fi

if [ ! -f "$CSID_BINARY_PATH" ]; then
    echo "Error: csid binary not found at $CSID_BINARY_PATH"
    exit 1
fi

case "${1:-install}" in
    install)
        mkdir -p "$LOG_DIR"
        mkdir -p "$(dirname "$PLIST_DEST")"

        sed -e "s|CSID_BINARY_PATH|$CSID_BINARY_PATH|g" \
            -e "s|HOME_DIR|$HOME|g" \
            "$PLIST_SOURCE" > "$PLIST_DEST"

        chmod 644 "$PLIST_DEST"
        launchctl load "$PLIST_DEST"
        echo "csid daemon installed and started."
        echo "Logs: $LOG_DIR"
        ;;
    uninstall)
        if [ -f "$PLIST_DEST" ]; then
            launchctl unload "$PLIST_DEST"
            rm "$PLIST_DEST"
            echo "csid daemon uninstalled."
        else
            echo "csid daemon not installed."
        fi
        ;;
    *)
        echo "Usage: $0 {install|uninstall}"
        exit 1
        ;;
esac
