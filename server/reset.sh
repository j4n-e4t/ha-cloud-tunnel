#!/bin/sh
# Reset server state - removes credentials and client binding
rm -f /data/state.json
echo "Server state reset. Restart the server to generate new credentials."
