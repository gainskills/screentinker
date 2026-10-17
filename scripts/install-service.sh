#!/bin/bash
# Install ScreenTinker as a systemd service
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICE_FILE="$SCRIPT_DIR/remotedisplay.service"

echo "Installing ScreenTinker service..."
sudo cp "$SERVICE_FILE" /etc/systemd/system/remotedisplay.service
sudo install -d -m 0755 /etc/logrotate.d
sudo install -m 0644 "$SCRIPT_DIR/logging/screentinker.logrotate" /etc/logrotate.d/screentinker
if ! command -v logrotate >/dev/null; then
    echo "Install logrotate to activate the supplied log rotation policy."
fi
sudo systemctl daemon-reload
sudo systemctl enable remotedisplay
sudo systemctl start remotedisplay
echo "Done! Service status:"
sudo systemctl status remotedisplay --no-pager
echo ""
echo "Commands:"
echo "  sudo systemctl status remotedisplay"
echo "  sudo systemctl restart remotedisplay"
echo "  sudo tail -F /var/log/screentinker/server.log"
