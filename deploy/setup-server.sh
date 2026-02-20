#!/bin/bash
# SecurityScan API Server Setup Script
# Run this on your Contabo VPS (Ubuntu 24.04)

set -e

echo "=== SecurityScan API Server Setup ==="
echo ""

# Update system
echo "[1/8] Updating system packages..."
apt update && apt upgrade -y

# Install dependencies
echo "[2/8] Installing dependencies..."
apt install -y python3.12 python3.12-venv python3-pip nginx certbot python3-certbot-nginx git ufw

# Create app user
echo "[3/8] Creating securityscan user..."
useradd -m -s /bin/bash securityscan || echo "User already exists"

# Setup firewall
echo "[4/8] Configuring firewall..."
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw --force enable

# Create app directory
echo "[5/8] Creating application directory..."
mkdir -p /opt/securityscan
chown securityscan:securityscan /opt/securityscan

# Setup Python virtual environment
echo "[6/8] Setting up Python environment..."
su - securityscan -c "cd /opt/securityscan && python3.12 -m venv venv"

# Create systemd service
echo "[7/8] Creating systemd service..."
cat > /etc/systemd/system/securityscan.service << 'EOF'
[Unit]
Description=SecurityScan API
After=network.target

[Service]
User=securityscan
Group=securityscan
WorkingDirectory=/opt/securityscan
Environment="PATH=/opt/securityscan/venv/bin"
EnvironmentFile=/opt/securityscan/.env
ExecStart=/opt/securityscan/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Create nginx config
echo "[8/8] Creating nginx configuration..."
cat > /etc/nginx/sites-available/securityscan << 'EOF'
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

ln -sf /etc/nginx/sites-available/securityscan /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "1. Copy your code to /opt/securityscan/"
echo "2. Create /opt/securityscan/.env with your API keys"
echo "3. Run: cd /opt/securityscan && ./venv/bin/pip install -r requirements.txt"
echo "4. Run: systemctl enable securityscan && systemctl start securityscan"
echo "5. (Optional) Add SSL: certbot --nginx -d yourdomain.com"
echo ""
