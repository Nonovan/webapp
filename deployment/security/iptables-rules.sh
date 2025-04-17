#!/bin/bash
# IPTables firewall rules for Cloud Infrastructure Platform
# This script sets up firewall rules to protect the application servers

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback interface
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established and related connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (restrict to specific IPs in production)
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
# For production, use:
# iptables -A INPUT -p tcp --dport 22 -s YOUR_TRUSTED_IP/32 -m state --state NEW -j ACCEPT

# Allow HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT

# Allow specific ports for services
# PostgreSQL (restrict to internal network)
iptables -A INPUT -p tcp --dport 5432 -s 10.0.0.0/8 -m state --state NEW -j ACCEPT

# Redis (restrict to internal network)
iptables -A INPUT -p tcp --dport 6379 -s 10.0.0.0/8 -m state --state NEW -j ACCEPT

# Prometheus (restrict to internal network)
iptables -A INPUT -p tcp --dport 9090 -s 10.0.0.0/8 -m state --state NEW -j ACCEPT

# Grafana (restrict to internal network)
iptables -A INPUT -p tcp --dport 3000 -s 10.0.0.0/8 -m state --state NEW -j ACCEPT

# Allow ping but rate limit to prevent ping floods
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 2/s -j ACCEPT

# Log and drop invalid packets
iptables -A INPUT -m state --state INVALID -j LOG --log-prefix "FIREWALL:INVALID:"
iptables -A INPUT -m state --state INVALID -j DROP

# Log and drop all other packets
iptables -A INPUT -j LOG --log-prefix "FIREWALL:DROP:"
iptables -A INPUT -j DROP

# Rate limit connection attempts to prevent brute force attacks
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --update --seconds 20 --hitcount 30 -j DROP
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m recent --update --seconds 20 --hitcount 30 -j DROP

# Block known malicious IPs (example - replace with actual IPs)
for IP in $(cat /etc/cloud-platform/security/blocked-ips.txt); do
    iptables -A INPUT -s $IP -j DROP
done

# Save rules
echo "Saving IPTables rules..."
if command -v iptables-save > /dev/null 2>&1; then
    iptables-save > /etc/iptables/rules.v4
    echo "Rules saved to /etc/iptables/rules.v4"
else
    echo "iptables-save not found. Please save the rules manually."
fi

echo "Firewall rules have been configured."
