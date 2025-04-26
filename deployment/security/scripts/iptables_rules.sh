#!/bin/bash
# IPTables firewall rules for Cloud Infrastructure Platform
# This script sets up firewall rules to protect the application servers

# Exit on any error
set -e

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Starting firewall configuration..."

# Flush existing rules
log "Flushing existing rules..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies
log "Setting default policies..."
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback interface
log "Configuring loopback interface..."
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established and related connections
log "Allowing established and related connections..."
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Rate limiting for new connections to prevent DoS attacks
log "Setting up rate limiting for new connections..."
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 50/s --limit-burst 100 -j ACCEPT

# Allow SSH (restrict to specific IPs in production)
log "Configuring SSH access..."
if [ "${ENVIRONMENT}" == "production" ]; then
    # Production environment - restrict SSH access
    for IP in ${TRUSTED_IPS//,/ }; do
        iptables -A INPUT -p tcp --dport 22 -s $IP -m conntrack --ctstate NEW -j ACCEPT
    done
    log "SSH restricted to trusted IPs: ${TRUSTED_IPS}"
else
    # Development/staging - allow SSH with rate limiting
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 10 -j ACCEPT
    log "SSH allowed with rate limiting"
fi

# Allow HTTP/HTTPS
log "Configuring web access..."
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# Allow specific ports for internal services (restrict to internal network)
log "Configuring internal services access..."

# Define internal networks
INTERNAL_NETS="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
IFS=',' read -ra NETWORKS <<< "$INTERNAL_NETS"

# PostgreSQL
for NET in "${NETWORKS[@]}"; do
    iptables -A INPUT -p tcp --dport 5432 -s $NET -m conntrack --ctstate NEW -j ACCEPT
done
log "PostgreSQL access restricted to internal networks"

# Redis
for NET in "${NETWORKS[@]}"; do
    iptables -A INPUT -p tcp --dport 6379 -s $NET -m conntrack --ctstate NEW -j ACCEPT
done
log "Redis access restricted to internal networks"

# Prometheus
for NET in "${NETWORKS[@]}"; do
    iptables -A INPUT -p tcp --dport 9090 -s $NET -m conntrack --ctstate NEW -j ACCEPT
done
log "Prometheus access restricted to internal networks"

# Grafana
for NET in "${NETWORKS[@]}"; do
    iptables -A INPUT -p tcp --dport 3000 -s $NET -m conntrack --ctstate NEW -j ACCEPT
done
log "Grafana access restricted to internal networks"

# Allow ping but rate limit to prevent ping floods
log "Configuring ICMP access with rate limiting..."
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 2/s --limit-burst 10 -j ACCEPT

# Log and drop invalid packets
log "Setting up invalid packet handling..."
iptables -A INPUT -m conntrack --ctstate INVALID -j LOG --log-prefix "FIREWALL:INVALID: " --log-level 6
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Log and drop all other traffic
log "Setting up default drop logging..."
iptables -A INPUT -j LOG --log-prefix "FIREWALL:DROP: " --log-level 6
iptables -A INPUT -j DROP

# Save rules (for different distributions)
log "Saving firewall rules..."
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save
elif [ -f "/etc/redhat-release" ]; then
    # RHEL/CentOS
    service iptables save
elif [ -f "/etc/debian_version" ]; then
    # Debian/Ubuntu
    iptables-save > /etc/iptables/rules.v4
else
    # Generic fallback
    iptables-save > /etc/iptables.rules
    log "Rules saved to /etc/iptables.rules. You may need to load them on boot."
fi

log "Firewall configuration completed successfully."

# Validate configuration
iptables -L -v
log "Firewall rules are now active and will persist across reboots."