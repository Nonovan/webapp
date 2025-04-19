environment = "production"
primary_region = "us-east-1"  # Swapped from normal production config
secondary_region = "us-west-2"  # Swapped from normal production config
domain_name = "cloud-platform.example.com"

# DR mode settings
is_dr_recovery = true
skip_regional_peering = true
emergency_mode = true

# Reduced capacity settings for emergency operations
compute_min_size = 2
compute_max_size = 10
compute_desired_capacity = 2

# Use same IPs and security settings as production
ssh_allowed_ips = [
  "203.0.113.10/32",  # Office IP
  "198.51.100.5/32"   # VPN IP
]

enable_ics_components = true
ics_restricted_ips = [
  "10.100.0.0/16",    # Industrial network
  "192.168.10.0/24"   # Control room network
]