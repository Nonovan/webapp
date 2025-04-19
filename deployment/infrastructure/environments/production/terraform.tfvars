environment = "production"
primary_region = "us-west-2"
secondary_region = "us-east-1"
domain_name = "cloud-platform.example.com"

# These values should be passed as sensitive variables
# db_username = "cloud_platform_app"
# db_password = "secure-password"

ssh_allowed_ips = [
  "203.0.113.10/32",  # Office IP
  "198.51.100.5/32"   # VPN IP
]

enable_ics_components = true
ics_restricted_ips = [
  "10.100.0.0/16",    # Industrial network
  "192.168.10.0/24"   # Control room network
]