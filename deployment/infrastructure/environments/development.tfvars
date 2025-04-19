# Development Environment Terraform Variables

# Environment settings
environment = "development"
primary_region = "us-west-2"
secondary_region = "us-east-1"
domain_name = "dev.cloud-platform.example.com"

# Network configuration
vpc_cidr_primary = "10.10.0.0/16"
vpc_cidr_secondary = "10.11.0.0/16"

# Access configuration
ssh_allowed_ips = [
  "203.0.113.10/32",  # Office IP
  "198.51.100.5/32",  # VPN IP
  "192.168.1.0/24"    # Development network
]

# Feature flags
enable_ics_components = true
emergency_mode = false
skip_regional_peering = false

# Compute settings - minimal for dev
compute_min_size = 1
compute_max_size = 3
compute_desired_capacity = 1

# Database settings - smaller instance for dev
db_instance_class = "db.t3.medium"
db_allocated_storage = 20
db_multi_az = false
db_backup_retention_days = 3

# Monitoring settings
enable_enhanced_monitoring = false
metrics_retention_days = 7
detailed_monitoring = false

# DNS settings
create_zone = false
zone_id = "Z1EXAMPLE123456" # Existing Route53 zone ID for dev

# ICS settings
ics_restricted_ips = [
  "10.100.0.0/16",   # Industrial network
  "192.168.10.0/24"  # Control room network
]