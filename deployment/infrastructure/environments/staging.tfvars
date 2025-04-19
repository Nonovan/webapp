# Staging Environment Terraform Variables

# Environment settings
environment = "staging"
primary_region = "us-west-2"
secondary_region = "us-east-1"
domain_name = "staging.cloud-platform.example.com"

# Network configuration
vpc_cidr_primary = "10.20.0.0/16"
vpc_cidr_secondary = "10.21.0.0/16"

# Access configuration
ssh_allowed_ips = [
  "203.0.113.10/32",  # Office IP
  "198.51.100.5/32"   # VPN IP
]

# Feature flags
enable_ics_components = true
emergency_mode = false
skip_regional_peering = false

# Compute settings - moderate for staging
compute_min_size = 2
compute_max_size = 10
compute_desired_capacity = 2

# Database settings - medium instance for staging
db_instance_class = "db.r5.large"
db_allocated_storage = 50
db_multi_az = true
db_backup_retention_days = 7

# Monitoring settings
enable_enhanced_monitoring = true
metrics_retention_days = 30
detailed_monitoring = true

# DNS settings
create_zone = false
zone_id = "Z2EXAMPLE123456" # Existing Route53 zone ID for staging

# Security settings
waf_enabled = true
flow_logs_enabled = true
ssl_policy = "ELBSecurityPolicy-FS-1-2-Res-2020-10"

# ICS settings
ics_restricted_ips = [
  "10.100.0.0/16",   # Industrial network
  "192.168.10.0/24"  # Control room network
]

# Monitoring/alerting settings
alarm_actions = [
  "arn:aws:sns:us-west-2:123456789012:staging-alerts"
]