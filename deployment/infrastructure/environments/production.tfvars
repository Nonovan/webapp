# Production Environment Terraform Variables

# Environment settings
environment = "production"
primary_region = "us-west-2"
secondary_region = "us-east-1"
domain_name = "cloud-platform.example.com"

# Network configuration
vpc_cidr_primary = "10.0.0.0/16"
vpc_cidr_secondary = "10.1.0.0/16"

# Access configuration - restrict SSH to specific IPs
ssh_allowed_ips = [
  "203.0.113.10/32",  # Office IP
  "198.51.100.5/32"   # VPN IP
]

# Feature flags
enable_ics_components = true
emergency_mode = false
skip_regional_peering = false

# Compute settings - robust for production
compute_min_size = 3
compute_max_size = 30
compute_desired_capacity = 4

# For the DR region (secondary)
dr_compute_min_size = 2
dr_compute_max_size = 30
dr_compute_desired_capacity = 2

# Database settings - larger instance for production
db_instance_class = "db.r5.large"
db_allocated_storage = 100
db_multi_az = true
db_backup_retention_days = 30

# Monitoring settings
enable_enhanced_monitoring = true
metrics_retention_days = 90
detailed_monitoring = true

# DNS settings
create_zone = true # Manage the Route53 zone in production

# Security settings
waf_enabled = true
cloudtrail_enabled = true
flow_logs_enabled = true
ssl_policy = "ELBSecurityPolicy-FS-1-2-Res-2020-10"

# ICS settings
ics_restricted_ips = [
  "10.100.0.0/16",    # Industrial network
  "192.168.10.0/24"   # Control room network
]

# Application settings
api_rate_limit = 1000
app_threads = 8
app_workers = 16

# Monitoring/alerting settings
alarm_actions = [
  "arn:aws:sns:us-west-2:123456789012:production-critical-alerts",
  "arn:aws:sns:us-west-2:123456789012:ops-team-alerts"
]
dr_alarm_actions = [
  "arn:aws:sns:us-east-1:123456789012:dr-alerts"
]

# Compliance settings
enable_compliance_checks = true
enable_security_hub = true
enable_config = true

# Database replication
enable_cross_region_replication = true