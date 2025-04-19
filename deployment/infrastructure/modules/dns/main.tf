/**
 * DNS Module for Cloud Infrastructure Platform
 * 
 * Sets up Route53 for failover between primary and secondary regions.
 */

resource "aws_route53_zone" "main" {
  count = var.create_zone ? 1 : 0
  name  = var.domain_name
  
  tags = var.tags
}

data "aws_route53_zone" "selected" {
  name         = var.domain_name
  private_zone = false
  zone_id      = var.create_zone ? aws_route53_zone.main[0].id : var.zone_id
}

# Health check for primary region
resource "aws_route53_health_check" "primary" {
  fqdn              = var.primary_lb_dns_name
  port              = 443
  type              = "HTTPS"
  resource_path     = var.health_check_path
  failure_threshold = 3
  request_interval  = 30
  
  tags = merge(var.tags, {
    Name = "${var.environment}-primary-health-check"
  })
}

# Health check for secondary region
resource "aws_route53_health_check" "secondary" {
  fqdn              = var.secondary_lb_dns_name
  port              = 443
  type              = "HTTPS"
  resource_path     = var.health_check_path
  failure_threshold = 3
  request_interval  = 30
  
  tags = merge(var.tags, {
    Name = "${var.environment}-secondary-health-check"
  })
}

# Main record with failover routing policy
resource "aws_route53_record" "primary" {
  zone_id         = data.aws_route53_zone.selected.zone_id
  name            = var.environment == "production" ? var.domain_name : "${var.environment}.${var.domain_name}"
  type            = "A"
  
  failover_routing_policy {
    type = "PRIMARY"
  }
  
  set_identifier  = "${var.environment}-primary"
  health_check_id = aws_route53_health_check.primary.id
  
  alias {
    name                   = var.primary_lb_dns_name
    zone_id                = var.primary_lb_zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "secondary" {
  zone_id         = data.aws_route53_zone.selected.zone_id
  name            = var.environment == "production" ? var.domain_name : "${var.environment}.${var.domain_name}"
  type            = "A"
  
  failover_routing_policy {
    type = "SECONDARY"
  }
  
  set_identifier  = "${var.environment}-secondary"
  health_check_id = aws_route53_health_check.secondary.id
  
  alias {
    name                   = var.secondary_lb_dns_name
    zone_id                = var.secondary_lb_zone_id
    evaluate_target_health = true
  }
}

# Region-specific records for explicit access
resource "aws_route53_record" "primary_region" {
  zone_id = data.aws_route53_zone.selected.zone_id
  name    = "primary.${var.environment == "production" ? var.domain_name : "${var.environment}.${var.domain_name}"}"
  type    = "A"
  
  alias {
    name                   = var.primary_lb_dns_name
    zone_id                = var.primary_lb_zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "secondary_region" {
  zone_id = data.aws_route53_zone.selected.zone_id
  name    = "secondary.${var.environment == "production" ? var.domain_name : "${var.environment}.${var.domain_name}"}"
  type    = "A"
  
  alias {
    name                   = var.secondary_lb_dns_name
    zone_id                = var.secondary_lb_zone_id
    evaluate_target_health = true
  }
}