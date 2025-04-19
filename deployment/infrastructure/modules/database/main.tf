/**
 * Database Module for Cloud Infrastructure Platform
 * 
 * Sets up PostgreSQL database with replication between regions for disaster recovery.
 */

resource "aws_db_subnet_group" "default" {
  name        = "${var.environment}-db-subnet-group-${var.region}"
  description = "DB subnet group for ${var.environment} in ${var.region}"
  subnet_ids  = var.subnet_ids
  
  tags = merge(var.tags, {
    Name = "${var.environment}-db-subnet-group-${var.region}"
  })
}

resource "aws_db_parameter_group" "default" {
  name        = "${var.environment}-db-params-${var.region}"
  family      = "postgres13"
  description = "DB parameter group for ${var.environment} in ${var.region}"
  
  # Parameters for replication if this is a primary instance
  dynamic "parameter" {
    for_each = var.is_primary && var.replicate_to_secondary ? [1] : []
    content {
      name  = "rds.logical_replication"
      value = "1"
    }
  }
  
  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements"
  }
  
  parameter {
    name  = "log_statement"
    value = "ddl"
  }
  
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
  
  tags = merge(var.tags, {
    Name = "${var.environment}-db-params-${var.region}"
  })
}

# Primary/standalone database instance
resource "aws_db_instance" "default" {
  identifier           = "${var.environment}-db-${var.region}"
  engine               = "postgres"
  engine_version       = var.engine_version
  instance_class       = var.instance_class
  allocated_storage    = var.allocated_storage
  storage_type         = "gp2"
  storage_encrypted    = true
  
  db_name              = var.database_name
  username             = var.db_username
  password             = var.db_password
  
  vpc_security_group_ids = var.security_group_ids
  db_subnet_group_name   = aws_db_subnet_group.default.name
  parameter_group_name   = aws_db_parameter_group.default.name
  
  multi_az             = var.is_production
  publicly_accessible  = false
  skip_final_snapshot  = !var.is_production
  deletion_protection  = var.is_production
  
  backup_retention_period = var.is_primary ? 7 : 1
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:30-sun:05:30"
  
  # Enable replication to secondary region if this is primary
  dynamic "replicate_source_db" {
    for_each = var.is_primary ? [] : [1]
    content {
      source_db_instance_identifier = "arn:aws:rds:${var.primary_region}:${data.aws_caller_identity.current.account_id}:db:${var.environment}-db-${var.primary_region}"
    }
  }
  
  tags = merge(var.tags, {
    Name = "${var.environment}-db-${var.region}"
  })
}

# Provision a read replica if this is the primary and replication is enabled
resource "aws_db_instance" "replica" {
  count                = var.is_primary && var.replicate_to_secondary ? 1 : 0
  identifier           = "${var.environment}-db-replica-${var.region}"
  
  replicate_source_db  = aws_db_instance.default.identifier
  instance_class       = var.replica_instance_class != "" ? var.replica_instance_class : var.instance_class
  
  vpc_security_group_ids = var.security_group_ids
  parameter_group_name   = aws_db_parameter_group.default.name
  
  publicly_accessible  = false
  skip_final_snapshot  = !var.is_production
  
  tags = merge(var.tags, {
    Name = "${var.environment}-db-replica-${var.region}"
  })
}

# Get current account ID
data "aws_caller_identity" "current" {}