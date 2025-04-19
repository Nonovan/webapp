/**
 * Networking Module for Cloud Infrastructure Platform
 * 
 * Sets up VPC, subnets, routing, and security groups in specified region.
 */

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  
  tags = merge(var.tags, {
    Name = "${var.environment}-vpc-${var.region}"
  })
}

# Create public subnets in each availability zone
resource "aws_subnet" "public" {
  count             = length(var.subnet_cidrs.public)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.subnet_cidrs.public[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  
  tags = merge(var.tags, {
    Name = "${var.environment}-public-subnet-${count.index + 1}-${var.region}"
    Tier = "public"
  })
}

# Create private application subnets in each availability zone
resource "aws_subnet" "private_app" {
  count             = length(var.subnet_cidrs.private_app)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.subnet_cidrs.private_app[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  tags = merge(var.tags, {
    Name = "${var.environment}-private-app-subnet-${count.index + 1}-${var.region}"
    Tier = "private"
    SubTier = "application"
  })
}

# Create private database subnets in each availability zone
resource "aws_subnet" "private_db" {
  count             = length(var.subnet_cidrs.private_db)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.subnet_cidrs.private_db[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  tags = merge(var.tags, {
    Name = "${var.environment}-private-db-subnet-${count.index + 1}-${var.region}"
    Tier = "private"
    SubTier = "database"
  })
}

# Create Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  
  tags = merge(var.tags, {
    Name = "${var.environment}-igw-${var.region}"
  })
}

# Create NAT Gateways with Elastic IPs
resource "aws_eip" "nat" {
  count = length(var.subnet_cidrs.public) > 0 ? 1 : 0
  vpc   = true
  
  tags = merge(var.tags, {
    Name = "${var.environment}-nat-eip-${var.region}"
  })
}

resource "aws_nat_gateway" "nat" {
  count         = length(var.subnet_cidrs.public) > 0 ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id
  
  tags = merge(var.tags, {
    Name = "${var.environment}-nat-gateway-${var.region}"
  })
}

# Create route tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  
  tags = merge(var.tags, {
    Name = "${var.environment}-public-rt-${var.region}"
  })
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  
  dynamic "route" {
    for_each = length(var.subnet_cidrs.public) > 0 ? [1] : []
    content {
      cidr_block = "0.0.0.0/0"
      nat_gateway_id = aws_nat_gateway.nat[0].id
    }
  }
  
  tags = merge(var.tags, {
    Name = "${var.environment}-private-rt-${var.region}"
  })
}

# Associate route tables with subnets
resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private_app" {
  count          = length(aws_subnet.private_app)
  subnet_id      = aws_subnet.private_app[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_db" {
  count          = length(aws_subnet.private_db)
  subnet_id      = aws_subnet.private_db[count.index].id
  route_table_id = aws_route_table.private.id
}

# Security Groups
resource "aws_security_group" "lb" {
  name        = "${var.environment}-lb-sg-${var.region}"
  description = "Security group for load balancer"
  vpc_id      = aws_vpc.main.id
  
  # Allow HTTP from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # Allow HTTPS from anywhere
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # Allow all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(var.tags, {
    Name = "${var.environment}-lb-sg-${var.region}"
  })
}

resource "aws_security_group" "app" {
  name        = "${var.environment}-app-sg-${var.region}"
  description = "Security group for application servers"
  vpc_id      = aws_vpc.main.id
  
  # Allow traffic from LB
  ingress {
    from_port       = 5000
    to_port         = 5000
    protocol        = "tcp"
    security_groups = [aws_security_group.lb.id]
  }
  
  # Allow SSH from specific IPs if provided
  dynamic "ingress" {
    for_each = length(var.ssh_allowed_ips) > 0 ? [1] : []
    content {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = var.ssh_allowed_ips
    }
  }
  
  # Allow all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(var.tags, {
    Name = "${var.environment}-app-sg-${var.region}"
  })
}

resource "aws_security_group" "db" {
  name        = "${var.environment}-db-sg-${var.region}"
  description = "Security group for database servers"
  vpc_id      = aws_vpc.main.id
  
  # Allow PostgreSQL from application servers
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
  
  # Allow PostgreSQL from secondary region for replication (if this is primary)
  dynamic "ingress" {
    for_each = var.allow_cross_region_db_access ? [1] : []
    content {
      from_port   = 5432
      to_port     = 5432
      protocol    = "tcp"
      cidr_blocks = [var.peer_vpc_cidr]
    }
  }
  
  # Allow all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(var.tags, {
    Name = "${var.environment}-db-sg-${var.region}"
  })
}

# VPC Peering for primary-secondary communication
resource "aws_vpc_peering_connection" "peer" {
  count       = var.create_peering ? 1 : 0
  vpc_id      = aws_vpc.main.id
  peer_vpc_id = var.peer_vpc_id
  peer_region = var.peer_region
  auto_accept = false
  
  tags = merge(var.tags, {
    Name = "${var.environment}-vpc-peering-${var.region}-to-${var.peer_region}"
  })
}

# Data source to get available AZs
data "aws_availability_zones" "available" {
  state = "available"
}