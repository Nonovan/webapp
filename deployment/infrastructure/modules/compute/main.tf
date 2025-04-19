/**
 * Compute Module for Cloud Infrastructure Platform
 * 
 * Sets up application servers with auto-scaling and load balancing.
 */

# Application Load Balancer
resource "aws_lb" "app" {
  name               = "${var.environment}-alb-${var.region}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = var.lb_security_group_ids
  subnets            = var.public_subnet_ids
  
  enable_deletion_protection = var.is_production
  
  tags = merge(var.tags, {
    Name = "${var.environment}-alb-${var.region}"
  })
}

resource "aws_lb_target_group" "app" {
  name     = "${var.environment}-tg-${var.region}"
  port     = 5000
  protocol = "HTTP"
  vpc_id   = var.vpc_id
  
  health_check {
    enabled             = true
    interval            = 30
    path                = "/health"
    port                = "traffic-port"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 5
    matcher             = "200"
  }
  
  tags = merge(var.tags, {
    Name = "${var.environment}-tg-${var.region}"
  })
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"
  
  default_action {
    type = "redirect"
    
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = var.certificate_arn
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# Launch template for application servers
resource "aws_launch_template" "app" {
  name_prefix   = "${var.environment}-lt-${var.region}"
  image_id      = data.aws_ami.amazon_linux.id
  instance_type = var.instance_type
  
  iam_instance_profile {
    name = aws_iam_instance_profile.app.name
  }
  
  vpc_security_group_ids = var.security_group_ids
  
  user_data = base64encode(<<-EOF
    #!/bin/bash
    # Cloud Platform initialization script
    yum update -y
    amazon-linux-extras install docker -y
    service docker start
    usermod -a -G docker ec2-user
    
    # Install CloudWatch agent
    yum install -y amazon-cloudwatch-agent
    
    # Pull the latest Docker image
    aws ecr get-login-password --region ${var.region} | \
      docker login --username AWS --password-stdin ${var.ecr_repository_url}
    docker pull ${var.ecr_repository_url}:latest
    
    # Run the container
    docker run -d \
      --name cloud-platform \
      -p 5000:5000 \
      -e ENVIRONMENT=${var.environment} \
      -e REGION=${var.region} \
      -e DATABASE_URL=${var.database_url} \
      -e REDIS_URL=${var.redis_url} \
      ${var.ecr_repository_url}:latest
  EOF
  )
  
  block_device_mappings {
    device_name = "/dev/xvda"
    
    ebs {
      volume_size           = 20
      volume_type           = "gp3"
      delete_on_termination = true
      encrypted             = true
    }
  }
  
  tag_specifications {
    resource_type = "instance"
    
    tags = merge(var.tags, {
      Name = "${var.environment}-app-${var.region}"
    })
  }
  
  tag_specifications {
    resource_type = "volume"
    
    tags = merge(var.tags, {
      Name = "${var.environment}-app-volume-${var.region}"
    })
  }
  
  lifecycle {
    create_before_destroy = true
  }
}

# Auto Scaling Group for application servers
resource "aws_autoscaling_group" "app" {
  name                = "${var.environment}-asg-${var.region}"
  vpc_zone_identifier = var.subnet_ids
  
  min_size             = var.min_size
  max_size             = var.max_size
  desired_capacity     = var.desired_capacity
  
  health_check_type         = "ELB"
  health_check_grace_period = 300
  
  target_group_arns    = [aws_lb_target_group.app.arn]
  
  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }
  
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 90
    }
  }
  
  dynamic "tag" {
    for_each = merge(
      var.tags,
      {
        Name = "${var.environment}-app-${var.region}"
      }
    )
    
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
}

# CPU-based auto scaling policy
resource "aws_autoscaling_policy" "cpu" {
  name                   = "${var.environment}-cpu-policy-${var.region}"
  autoscaling_group_name = aws_autoscaling_group.app.name
  policy_type            = "TargetTrackingScaling"
  
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    
    target_value = 70.0
  }
}

# IAM role for application servers
resource "aws_iam_role" "app" {
  name = "${var.environment}-app-role-${var.region}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
  
  tags = var.tags
}

# IAM instance profile
resource "aws_iam_instance_profile" "app" {
  name = "${var.environment}-app-profile-${var.region}"
  role = aws_iam_role.app.name
}

# IAM policies for application servers
resource "aws_iam_role_policy" "app_s3" {
  name   = "${var.environment}-app-s3-policy-${var.region}"
  role   = aws_iam_role.app.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
        ]
        Effect   = "Allow"
        Resource = [
          "arn:aws:s3:::${var.environment}-cloud-platform-assets/*",
          "arn:aws:s3:::${var.environment}-cloud-platform-assets"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "app_ecr" {
  name   = "${var.environment}-app-ecr-policy-${var.region}"
  role   = aws_iam_role.app.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetAuthorizationToken"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# Latest Amazon Linux AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
  
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}