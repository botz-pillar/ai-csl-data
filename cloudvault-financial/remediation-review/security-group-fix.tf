# Priya's proposed fix for the dev security group
# Review this before she applies it

resource "aws_security_group" "sg_dev" {
  name        = "sg-dev"
  description = "Development server security group - UPDATED"
  vpc_id      = var.vpc_id

  # SSH access - restricted to office IPs
  ingress {
    description = "SSH from office"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["98.45.172.0/24"]
  }

  # RDP access - removed the 0.0.0.0/0 rule
  # But Priya added her home IP "temporarily" for remote work
  ingress {
    description = "RDP from Priya home"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["98.45.172.88/32", "0.0.0.0/0"]  # Oops - left the old rule in
  }

  # Application port
  ingress {
    description = "App port from VPC"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # All outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "sg-dev"
    Environment = "development"
    ManagedBy   = "terraform"
  }
}
