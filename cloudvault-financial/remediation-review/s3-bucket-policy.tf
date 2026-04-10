# Priya's proposed S3 bucket configurations
# She's trying to fix the public access issue on app-assets
# while keeping client-docs locked down

resource "aws_s3_bucket" "client_docs" {
  bucket = "cloudvault-client-docs"

  tags = {
    Name        = "Client Documents"
    Environment = "production"
    Sensitivity = "high"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "client_docs" {
  bucket = aws_s3_bucket.client_docs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# NOTE: No bucket policy here — relying on default deny
# Is that sufficient for a bucket with PII and financial data?

resource "aws_s3_bucket" "app_assets" {
  bucket = "cloudvault-app-assets"

  tags = {
    Name        = "Application Assets"
    Environment = "production"
    Sensitivity = "low"
  }
}

resource "aws_s3_bucket_policy" "app_assets_public" {
  bucket = aws_s3_bucket.app_assets.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.app_assets.arn}/*"
      }
    ]
  })
}

# Backup bucket
resource "aws_s3_bucket" "backups" {
  bucket = "cloudvault-backups"

  tags = {
    Name        = "Database Backups"
    Environment = "production"
    Sensitivity = "high"
  }
}

resource "aws_s3_bucket_versioning" "backups" {
  bucket = aws_s3_bucket.backups.id
  versioning_configuration {
    status = "Enabled"
  }
}

# NOTE: svc-backup-agent has s3:* permissions on all buckets
# Priya says "it needs full access to do backups"
# Is that true?
