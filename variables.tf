variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "Primary AWS region for security lab deployment."
}

variable "account_id" {
  type        = string
  default     = "451637428094"
  description = "AWS Account ID used for globally unique resource naming."
}
