output "vpc_id" {
  description = "The ID of the custom Purple Team VPC."
  value       = aws_vpc.main.id
}

output "public_subnet_id" {
  description = "The ID of the public subnet."
  value       = aws_subnet.public.id
}

output "private_subnet_id" {
  description = "The ID of the private subnet."
  value       = aws_subnet.private.id
}

output "cloudtrail_arn" {
  description = "ARN of the active CloudTrail instance."
  value       = aws_cloudtrail.main.arn
}

output "target_vm_public_ip" {
  description = "Public IP address of the target VM."
  value       = aws_instance.target.public_ip
}
