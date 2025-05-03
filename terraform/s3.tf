resource "aws_s3_bucket" "service_provisioning" {
  bucket        = "service-provisioning-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  force_destroy = false
}
