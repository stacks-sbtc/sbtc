data "aws_iam_policy" "AmazonS3ReadOnlyAccess" {
  arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

data "aws_iam_policy" "AWSLambdaRole" {
  arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaRole"
}

data "aws_iam_policy" "AWSDataLifecycleManagerServiceRole" {
  arn = "arn:aws:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole"
}

data "aws_iam_policy" "CloudWatchAgentAdminPolicy" {
  arn = "arn:aws:iam::aws:policy/CloudWatchAgentAdminPolicy"
}

data "aws_iam_policy" "AutoScalingNotificationAccessRole" {
  arn = "arn:aws:iam::aws:policy/service-role/AutoScalingNotificationAccessRole"
}

data "aws_iam_policy_document" "ec2_describe" {
  statement {
    actions = [
      "ec2:Describe*",
    ]
    effect    = "Allow"
    resources = ["*"]
  }
  version = "2012-10-17"
}

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    actions = [
      "sts:AssumeRole",
    ]
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
  version = "2012-10-17"
}

data "aws_iam_policy_document" "codedeploy_assume_role" {
  statement {
    actions = [
      "sts:AssumeRole",
    ]
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["codedeploy.amazonaws.com"]
    }
  }
  version = "2012-10-17"
}

data "aws_iam_policy_document" "asg_assume_role" {
  statement {
    actions = [
      "sts:AssumeRole",
    ]
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["autoscaling.amazonaws.com"]
    }
  }
  version = "2012-10-17"
}

resource "aws_iam_policy" "ec2_describe" {
  name        = "ec2-describe-iam-policy"
  path        = "/"
  policy      = data.aws_iam_policy_document.ec2_describe.json
  description = "Policy allowing requests to describe any instance"
}

resource "aws_iam_role" "sbtc_immunefi" {
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
  description        = "The IAM role for sbtc_immunefi cluster"
  name               = "sbtc-immunefi-iam-role"
}

resource "aws_iam_role" "codedeploy_service_role" {
  assume_role_policy = data.aws_iam_policy_document.codedeploy_assume_role.json
  description        = "The IAM service role for AWS CodeDeploy"
  name               = "codedeploy-iam-service-role"
}

resource "aws_iam_role_policy_attachment" "ec2_describe_attachment" {
  role       = aws_iam_role.sbtc_immunefi.name
  policy_arn = aws_iam_policy.ec2_describe.arn
}

resource "aws_iam_role_policy_attachment" "sbtc_immunefi_AWSLambdaRole" {
  role       = aws_iam_role.sbtc_immunefi.name
  policy_arn = data.aws_iam_policy.AWSLambdaRole.arn
}

resource "aws_iam_role_policy_attachment" "sbtc_immunefi_AmazonS3ReadOnlyAccess" {
  role       = aws_iam_role.sbtc_immunefi.name
  policy_arn = data.aws_iam_policy.AmazonS3ReadOnlyAccess.arn
}

resource "aws_iam_role_policy_attachment" "sbtc_immunefi_CloudWatchAgentAdminPolicy" {
  role       = aws_iam_role.sbtc_immunefi.name
  policy_arn = data.aws_iam_policy.CloudWatchAgentAdminPolicy.arn
}

resource "aws_iam_instance_profile" "sbtc_immunefi" {
  name = "sbtc-immunefi-iam-instance-profile"
  role = aws_iam_role.sbtc_immunefi.name
}
