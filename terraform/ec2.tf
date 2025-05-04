resource "tls_private_key" "sbtc_ec2_key" {
  algorithm   = "ED25519"
}

resource "aws_key_pair" "sbtc_ec2" {
  key_name   = "sbtc-devenv-ec2-key"
  public_key = tls_private_key.sbtc_ec2_key.public_key_openssh
}

resource "local_file" "private_key_pem" {
  content          = tls_private_key.sbtc_ec2_key.private_key_openssh 
  filename         = "${path.module}/sbtc-immunefi.pem"
  file_permission  = "0600"
}

data "aws_security_group" "sbtc_immunefi" {
  id = aws_security_group.sbtc_immunefi.id
}

data "aws_iam_instance_profile" "sbtc_immunefi" {
  name = aws_iam_instance_profile.sbtc_immunefi.name
}

data "aws_ami" "ubuntu_noble" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
}

resource "aws_launch_template" "sbtc_devenv_immunefi_instance" {
  name          = "sbtc-immunefi-devenv-launch-template"
  description   = "The launch template for sbtc devenv applications"
  image_id      = data.aws_ami.ubuntu_noble.id
  instance_type = "c7i.xlarge"
  ebs_optimized = true
  key_name      = aws_key_pair.sbtc_ec2.key_name

  update_default_version = true

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      delete_on_termination = true
      encrypted             = false
      volume_type           = "gp3"
      volume_size           = "100"
    }
  }

  credit_specification {
    cpu_credits = "standard"
  }

  iam_instance_profile {
    arn = data.aws_iam_instance_profile.sbtc_immunefi.arn
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups = [
      data.aws_security_group.sbtc_immunefi.id,
    ]
  }

  monitoring {
    enabled = false
  }

  tags = {
    app = "sbtc-devenv"
  }
}

resource "aws_autoscaling_group" "sbtc_devenv_server_cluster" {
  name     = "sbtc-immunefi-devenv-autoscaling"
  min_size = 0
  max_size = 32

  desired_capacity     = 0
  health_check_type    = "EC2"
  termination_policies = ["OldestLaunchTemplate", "NewestInstance"]
  vpc_zone_identifier  = [aws_subnet.main[0].id]

  launch_template {
    id      = aws_launch_template.sbtc_devenv_immunefi_instance.id
    version = aws_launch_template.sbtc_devenv_immunefi_instance.latest_version
  }

  tag {
    key                 = "Name"
    value               = "sbtc-devenv"
    propagate_at_launch = true
  }
}


resource "aws_launch_template" "sbtc_devenv_immunefi_attacker" {
  name          = "sbtc-immunefi-attacker-launch-template"
  description   = "The launch template for sbtc protocol attacker applications"
  image_id      = data.aws_ami.ubuntu_noble.id
  instance_type = "c7i.2xlarge"
  ebs_optimized = true
  key_name      = aws_key_pair.sbtc_ec2.key_name

  update_default_version = true

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      delete_on_termination = true
      encrypted             = false
      volume_type           = "gp3"
      volume_size           = "80"
    }
  }

  credit_specification {
    cpu_credits = "standard"
  }

  iam_instance_profile {
    arn = data.aws_iam_instance_profile.sbtc_immunefi.arn
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups = [
      data.aws_security_group.sbtc_immunefi.id,
    ]
  }

  monitoring {
    enabled = false
  }

  tags = {
    app = "sbtc-devenv"
  }
}

resource "aws_autoscaling_group" "sbtc_devenv_attacker_cluster" {
  name     = "sbtc-immunefi-attacker-autoscaling"
  min_size = 0
  max_size = 32

  desired_capacity     = 0
  health_check_type    = "EC2"
  termination_policies = ["OldestLaunchTemplate", "NewestInstance"]
  vpc_zone_identifier  = [aws_subnet.main[0].id]

  launch_template {
    id      = aws_launch_template.sbtc_devenv_immunefi_attacker.id
    version = aws_launch_template.sbtc_devenv_immunefi_attacker.latest_version
  }

  tag {
    key                 = "Name"
    value               = "sbtc-attacker"
    propagate_at_launch = true
  }
}

