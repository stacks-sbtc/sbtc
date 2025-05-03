terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.97.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "4.1.0"
    }
  }

  backend "s3" {
    bucket = var.tfstate_bucket
    key    = "tfstate/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  profile = "default"
  region  = "us-east-1"

  default_tags {
    tags = {
      Provisioner = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
