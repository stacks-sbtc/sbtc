resource "aws_vpc" "main" {
  cidr_block                       = "10.0.0.0/19"
  instance_tenancy                 = "default"
  enable_dns_hostnames             = true
  enable_dns_support               = true
  assign_generated_ipv6_cidr_block = true

  tags = {
    Name        = "sbtc-immunefi-us-east-1"
    Provisioner = "terraform"
  }
}

resource "aws_internet_gateway" "main_gateway" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name        = "sbtc-immunefi"
    Provisioner = "terraform"
  }
}

resource "aws_default_route_table" "main_route_table" {
  default_route_table_id = aws_vpc.main.default_route_table_id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main_gateway.id
  }

  route {
    ipv6_cidr_block = "::/0"
    gateway_id      = aws_internet_gateway.main_gateway.id
  }

  route {
    cidr_block = var.home_ipv4
    gateway_id = aws_internet_gateway.main_gateway.id
  }

  route {
    ipv6_cidr_block = var.home_ipv6
    gateway_id      = aws_internet_gateway.main_gateway.id
  }

  tags = {
    Name        = "sbtc-immunefi-rt"
    Provisioner = "terraform"
  }
}

resource "aws_route_table_association" "private_subnet" {
  subnet_id      = aws_subnet.main[0].id
  route_table_id = aws_default_route_table.main_route_table.id
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_subnet" "main" {
  count = 2

  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 3, count.index)
  ipv6_cidr_block   = cidrsubnet(aws_vpc.main.ipv6_cidr_block, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[0]
  enable_dns64      = true

  map_public_ip_on_launch         = false
  assign_ipv6_address_on_creation = true

  tags = {
    Name        = count.index == 0 ? "sbtc-immunefi-private-vpc-subnet" : "sbtc-immunefi-public-vpc-subnet"
    Provisioner = "terraform"
  }
}

resource "aws_vpc_endpoint" "s3" {
  service_name = "com.amazonaws.us-east-1.s3"
  vpc_id       = aws_vpc.main.id
}

resource "aws_vpc_endpoint_route_table_association" "s3" {
  route_table_id  = aws_default_route_table.main_route_table.id
  vpc_endpoint_id = aws_vpc_endpoint.s3.id
}

resource "aws_vpc_endpoint" "dynamodb" {
  service_name = "com.amazonaws.us-east-1.dynamodb"
  vpc_id       = aws_vpc.main.id
}

resource "aws_vpc_endpoint_route_table_association" "dynamodb" {
  route_table_id  = aws_default_route_table.main_route_table.id
  vpc_endpoint_id = aws_vpc_endpoint.dynamodb.id
}

resource "aws_route_table" "public_subnet" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main_gateway.id
  }

  route {
    ipv6_cidr_block = "::/0"
    gateway_id      = aws_internet_gateway.main_gateway.id
  }

  tags = {
    Name        = "sbtc-immunefi-public-subnet-rt"
    Provisioner = "terraform"
  }
}

resource "aws_route_table_association" "public_subnet" {
  subnet_id      = aws_subnet.main[1].id
  route_table_id = aws_route_table.public_subnet.id
}

resource "aws_security_group" "sbtc_immunefi" {
  name        = "sbtc-immunefi-devenv-us-east-1-sg"
  description = "Cluster security group. Allows me to communicate with it"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port        = 5432
    to_port          = 5434
    protocol         = "tcp"
    cidr_blocks      = [var.home_ipv4]
    ipv6_cidr_blocks = [var.home_ipv6]
    description      = "Hit cluster endpoints from home"
  }

  ingress {
    from_port        = 8083
    to_port          = 8083
    protocol         = "tcp"
    cidr_blocks      = [var.home_ipv4]
    ipv6_cidr_blocks = [var.home_ipv6]
    description      = "The devenv mempool port"
  }

  ingress {
    from_port        = 3000
    to_port          = 3000
    protocol         = "tcp"
    cidr_blocks      = [var.home_ipv4]
    ipv6_cidr_blocks = [var.home_ipv6]
    description      = "The devenv sbtc-bridge port"
  }

  ingress {
    from_port        = 3020
    to_port          = 3020
    protocol         = "tcp"
    cidr_blocks      = [var.home_ipv4]
    ipv6_cidr_blocks = [var.home_ipv6]
    description      = "The devenv stacks explorer port"
  }

  ingress {
    from_port        = 3040
    to_port          = 3040
    protocol         = "tcp"
    cidr_blocks      = [var.home_ipv4]
    ipv6_cidr_blocks = [var.home_ipv6]
    description      = "The devenv grafana port"
  }

  ingress {
    from_port        = 3999
    to_port          = 3999
    protocol         = "tcp"
    cidr_blocks      = [var.home_ipv4]
    ipv6_cidr_blocks = [var.home_ipv6]
    description      = "The stacks api port"
  }

  ingress {
    from_port   = 4122
    to_port     = 4124
    protocol    = "tcp"
    self        = true
    description = "Hit cluster endpoints from within the security group"
  }

  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = [var.home_ipv4]
    ipv6_cidr_blocks = [var.home_ipv6]
    description      = "Allows logging into the cluster from home"
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
    description      = "Allow all outbound traffic"
  }

  tags = {
    Provisioner = "terraform"
    Name        = "sbtc-immunefi-sg"
  }
}
