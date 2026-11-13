provider "aws" {
  region = var.app_location
}

resource "aws_instance" "my_first_tf_instance" {
  ami                         = var.test_app_ami_id
  instance_type               = var.test_vm
  tags                        = { Name = var.test_name }
  vpc_security_group_ids      = [aws_security_group.allow_ports.id]
  subnet_id                   = module.vpc.public_subnets[0]
  associate_public_ip_address = true
  key_name                    = var.app_key_name
  user_data                   = replace(var.app_user_data, "DB-PRIVATE-IP", aws_instance.my_first_tf_instance_db.private_ip)
}

resource "aws_security_group" "allow_ports" {
  name   = "tech613-ameen-tf-allow-port-22-80-for-app"
  vpc_id = module.vpc.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "allow_ssh" {
  security_group_id = aws_security_group.allow_ports.id
  cidr_ipv4         = "${trimspace(data.http.my_ip.response_body)}/32"
  from_port         = 22
  ip_protocol       = "tcp"
  to_port           = 22
}

resource "aws_vpc_security_group_ingress_rule" "allow_http" {
  security_group_id = aws_security_group.allow_ports.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  ip_protocol       = "tcp"
  to_port           = 80
}

resource "aws_vpc_security_group_egress_rule" "app_to_db_outbound_traffic" {
  security_group_id            = aws_security_group.allow_ports.id
  referenced_security_group_id = aws_security_group.allow_db_ports.id
  from_port                    = 27017
  to_port                      = 27017
  ip_protocol                  = "tcp"
}

resource "aws_instance" "my_first_tf_instance_db" {
  ami                         = var.test_app_ami_id_db
  instance_type               = var.test_vm
  tags                        = { Name = var.test_name_db }
  vpc_security_group_ids      = [aws_security_group.allow_db_ports.id]
  subnet_id                   = aws_subnet.db_private_subnet.id
  associate_public_ip_address = false
  key_name                    = var.app_key_name
}

resource "aws_security_group" "allow_db_ports" {
  name   = "tech613-ameen-tf-allow-port-27017-for-db-vm"
  vpc_id = module.vpc.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "allow_mongodb" {
  security_group_id            = aws_security_group.allow_db_ports.id
  referenced_security_group_id = aws_security_group.allow_ports.id
  from_port                    = 27017
  ip_protocol                  = "tcp"
  to_port                      = 27017
}

module "vpc" {
  source             = "terraform-aws-modules/vpc/aws"
  name               = "tech613-ameen-vpc"
  cidr               = "10.0.0.0/16"
  azs                = ["eu-west-1a", "eu-west-1b"]
  public_subnets     = var.public_subnet_cidrs
  private_subnets    = []
  enable_nat_gateway = false
  tags               = { Terraform = "true", Environment = "dev" }
}

resource "aws_subnet" "db_private_subnet" {
  vpc_id                  = module.vpc.vpc_id
  cidr_block              = var.private_subnet_cidrs[0]
  availability_zone       = "eu-west-1b"
  map_public_ip_on_launch = false
  tags                    = { Name = "tech613-ameen-private-subnet" }
}

variable "test_app_ami_id" {
  default = "ami-0bbef9f6cebc6d549"
}
variable "test_vm" {
  default = "t3.micro"
}
variable "test_name" {
  default = "tech613-ameen-terraform-app-vm-with-db"
}
variable "app_location" {
  default = "eu-west-1"
}
variable "app_key_name" {
  default = "tech613-ameen-aws-key"
}
variable "test_app_ami_id_db" {
  default = "ami-0b71fb5fbe7a542e9"
}
variable "test_name_db" {
  default = "tech613-ameen-terraform-app-vm-db"
}
variable "app_user_data" {
  default = <<-EOF_SCRIPT
    #!/bin/bash

    set -e

    cd /home/ubuntu/app

    export MONGODB_URI="mongodb://DB-PRIVATE-IP:27017/tictactoe"

    export PM2_HOME=/root/.pm2

    pm2 restart tictactoe --update-env || pm2 start npm --name tictactoe -- start
  EOF_SCRIPT
}
data "http" "my_ip" {
  url = "https://checkip.amazonaws.com"
}
variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.2.0/24"]
}
variable "private_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.3.0/24"]
}
