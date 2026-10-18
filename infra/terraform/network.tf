resource "aws_vpc" "this" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = merge(local.tags, {
    Name = local.prefix
  })
}
resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = local.tags
}
resource "aws_subnet" "worker" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = "10.42.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false
  tags = merge(local.tags, {
    Name = "${local.prefix}-worker"
  })
}
resource "aws_subnet" "probe" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = "10.42.2.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false
  tags = merge(local.tags, {
    Name = "${local.prefix}-probe-private"
  })
}
resource "aws_route_table" "worker" {
  vpc_id = aws_vpc.this.id
  tags   = local.tags
}
resource "aws_route" "internet" {
  route_table_id         = aws_route_table.worker.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}
resource "aws_route_table_association" "worker" {
  subnet_id      = aws_subnet.worker.id
  route_table_id = aws_route_table.worker.id
}
resource "aws_route_table" "probe" {
  vpc_id = aws_vpc.this.id
  tags   = local.tags
}
resource "aws_route_table_association" "probe" {
  subnet_id      = aws_subnet.probe.id
  route_table_id = aws_route_table.probe.id
}
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.probe.id]
  tags              = local.tags
}
resource "aws_security_group" "worker" {
  name_prefix = "${local.prefix}-worker-"
  vpc_id      = aws_vpc.this.id
  tags        = local.tags
}
resource "aws_vpc_security_group_egress_rule" "worker" {
  security_group_id = aws_security_group.worker.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}
resource "aws_security_group" "probe" {
  name_prefix = "${local.prefix}-probe-"
  vpc_id      = aws_vpc.this.id
  tags        = local.tags
}
resource "aws_security_group" "endpoints" {
  name_prefix = "${local.prefix}-endpoints-"
  vpc_id      = aws_vpc.this.id
  tags        = local.tags
}
resource "aws_vpc_security_group_ingress_rule" "endpoints" {
  security_group_id            = aws_security_group.endpoints.id
  referenced_security_group_id = aws_security_group.probe.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}
resource "aws_vpc_security_group_egress_rule" "probe_endpoints" {
  security_group_id            = aws_security_group.probe.id
  referenced_security_group_id = aws_security_group.endpoints.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}
resource "aws_vpc_security_group_egress_rule" "probe_s3" {
  security_group_id = aws_security_group.probe.id
  prefix_list_id    = aws_vpc_endpoint.s3.prefix_list_id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}
resource "aws_vpc_endpoint" "probe_services" {
  for_each            = local.deploy ? toset(["ecr.api", "ecr.dkr", "logs"]) : toset([])
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.probe.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  tags                = local.tags
}
