###############################################################################
# Optional ElastiCache (Redis) replication group.
###############################################################################

resource "aws_elasticache_subnet_group" "this" {
  count = var.elasticache_enabled ? 1 : 0

  name       = "${var.name}-cache"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_security_group" "cache" {
  count = var.elasticache_enabled ? 1 : 0

  name        = "${var.name}-cache"
  description = "Redis access from within the VPC."
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "Redis from within the VPC."
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name}-cache"
  }
}

resource "aws_elasticache_replication_group" "this" {
  count = var.elasticache_enabled ? 1 : 0

  replication_group_id = "${var.name}-cache"
  description          = "SNG control-plane cache"
  engine               = "redis"
  node_type            = var.elasticache_node_type
  num_cache_clusters   = var.elasticache_num_nodes
  port                 = 6379

  automatic_failover_enabled = var.elasticache_num_nodes > 1
  multi_az_enabled           = var.elasticache_num_nodes > 1

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  subnet_group_name  = aws_elasticache_subnet_group.this[0].name
  security_group_ids = [aws_security_group.cache[0].id]
}
