###############################################################################
# RDS PostgreSQL primary + optional read replicas (PG_READ_REPLICA_HOSTS).
###############################################################################

resource "aws_db_subnet_group" "this" {
  name       = "${var.name}-pg"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name = "${var.name}-pg"
  }
}

resource "aws_security_group" "pg" {
  name        = "${var.name}-pg"
  description = "PostgreSQL access from the EKS node group."
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "PostgreSQL from within the VPC (EKS pods/nodes)."
    from_port   = 5432
    to_port     = 5432
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
    Name = "${var.name}-pg"
  }
}

resource "aws_db_parameter_group" "pg" {
  name   = "${var.name}-pg16"
  family = "postgres16"

  # Surface the wire-level pool ceiling the control plane sizes against
  # (see docs/scaling.md PG_MAX_OPEN_CONNS guidance).
  parameter {
    name         = "max_connections"
    value        = "500"
    apply_method = "pending-reboot"
  }
}

resource "aws_db_instance" "primary" {
  identifier     = "${var.name}-pg"
  engine         = "postgres"
  engine_version = var.pg_engine_version
  instance_class = var.pg_instance_class

  allocated_storage     = var.pg_allocated_storage
  max_allocated_storage = var.pg_max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = var.pg_database_name
  username = var.pg_username
  password = random_password.pg.result
  port     = 5432

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.pg.id]
  parameter_group_name   = aws_db_parameter_group.pg.name

  multi_az                = var.pg_multi_az
  backup_retention_period = var.pg_backup_retention_days
  deletion_protection     = var.pg_deletion_protection
  storage_throughput      = 125
  iops                    = 3000

  # Read replicas require automated backups on the source.
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name}-pg-final"
  apply_immediately         = false

  tags = {
    Name = "${var.name}-pg"
  }
}

resource "aws_db_instance" "replica" {
  count = var.pg_read_replica_count

  identifier          = "${var.name}-pg-replica-${count.index}"
  replicate_source_db = aws_db_instance.primary.identifier
  instance_class      = var.pg_instance_class
  storage_encrypted   = true

  vpc_security_group_ids = [aws_security_group.pg.id]
  parameter_group_name   = aws_db_parameter_group.pg.name

  skip_final_snapshot = true
  apply_immediately   = false

  tags = {
    Name = "${var.name}-pg-replica-${count.index}"
  }
}
