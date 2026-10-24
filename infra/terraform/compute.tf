resource "aws_cloudwatch_log_group" "worker" {
  name              = "/ecs/${local.prefix}/worker"
  retention_in_days = 7
  tags              = local.tags
}
resource "aws_cloudwatch_log_group" "probe" {
  name              = "/ecs/${local.prefix}/probe"
  retention_in_days = 7
  tags              = local.tags
}
resource "aws_cloudwatch_log_group" "web" {
  name              = "/aws/lambda-web/${local.prefix}"
  retention_in_days = 7
  tags              = local.tags
}

resource "aws_iam_role" "ecs_execution" {
  name = "${local.prefix}-ecs-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17", Statement = [{
      Effect = "Allow", Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }, Action = "sts:AssumeRole"
    }]
  })
  tags = local.tags
}
resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "worker" {
  name = "${local.prefix}-worker"
  assume_role_policy = jsonencode({
    Version = "2012-10-17", Statement = [{
      Effect = "Allow", Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }, Action = "sts:AssumeRole"
    }]
  })
  tags = local.tags
}
resource "aws_iam_role_policy" "worker" {
  count = local.deploy ? 1 : 0
  name  = "${local.prefix}-worker"
  role  = aws_iam_role.worker.id
  policy = jsonencode({
    Version = "2012-10-17", Statement = [
      {
        Effect = "Allow", Action = ["s3:GetObject"], Resource = ["${aws_s3_bucket.jobs.arn}/jobs/*", "${aws_s3_bucket.results.arn}/probe-results/*"]
      },
      {
        Effect = "Allow", Action = ["s3:PutObject"], Resource = ["${aws_s3_bucket.results.arn}/results/*", "${aws_s3_bucket.results.arn}/probe-results/*"]
      },
      {
        Effect = "Allow", Action = ["dynamodb:TransactWriteItems", "dynamodb:UpdateItem", "dynamodb:PutItem"], Resource = aws_dynamodb_table.budget.arn
      },
      {
        Effect = "Allow", Action = ["bedrock:CountTokens", "bedrock:InvokeModel"], Resource = var.bedrock_model_arn
      },
      {
        Effect = "Allow", Action = ["ecs:DescribeTaskDefinition", "ecs:RunTask"], Resource = aws_ecs_task_definition.probe[0].arn
      },
      {
        Effect = "Allow", Action = ["ecs:DescribeTasks", "ecs:StopTask"], Resource = "*", Condition = {
          ArnEquals = {
            "ecs:cluster" = aws_ecs_cluster.this.arn
          }
        }
      },
      {
        Effect = "Allow", Action = ["iam:PassRole"], Resource = [aws_iam_role.ecs_execution.arn], Condition = {
          StringEquals = {
            "iam:PassedToService" = "ecs-tasks.amazonaws.com"
          }
        }
      }
    ]
  })
}

resource "aws_ecs_task_definition" "probe" {
  count                    = local.deploy ? 1 : 0
  family                   = "${local.prefix}-probe"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  # No task_role_arn: untrusted rules only get short-lived S3 presigned URLs.
  container_definitions = jsonencode([{
    name                   = "probe", image = var.probe_image_uri, essential = true,
    readonlyRootFilesystem = false,
    linuxParameters = {
      initProcessEnabled = true
    },
    logConfiguration = {
      logDriver = "awslogs", options = {
        "awslogs-group" = aws_cloudwatch_log_group.probe.name, "awslogs-region" = var.aws_region, "awslogs-stream-prefix" = "probe"
      }
    }

  }])
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  tags       = local.tags
  depends_on = [aws_iam_role_policy_attachment.ecs_execution]
}
resource "aws_ecs_task_definition" "worker" {
  count                    = local.deploy ? 1 : 0
  family                   = "${local.prefix}-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.worker.arn
  container_definitions = jsonencode([{
    name = "worker", image = var.worker_image_uri, essential = true,
    environment = [
      {
        name = "JOB_BUCKET", value = aws_s3_bucket.jobs.bucket
      },
      {
        name = "RESULT_BUCKET", value = aws_s3_bucket.results.bucket
      },
      {
        name = "BUDGET_TABLE", value = aws_dynamodb_table.budget.name
      },
      {
        name = "BEDROCK_MODEL_ID", value = var.bedrock_model_id
      },
      {
        name = "BEDROCK_INPUT_MICROUSD_PER_MILLION", value = tostring(var.bedrock_input_micro_usd_per_million)
      },
      {
        name = "BEDROCK_OUTPUT_MICROUSD_PER_MILLION", value = tostring(var.bedrock_output_micro_usd_per_million)
      },
      {
        name = "MAX_INPUT_TOKENS", value = tostring(var.max_input_tokens)
      },
      {
        name = "MAX_OUTPUT_TOKENS", value = tostring(var.max_output_tokens)
      },
      {
        name = "PROBE_ECS_CLUSTER", value = aws_ecs_cluster.this.arn
      },
      {
        name = "PROBE_ECS_TASK_DEFINITION", value = aws_ecs_task_definition.probe[0].arn
      },
      {
        name = "PROBE_ECS_CONTAINER", value = "probe"
      },
      {
        name = "PROBE_ECS_SUBNETS", value = aws_subnet.probe.id
      },
      {
        name = "PROBE_ECS_SECURITY_GROUPS", value = aws_security_group.probe.id
      }
    ],
    logConfiguration = {
      logDriver = "awslogs", options = {
        "awslogs-group" = aws_cloudwatch_log_group.worker.name, "awslogs-region" = var.aws_region, "awslogs-stream-prefix" = "worker"
      }
    }

  }])
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  tags       = local.tags
  depends_on = [aws_iam_role_policy_attachment.ecs_execution, aws_iam_role_policy.worker]
}

resource "aws_iam_role" "web" {
  name = "${local.prefix}-web"
  assume_role_policy = jsonencode({
    Version = "2012-10-17", Statement = [{
      Effect = "Allow", Principal = {
        Service = "lambda.amazonaws.com"
      }, Action = "sts:AssumeRole"
    }]
  })
  tags = local.tags
}
resource "aws_iam_role_policy" "web" {
  count = local.deploy ? 1 : 0
  name  = "${local.prefix}-web"
  role  = aws_iam_role.web.id
  policy = jsonencode({
    Version = "2012-10-17", Statement = [
      {
        Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.web.arn}:*"
      },
      {
        Effect = "Allow", Action = ["s3:PutObject"], Resource = ["${aws_s3_bucket.jobs.arn}/jobs/*", "${aws_s3_bucket.jobs.arn}/uploads/*"]
      },
      {
        Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.jobs.arn}/uploads/*"
      },
      {
        Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.results.arn}/results/*"
      },
      {
        Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:UpdateItem"], Resource = aws_dynamodb_table.budget.arn
      },
      {
        Effect = "Allow", Action = ["ecs:RunTask"], Resource = aws_ecs_task_definition.worker[0].arn, Condition = {
          ArnEquals = {
            "ecs:cluster" = aws_ecs_cluster.this.arn
          }
        }
      },
      {
        Effect = "Allow", Action = ["iam:PassRole"], Resource = [aws_iam_role.ecs_execution.arn, aws_iam_role.worker.arn], Condition = {
          StringEquals = {
            "iam:PassedToService" = "ecs-tasks.amazonaws.com"
          }
        }
      },
      {
        Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = var.turnstile_secret_arn
      }
    ]
  })
}
