# WAF Compass

Go components for reviewing AWS WAF and ModSecurity rules with Bedrock, and for running bounded ModSecurity request tests. The public introduction and authenticated browser form are in `web/index.html`. The authenticated HTTP entry point is in `webfunction/index.js`, and Terraform is in `infra/terraform`. Terraform separates foundational resources from the public application with `deploy_application`.

The browser also accepts access logs from sites without a WAF. Select **Access logs**, then choose **CloudFront standard**, **ALB access**, or **Apache/Nginx Combined** before uploading a UTF-8 plain-text file of at most 1 MiB. A mismatched or malformed format is rejected by the authenticated server before the daily user slot is claimed. Custom Apache/Nginx `log_format` layouts and compressed files are not supported. The worker validates the format again, counts request statuses and suspicious URL patterns, and sends only numeric aggregates to Bedrock. It never sends raw access-log lines, IP addresses, query strings, or user agents to the model. The report suggests AWS Managed Rules groups and, when the sample supports it, a rate-based rule. These are candidates, not confirmed detections; logs alone cannot establish whether a request was malicious or would have been blocked. Test candidates in AWS WAF Count mode and inspect sampled requests and false positives before enabling Block. There is no automatic Web ACL change.

## What each result means

The caller selects one or more of `sqli`, `xss`, `path_traversal`, `cmdi`, `ssrf`, `xxe`, and `ssti`. Each category has two fixed attack requests and one benign request in `internal/attacks/catalog.go` (21 requests maximum). A passing category means only that **these sample requests** behaved as expected. Payloads such as SSRF URLs and XXE entities are delivered only to the isolated dummy backend; the service never fetches them.

- **AWS WAF:** the Go worker reviews a `GetWebACL` snapshot and the selected categories with Bedrock. `attack_results[].outcome` is `unverified`. JSON inspection cannot establish how managed rules or a live Web ACL would handle a request. A staging endpoint and traffic logs would be needed for a future live-test option.
- **ModSecurity:** a separate ECS/Fargate task starts **ModSecurity 2 on Apache** with the submitted flattened ruleset and a dummy backend that always returns HTTP 200. It sends the fixed requests only to loopback. It reports the observed HTTP status, pass/fail against the expected behavior, and matching rule IDs when the JSON audit log contains them. It does not send requests to the user's application. A production ModSecurity 3/Nginx deployment may behave differently.
- **Access logs:** the Go worker analyzes the selected log format and returns aggregate evidence and natural-language AWS WAF rule candidates. This mode does not run test requests or require an existing WAF. The analysis sees only the uploaded sample and cannot inspect request bodies or prove attack intent.

The report contains a deterministic natural-language `summary` and a Bedrock-written `assessment` in the selected `language` (`ja` or `en`). The structured `attack_results` are computed from the fixed tests; Bedrock cannot turn an unverified result into a measured pass. Missing `language` in older jobs means Japanese.

## OWASP Top 10:2025 scope

The selectable cases cover WAF-visible examples: path traversal and SSRF associated with **A01 Broken Access Control**, and SQL injection, XSS, command injection, and template injection associated with **A05 Injection**. XXE is included as an additional XML attack pattern. This is sample-based WAF behavior testing, not a vulnerability scan of the application. Authorization/IDOR, authentication, cryptography, supply chain, design, logging, integrity, and exceptional-condition risks need application code, configuration, identity, and operational tests. A WAF verdict cannot certify the entire OWASP Top 10.

See [OWASP Top 10:2025](https://top10.owasp.org/2025/0x00_2025-Introduction/) and its [A05 Injection](https://top10.owasp.org/2025/A05_2025-Injection/) category.

## Job input

Only the authenticated server may create this private S3 object. The browser sends `kind`, `language`, `snapshot`, and `attack_categories`; the server derives `id` and `user_id` from its own job creation and verified login, and sets `probe_result_key` for ModSecurity. Never copy a browser-supplied `user_id`, job ID, result key, price, or model ID.

```json
{
  "id": "job_01",
  "user_id": "authenticated_user_id",
  "kind": "modsecurity",
  "language": "ja",
  "snapshot": "SecRuleEngine On\nSecRule ARGS \"@contains script\" \"id:100001,phase:2,deny,status:403\"",
  "attack_categories": ["sqli", "xss"],
  "probe_result_key": "probe-results/job_01.json"
}
```

`kind` may also be `aws_waf`; then `snapshot` must be the full `GetWebACL` JSON response and `probe_result_key` must be omitted. ModSecurity input must be the effective ruleset with all `Include`/`IncludeOptional` directives expanded in actual load order. The current **service upload limit is 1 MiB**, as selected for this service. AWS WAF's 5,000 WCU maximum measures rule processing capacity, not the byte size of a rules JSON file. ModSecurity `SecRequestBodyLimit` and `SecRequestBodyNoFilesLimit` bound inspected HTTP request bodies, not the byte size of the rules configuration. There is no meaningful "larger of the two" upload value to adopt; the upload limit must be set from this service's token, memory, time, and cost budget. A file under 1 MiB can still exceed the configured Bedrock token or daily cost ceiling; that evaluation fails without inference. The isolated test task rejects unresolved includes and remote-rule/script directives. Rules that depend on external files, connector-specific behavior, or application state may be unable to run in this testbed.

For log analysis use `kind: "traffic_log"`, set `log_format` to `cloudfront`, `alb`, or `combined`, put the log text in `snapshot`, and send `attack_categories: []`. This mode uses the same login, Turnstile, one-per-user-per-JST-day, and $3-per-JST-day Bedrock ceiling. The raw job file is private and targeted for deletion after seven days; aggregate results are targeted for deletion after thirty days. Access logs can contain personal data and credentials in URLs, so remove unnecessary fields before upload.

## Request and cost limits

The worker's DynamoDB transaction reserves **one new job per user per JST day** and a worst-case **Bedrock inference ceiling of $3 per JST day**. For ModSecurity it reserves the configured maximum input and output token cost **before** launching the test task, so duplicate jobs cannot repeatedly start Fargate tests. Failed jobs retain their reservation and daily slot. If the JST day changes before inference, the worker fails closed without invoking Bedrock. Bedrock SDK retries are disabled.

The $3 ceiling applies only to Bedrock inference from this worker. ECS/Fargate, AWS WAF, CloudFront, S3, DynamoDB, Route 53, and data transfer can still incur charges. Keep fixed test counts, a short task timeout, a small Fargate task size, and a deployment-level concurrency quota for test tasks. The public entry point verifies Cognito login and Cloudflare Turnstile before writing a job or starting the worker. It atomically claims `SUBMIT#<JST-day>#<Cognito-sub>` in DynamoDB before starting ECS, so repeated submissions do not launch extra workers. A pending or failed submission consumes the daily slot. The worker independently enforces the Bedrock budget and daily user limit.

## Terraform deployment

Use Terraform 1.14 or later. AWS and AWSCC providers are locked in `infra/terraform/.terraform.lock.hcl`. The default Region is Tokyo. Terraform defines Lambda Web Functions, CloudFront OAC, ECS task definitions, Cognito, private S3 buckets, DynamoDB, IAM, VPC networking, Route 53, and an ACM certificate. The optional CloudFront AWS WAF rate rule is off by default because it has a separate charge. The isolated ModSecurity task has no public IP, NAT route, or task role. The on-demand Go worker uses a public subnet and public IP to reach AWS APIs without a NAT gateway.

1. Copy `infra/terraform/terraform.tfvars.example` to `infra/terraform/terraform.tfvars`. Choose a globally unique Cognito domain prefix. Keep `deploy_application = false`; then run `terraform init`, `terraform plan`, and `terraform apply` from `infra/terraform`. Review the plan before applying: foundational resources can incur AWS charges.
2. Add an NS delegation record for `waf.i-wind.jp` in the parent `i-wind.jp` zone, using the `name_servers` Terraform output. Wait until public DNS returns those nameservers. The second apply requests and validates an ACM certificate in `us-east-1`.
3. Run `./scripts/push-images.sh ap-northeast-1 WORKER_ECR_URL PROBE_ECR_URL` with the two Terraform repository outputs. It builds Linux x86_64 images from `Dockerfile` and `Dockerfile.testtask`, pushes them, and prints immutable image URIs for `worker_image_uri` and `probe_image_uri`.
4. Create a Cloudflare Turnstile widget for `waf.i-wind.jp`. Store its secret in AWS Secrets Manager outside Terraform. Set `turnstile_site_key` and `turnstile_secret_arn`; never put the secret value into Terraform state. Set the Bedrock model or inference profile ID, its IAM ARN, current input/output prices in microUSD per million tokens, and positive token ceilings. Recheck the prices when the model or its pricing changes. The $3/JST day reservation is enforced by the worker, not by AWS Billing.
5. Run `./scripts/package-web.sh` from the repository root to create `infra/terraform/build/web.zip`. Set `deploy_application = true`, review `terraform plan`, then apply. `service_url` points to the CloudFront URL. The Web Functions endpoint uses IAM authentication and allows CloudFront OAC access only from this distribution.
6. Before public launch, run a staging smoke test for login, Turnstile rejection and acceptance, 1 MiB rejection, daily user limit, ModSecurity isolation, Bedrock report completion, result polling, and the $3 ceiling.

The application deployment creates three private interface endpoints for the probe task. They incur hourly and data processing charges even with zero traffic. CloudFront, ECS/Fargate, Cognito, Route 53, S3, DynamoDB, and logs have separate charges. `deploy_application = false` leaves foundational resources in place. Keep Terraform state in an access-controlled remote backend before team use.

## AWS resources and permissions

Create private job and result S3 buckets, a DynamoDB table with string partition key `pk`, an ECS cluster, the Bedrock worker task definition, and a **separate** ModSecurity test task definition. Both tasks can run on demand; no always-on ECS service is required. Encrypt the S3 buckets and logs and set retention/lifecycle policies.

- The **worker task role** needs `s3:GetObject` on the job prefix and probe result prefix, `s3:PutObject` on the report prefix, `dynamodb:TransactWriteItems`/`UpdateItem` on the budget table, `bedrock:CountTokens`/`InvokeModel` for the chosen model, and narrowly scoped `ecs:DescribeTaskDefinition`, `RunTask`, `DescribeTasks`, `StopTask` plus `iam:PassRole` for the test task's **execution role**. It also presigns S3 GET/PUT URLs for the test task.
- The **ModSecurity test task must have no task role**. Its execution role is for ECS to pull the image and deliver logs; the container itself receives only short-lived presigned S3 URLs. The worker checks that the task definition has no task role and uses `awsvpc` before launch. Put the task in private subnets without a NAT/internet route, give it no public IP, and allow only the S3 VPC endpoint needed for its presigned URLs. Keep the test task's security group without inbound rules. Do not reuse the worker's task definition or IAM role.
- The result bucket's `probe-results/` prefix must be writable only through the worker-issued presigned URL and readable only by the worker. Browsers must never have direct write access. Restrict the job prefix similarly.

The Go worker reads `probe-results/<job_id>.json`, validates the job ID, snapshot hash, selected categories, case IDs, statuses, and computed outcomes, then includes it in the Bedrock prompt and final report.

## Worker environment

| Variable | Meaning |
| --- | --- |
| `JOB_BUCKET`, `JOB_KEY` | Private input job object |
| `RESULT_BUCKET` | Private probe receipt and final report bucket |
| `BUDGET_TABLE` | DynamoDB budget table |
| `BEDROCK_MODEL_ID` | Model or inference profile ID |
| `BEDROCK_INPUT_MICROUSD_PER_MILLION`, `BEDROCK_OUTPUT_MICROUSD_PER_MILLION` | Current model prices; no defaults |
| `MAX_INPUT_TOKENS`, `MAX_OUTPUT_TOKENS` | Per-job token ceilings used for the worst-case reservation |
| `PROBE_ECS_CLUSTER`, `PROBE_ECS_TASK_DEFINITION`, `PROBE_ECS_CONTAINER` | Separate ModSecurity test task |
| `PROBE_ECS_SUBNETS`, `PROBE_ECS_SECURITY_GROUPS` | Comma-separated private network IDs for the test task |

The `PROBE_*` variables are required only for a ModSecurity job with `probe_result_key`.

## Local verification

```sh
go test ./...
go vet ./...
docker build -t waf-worker -f Dockerfile .
docker build -t waf-testtask -f Dockerfile.testtask .
WAF_DOCKER_INTEGRATION=1 go test ./cmd/testtask -run TestDockerProbe -v
cd webfunction && npm ci && NODE_ENV=test node --test index.test.js
cd ../infra/terraform && terraform init -backend=false && terraform validate
```

The Docker integration test sends all 21 fixed cases to the real Apache/ModSecurity testbed and verifies both blocking and disabled-rule outcomes. It is opt-in because it needs a local Docker daemon. Unit tests cover category bounds, receipt consistency, language selection, prompt constraints, token-cost arithmetic, budget reservation, and ECS task configuration. There is no deployed AWS integration test yet: Cognito/Turnstile API handling, S3/ECS orchestration, Bedrock output language, and the $3 daily cap still need a staging environment test before public launch.

To test the ModSecurity task locally, create a service-style job JSON and run the image with a **private, no-network** container. The image accepts local paths only for this development mode:

```sh
docker run --rm --network none --memory 512m --pids-limit 256 \
  -e LOCAL_JOB_FILE=/input/job.json -e LOCAL_RESULT_FILE=/output/receipt.json \
  -v /absolute/private/test-directory:/input:ro \
  -v /absolute/private/test-directory:/output \
  waf-testtask
```

The test task writes a receipt JSON file to the output directory. It runs a dummy backend internally; no target URL is accepted from the user. The separate `cmd/probe` command can exercise a trusted loopback WAF testbed during development.

## Browser API contract

The public legal pages are `/terms` and `/privacy` (Japanese and English). They identify 西川 彰 as the individual operator, give `info [at] i-wind.jp` (replace `[at]` with `@`) as the contact address, offer the postal address on request, and name the Kagoshima District Court as the agreed first-instance court to the extent permitted by law. The browser requires a checked Terms of Service box before submission, and the API independently requires `terms_accepted: true`; the short-lived evaluation record stores the terms version. **Before public launch, verify the selected Bedrock model's retention terms, actual deployment settings, and the operator's ability to answer address requests promptly; obtain a legal review of the final wording.** Job objects are targeted for deletion after 7 days, results after 30 days, CloudWatch logs after 7 days, and DynamoDB evaluation/quota records through TTL after roughly 3 or 32 days. Cognito accounts remain until deleted through an operator-handled request.

`web/index.html` sends `POST /api/evaluations` with `{kind, language, snapshot, attack_categories, turnstile_token, terms_accepted}` and expects `{job_id, status_url}`. It polls that same-origin URL until it returns `{status:"complete", report:{language, summary, assessment, attack_results}}` or `{status:"failed", message}`. Rendered model text is inserted as text, never HTML. A server-owned `window.WAF_CONFIG.turnstileSiteKey` enables the Turnstile widget. The API verifies the Cognito ID-token cookie and Turnstile token server-side, enforces the 1 MiB input limit, and creates the private job. The Web Functions endpoint and CloudFront distribution are defined in Terraform; a live staging test is required before public use.
