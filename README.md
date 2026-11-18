# CloudShield 360 (free-tier edition + EC2 network segmentation)

Serverless site (API Gateway + Lambda + private S3), scanned data bucket, locked backups,
event-driven detection and containment, PLUS a three-tier network:

| Tier | Resources | Network rule |
|---|---|---|
| Public | Application Load Balancer, regional WAF, internet gateway | Internet may reach only the load balancer |
| App | EC2 in an Auto Scaling group, private subnets, no internet route | Accepts port 8080 from the load balancer only; SSH only through an Instance Connect Endpoint |
| Data | S3 data bucket | Reached from the app tier only through an S3 gateway endpoint with an endpoint policy |

Extras: IMDSv2 only, encrypted volumes, locked default security group, a quarantine security group,
VPC flow logs to the logs bucket, and the `isolate_instance` containment function.

## Files (new or changed in this edition)
- `network.tf`  - VPC, subnets, route tables, S3 endpoint, security groups, Instance Connect Endpoint, flow logs
- `compute.tf`  - instance role, launch template, load balancer, Auto Scaling group
- `containment_ec2.tf`, `lambda/isolate_instance.py` - EC2 isolation
- `containment.tf`, `s3.tf`, `variables.tf`, `outputs.tf` - extended
- all earlier files unchanged (website, backup, monitoring, scanner, identity and bucket isolation)

## Apply on top of your existing deployment
1. Copy these files over your current project folder (keep `terraform.tfstate` and `.terraform`).
2. `terraform init -upgrade`, `terraform validate`, `terraform plan -out tfplan`, `terraform apply tfplan`.
3. Wait 3-5 minutes for the first instance to become healthy in the target group.
4. `terraform output alb_url` and open it: the app tier page loads (HTTP only unless you set `alb_certificate_arn`).

If the load balancer or EC2 is refused with an activation or verification error, the account needs the same
activation as before; open the support case and re-run.

## Demonstrate the network segmentation
1. Public tier: `curl.exe -i <alb_url>` returns 200. In EC2 > Instances the app instance has no public IP.
2. Open EC2 > Instances > select the app instance > Connect > EC2 Instance Connect > "Connect using EC2 Instance Connect Endpoint" > Connect. Inside the instance run:
   - `curl -m 5 https://example.com` -> times out (no internet route)
   - `curl -m 5 http://169.254.169.254/latest/meta-data/` -> 401 (IMDSv2 required)
   - `aws s3 ls s3://<data_bucket>/app/` -> lists the heartbeat file (data tier through the endpoint)
   - `aws s3 ls s3://<website_bucket>/` -> AccessDenied (role and endpoint policy)
3. Show the rules: VPC > Security groups (alb, app, eice, quarantine) and Route tables (the app table has no 0.0.0.0/0 route).
4. Flow logs: after about 10 minutes `aws s3 ls s3://<logs_bucket>/vpc-flow/ --recursive` shows delivered logs;
   rejected connections appear with `REJECT`.

## Demonstrate EC2 isolation
1. Pick the instance ID: `aws ec2 describe-instances --filters Name=tag:Project,Values=CloudShield360 Name=instance-state-name,Values=running --query "Reservations[].Instances[].InstanceId" --output text`
2. Tag it: `aws ec2 create-tags --resources <instance-id> --tags Key=SecurityIsolate,Value=true`
   (or invoke `<project>-isolate_instance` with `tests/instance_event.json`).
3. Within a few minutes: you get an email; the instance uses only the quarantine security group; snapshots exist
   (`aws ec2 describe-snapshots --owner-ids self --filters Name=tag:Project,Values=CloudShield360`);
   the Auto Scaling group launches a replacement and the load balancer keeps serving.
4. Cleanup of the isolated instance: terminate it (`aws ec2 terminate-instances --instance-ids <id>`) and delete the snapshots.

## Clean up
1. Terminate any detached, isolated instance and delete forensic snapshots first, otherwise `terraform destroy` fails on the subnet and security group.
2. `terraform destroy` inside the Vault Lock cooling-off window.
3. The load balancer and EC2 are billed against your credits; destroy as soon as you have your evidence.

## Limits
- HTTP only on the load balancer unless you provide an ACM certificate.
- The app is a small Python web server for demonstration; replace it with your real application.
- No NAT gateway and no interface endpoints, so the instance cannot reach SSM or other AWS APIs. Package updates work only through the S3 endpoint.
- Network ACLs are not included; security groups enforce the tiers.
- No database tier. Add RDS in the app-tier pattern (new private subnets, a security group that accepts only the app security group) when needed.

## One-pass run (Windows PowerShell)
1. `powershell -ExecutionPolicy Bypass -File scripts\deploy.ps1` - checks credentials, init, validate, plan, asks, applies.
2. Confirm the SNS email and wait 3-5 minutes for the instance to become healthy.
3. `powershell -ExecutionPolicy Bypass -File scripts\verify.ps1 -WithScanTest` - PASS/FAIL checks of every tier.
