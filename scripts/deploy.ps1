# One-pass deployment of CloudShield 360 (EC2 edition). Run from the project folder:
#   powershell -ExecutionPolicy Bypass -File scripts\deploy.ps1
$env:AWS_PAGER = ""

function Run($description, [scriptblock]$command) {
    Write-Host ""
    Write-Host "==> $description" -ForegroundColor Cyan
    & $command
    if ($LASTEXITCODE -ne 0) { throw "Step failed: $description" }
}

if (-not (Test-Path "terraform.tfvars")) {
    Copy-Item "terraform.tfvars.example" "terraform.tfvars"
    Write-Host "Created terraform.tfvars. Edit alert_email (and anything else), then run this script again." -ForegroundColor Yellow
    exit 1
}

Run "Check AWS credentials"      { aws sts get-caller-identity }
Run "Initialise Terraform"       { terraform init -upgrade }
Run "Validate configuration"     { terraform validate }
Run "Create plan"                { terraform plan -out tfplan }

$answer = Read-Host "Apply this plan? Type yes to continue"
if ($answer -ne "yes") { Write-Host "Stopped before apply."; exit 0 }

Run "Apply"                      { terraform apply tfplan }
Run "Outputs"                    { terraform output }

Write-Host ""
Write-Host "Next: confirm the SNS email, wait 3-5 minutes for the instance to become healthy, then run scripts\verify.ps1" -ForegroundColor Green
