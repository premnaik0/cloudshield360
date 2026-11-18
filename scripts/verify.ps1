# Automatic checks of the deployed project. Run from the project folder:
#   powershell -ExecutionPolicy Bypass -File scripts\verify.ps1
#   add -WithScanTest to also upload a harmless .exe-named file and check that it is quarantined
param(
    [string]$Project = "cloudshield360",
    [switch]$WithScanTest
)
$env:AWS_PAGER = ""

function Code($url) { (curl.exe -s -m 15 -o NUL -w "%{http_code}" $url) }
function Check($name, $actual, $expected) {
    if ("$actual".Trim() -eq "$expected") { Write-Host ("PASS  {0}  ({1})" -f $name, $actual) -ForegroundColor Green }
    else { Write-Host ("FAIL  {0}  (got '{1}', expected '{2}')" -f $name, $actual, $expected) -ForegroundColor Red }
}

$alb   = terraform output -raw alb_url
$api   = terraform output -raw website_url
$data  = terraform output -raw data_bucket
$quar  = terraform output -raw quarantine_bucket
$inj   = "?x=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

Write-Host "`n--- Public tier and edge ---"
Check "Load balancer serves the app tier"            (Code $alb) 200
Check "API site serves the website bucket"           (Code $api) 200
Check "Website cannot read other buckets (404)"      (Code "${api}not-in-website-bucket.txt") 404
Check "WAF blocks script injection on the API"       (Code "$api$inj") 403
Check "WAF blocks script injection on the ALB"       (Code "$alb$inj") 403

Write-Host "`n--- App tier network ---"
$publicIps = aws ec2 describe-instances --filters "Name=tag:Project,Values=CloudShield360" "Name=instance-state-name,Values=running" --query "Reservations[].Instances[].PublicIpAddress" --output text
Check "App instances have no public IP"              ($publicIps -replace "None","").Trim() ""

$appRoutes = aws ec2 describe-route-tables --filters "Name=tag:Name,Values=$Project-app-rt" --query "RouteTables[0].Routes[].GatewayId" --output text
Check "App route table has no internet gateway"      ([string]($appRoutes -match "igw-")) "False"

$q = aws ec2 describe-security-groups --filters "Name=group-name,Values=$Project-quarantine-sg" --query "SecurityGroups[0].[length(IpPermissions),length(IpPermissionsEgress)]" --output text
Check "Quarantine group has no rules (in, out)"      ($q -replace "\s+"," ") "0 0"

$appIn = aws ec2 describe-security-groups --filters "Name=group-name,Values=$Project-app-sg" --query "SecurityGroups[0].IpPermissions[].IpRanges[].CidrIp" --output text
Check "App group accepts no CIDR ranges (groups only)" $appIn.Trim() ""

Write-Host "`n--- Data tier and scanner ---"
Check "Data bucket public access fully blocked"      (aws s3api get-public-access-block --bucket $data --query "PublicAccessBlockConfiguration.[BlockPublicAcls,BlockPublicPolicy,IgnorePublicAcls,RestrictPublicBuckets]" --output text) "True True True True"

if ($WithScanTest) {
    "test" | Set-Content verify-test.exe
    aws s3 cp verify-test.exe "s3://$data/verify-test.exe" | Out-Null
    Write-Host "Uploaded verify-test.exe, waiting 60 seconds for the scanner..."
    Start-Sleep -Seconds 60
    $inData = aws s3 ls "s3://$data/verify-test.exe"
    $inQuar = aws s3 ls "s3://$quar/" --recursive | Select-String "verify-test.exe"
    Check "Dangerous upload removed from data bucket" ([string]($null -ne $inData -and $inData -ne "")) "False"
    Check "Dangerous upload found in quarantine"      ([string]($null -ne $inQuar)) "True"
    Remove-Item verify-test.exe -ErrorAction SilentlyContinue
}

Write-Host "`nDone. FAIL lines point to the part to inspect; the demonstration steps cover the rest (isolation, flow logs)."
