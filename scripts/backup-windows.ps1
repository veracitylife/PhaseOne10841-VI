Set-Location "C:\Users\disru\Documents\PhaseOne10841ME"
New-Item -ItemType Directory -Force -Path backups | Out-Null
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
docker compose exec -T postgres pg_dump -U phaseone phaseone | Set-Content "backups\phaseone-$ts.sql"
Copy-Item policy\default-policy.yaml "backups\policy-$ts.yaml" -ErrorAction SilentlyContinue
Write-Output "backup done $ts"
