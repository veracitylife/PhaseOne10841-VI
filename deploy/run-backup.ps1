Set-Location "C:\Users\disru\Documents\PhaseOne10841ME"
bash scripts/backup.sh 2>$null
if ($LASTEXITCODE -ne 0) {
  New-Item -ItemType Directory -Force backups | Out-Null
  docker compose exec -T postgres pg_dump -U phaseone phaseone | Out-File -Encoding utf8 ("backups\phaseone-{0:yyyyMMdd-HHmmss}.sql" -f (Get-Date))
}
