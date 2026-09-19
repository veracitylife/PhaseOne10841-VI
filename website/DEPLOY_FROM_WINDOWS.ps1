$ErrorActionPreference = 'Stop'

# Run from this checked-out repository. SSH uses the configured phaseone10841 key alias.
$src = $PSScriptRoot
$hostAlias = 'phaseone10841'
$targetRoot = '~/public_html'
$files = @(
  'index.html', 'demo.html', 'sales.html', 'hire.html', 'hire-submit.php',
  'contact.html', 'contact-submit.php', 'terms.html', 'styles.css', 'script.js',
  'robots.txt', 'favicon.svg'
)

foreach ($file in $files) {
  $local = Join-Path $src $file
  if (-not (Test-Path -LiteralPath $local -PathType Leaf)) { throw "Missing website source: $local" }
}

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$stage = "$targetRoot/.phaseone-deploy-$stamp"
$backup = "$targetRoot/backup-files/phaseone-deploy-$stamp"
$backupName = "backup-files/phaseone-deploy-$stamp"

Write-Host "Target: $hostAlias`:$targetRoot"
Write-Host "Backup: $backupName"
Write-Host "Uploading $($files.Count) files to a temporary directory..."
$prepare = "set -e; root=`"`$HOME/public_html`"; mkdir -p `"`$root/backup-files`" `"`$root/backup-files/phaseone-deploy-$stamp`" `"`$root/.phaseone-deploy-$stamp`"; chmod 700 `"`$root/backup-files`" `"`$root/backup-files/phaseone-deploy-$stamp`" `"`$root/.phaseone-deploy-$stamp`""
ssh $hostAlias $prepare
if ($LASTEXITCODE -ne 0) { throw 'Could not prepare the remote staging and backup directories.' }

foreach ($file in $files) {
  scp -p (Join-Path $src $file) "${hostAlias}:$stage/$file"
  if ($LASTEXITCODE -ne 0) { throw "Upload failed for $file; live files were not promoted. Staging: $stage" }
}

$fileList = $files -join ' '
$promote = "set -e; root=`"`$HOME/public_html`"; stage=`"`$root/.phaseone-deploy-$stamp`"; backup=`"`$root/backup-files/phaseone-deploy-$stamp`"; for f in $fileList; do if [ -f `"`$root/`$f`" ]; then cp -p `"`$root/`$f`" `"`$backup/`$f`"; fi; done; for f in $fileList; do mv -f `"`$stage/`$f`" `"`$root/`$f`"; done; rmdir `"`$stage`""
ssh $hostAlias $promote
if ($LASTEXITCODE -ne 0) {
  throw "Remote promotion failed. Backup is $backupName; inspect the live site before retrying."
}

Write-Host 'Deployment complete. The prior files are in the private backup directory.'
Write-Host "Rollback example: ssh $hostAlias 'cp -p $backup/index.html $targetRoot/index.html'"
foreach ($path in @('/', '/contact.html', '/hire.html', '/terms.html')) {
  $url = "https://phaseone10841.me$path"
  $status = & curl.exe -sS -o NUL -w '%{http_code}' --max-time 15 $url
  if ($LASTEXITCODE -ne 0 -or $status -ne '200') { throw "Post-deploy check failed for $url (HTTP $status)" }
  Write-Host "$url -> HTTP $status"
}
