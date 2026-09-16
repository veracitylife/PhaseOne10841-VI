$ErrorActionPreference = 'Stop'
$src = 'C:\Users\disru\Documents\PhaseOne10841ME\website'
if (-not (Test-Path $src)) { throw "Missing $src — CopyFromBox /workspace/PhaseOne10841ME/website/ first" }
Write-Host "Local website files:"
Get-ChildItem $src | Format-Table Name, Length
Write-Host "SSH config alias probe:"
ssh -G phaseone10841 | Select-String -Pattern '^(host|hostname|user|identityfile|port) '
Write-Host "Remote public_html before:"
ssh phaseone10841 'ls -la ~/public_html | head -40'

# Static site files (do NOT overwrite .htaccess wholesale)
$files = @('index.html','styles.css','script.js','robots.txt','favicon.svg','demo.html','sales.html')
foreach ($f in $files) {
  $local = Join-Path $src $f
  if (-not (Test-Path $local)) { throw "Missing $local" }
  scp $local "phaseone10841:~/public_html/$f"
  Write-Host "Uploaded $f"
}

# Carefully prepend HTTPS rules if not already present (preserve cPanel php blocks)
$prepend = Join-Path $src 'htaccess.prepend'
if (Test-Path $prepend) {
  Write-Host "Ensuring HTTPS rewrite at TOP of remote .htaccess..."
  scp $prepend "phaseone10841:~/public_html/htaccess.prepend"
  ssh phaseone10841 @'
set -e
cd ~/public_html
if [ ! -f .htaccess ]; then
  cp htaccess.prepend .htaccess
  echo "Created .htaccess from prepend"
elif grep -q "PhaseOne10841.me HTTPS" .htaccess; then
  echo "HTTPS block already present — left .htaccess unchanged"
else
  cp .htaccess .htaccess.bak.$(date +%Y%m%d%H%M%S)
  cat htaccess.prepend .htaccess > .htaccess.new
  mv .htaccess.new .htaccess
  echo "Prepended HTTPS block; backup saved"
fi
rm -f htaccess.prepend
head -40 .htaccess
'@
}

Write-Host "Remote public_html after:"
ssh phaseone10841 'ls -la ~/public_html | head -40'
Write-Host "Verify:"
ssh phaseone10841 'head -c 200 ~/public_html/demo.html; echo; head -c 200 ~/public_html/sales.html; echo'
curl.exe -sS -I https://phaseone10841.me/ | Select-Object -First 12
curl.exe -sS https://phaseone10841.me/demo.html | Select-String -Pattern 'PhaseOne' | Select-Object -First 3
curl.exe -sS https://phaseone10841.me/sales.html | Select-String -Pattern 'Early' | Select-Object -First 3
