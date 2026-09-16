$ErrorActionPreference = 'Stop'
$src = 'C:\Users\disru\Documents\PhaseOne10841ME\website'
if (-not (Test-Path $src)) { throw "Missing $src" }
Write-Host "Local website files:"
Get-ChildItem $src | Format-Table Name, Length
Write-Host "SSH config alias probe:"
ssh -G phaseone10841 | Select-String -Pattern '^(host|hostname|user|identityfile|port) '
Write-Host "Remote public_html before:"
ssh phaseone10841 'ls -la ~/public_html | head -40'
# Deploy without deleting protected dirs
$files = @('index.html','styles.css','script.js','robots.txt','favicon.svg')
foreach ($f in $files) {
  $local = Join-Path $src $f
  if (-not (Test-Path $local)) { throw "Missing $local" }
  scp $local "phaseone10841:~/public_html/$f"
  Write-Host "Uploaded $f"
}
Write-Host "Remote public_html after:"
ssh phaseone10841 'ls -la ~/public_html | head -40'
Write-Host "Remote index sniff:"
ssh phaseone10841 'head -c 400 ~/public_html/index.html; echo; curl -sS -o /dev/null -w "%{http_code}\n" -H "Host: phaseone10841.net" http://127.0.0.1/'
