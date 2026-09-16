$ErrorActionPreference = 'Stop'
$src = 'C:\Users\disru\Documents\PhaseOne10841ME\website'
if (-not (Test-Path $src)) { throw "Missing $src" }
Write-Host 'Local website files:'
Get-ChildItem $src | Format-Table Name, Length
Write-Host 'SSH config alias probe:'
ssh -G phaseone10841 | Select-String -Pattern '^(host|hostname|user|identityfile|port) '
Write-Host 'Remote public_html before:'
ssh phaseone10841 'ls -la ~/public_html | head -40'
# Deploy without deleting protected dirs (.htaccess, php.ini, .well-known, cgi-bin)
$files = @('index.html','styles.css','script.js','robots.txt','favicon.svg','demo.html','sales.html')
foreach ($f in $files) {
  $local = Join-Path $src $f
  if (-not (Test-Path $local)) { throw "Missing $local" }
  scp $local "phaseone10841:~/public_html/$f"
  Write-Host "Uploaded $f"
}
$pre = Join-Path $src 'htaccess.prepend'
if (Test-Path $pre) {
  scp $pre 'phaseone10841:~/public_html/htaccess.prepend'
  ssh phaseone10841 'set -e; cd ~/public_html; if [ -f .htaccess ] && grep -q demo.html .htaccess 2>/dev/null; then echo htaccess already has demo routes; else if [ -f .htaccess ]; then cp .htaccess .htaccess.bak.phase5; fi; cat htaccess.prepend >> .htaccess; echo Appended htaccess.prepend; fi; rm -f htaccess.prepend'
}
Write-Host 'Remote public_html after:'
ssh phaseone10841 'ls -la ~/public_html | head -40'
Write-Host 'Remote verify:'
ssh phaseone10841 'head -c 200 ~/public_html/index.html; echo; curl -sS -o /dev/null -w "index:%{http_code}\n" -H "Host: phaseone10841.net" http://127.0.0.1/; curl -sS -o /dev/null -w "demo:%{http_code}\n" -H "Host: phaseone10841.net" http://127.0.0.1/demo.html; curl -sS -o /dev/null -w "sales:%{http_code}\n" -H "Host: phaseone10841.net" http://127.0.0.1/sales.html'
