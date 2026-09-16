# Parent handoff — PhaseOne10841.me marketing site (demo + sales)

## Built on box (ready)
`/workspace/PhaseOne10841ME/website/`
- **New:** `demo.html`, `sales.html`, `htaccess.prepend`
- **Updated:** `index.html` (Demo/Sales nav + hero CTA), `styles.css` (page-hero, steps, mock-ui, tiers)
- Unchanged helpers: `script.js`, `robots.txt`, `favicon.svg`, `DEPLOY_FROM_WINDOWS.ps1`

Zip (optional): recreate with
`cd /workspace && zip -r PhaseOne10841ME-website.zip PhaseOne10841ME/website/`

## Executor deploy status (this box)
- **SSH alias `phaseone10841`:** NOT reachable here (`Could not resolve hostname`; no IdentityFile in `~/.ssh`).
- **machineId `b8727108-a473-4199-acc5-1d2c44176a81`:** not exposed to this subagent (no CopyFromBox/ListMachines/machineId Shell).
- Public site **already serves HTTPS** for `https://phaseone10841.me/` (200, Apache) but **HTTP does not redirect** yet; **demo/sales are 404** until upload.

## Parent: finish deploy
1. CopyFromBox from `/workspace/PhaseOne10841ME/website/` → Windows path used by deploy script  
   machineId: `b8727108-a473-4199-acc5-1d2c44176a81`
2. On Windows Shell(machineId=...), run `DEPLOY_FROM_WINDOWS.ps1` **or**:
   ```
   scp index.html styles.css script.js robots.txt favicon.svg demo.html sales.html phaseone10841:~/public_html/
   ```
3. Prepend HTTPS rules **without wiping** cPanel php blocks:
   ```
   scp htaccess.prepend phaseone10841:~/public_html/
   ssh phaseone10841 'cd ~/public_html && cp .htaccess .htaccess.bak && cat htaccess.prepend .htaccess > .htaccess.new && mv .htaccess.new .htaccess && rm htaccess.prepend && head -40 .htaccess'
   ```
   Skip prepend if remote `.htaccess` already contains `PhaseOne10841.me HTTPS`.
4. Do **NOT** delete `.htaccess`, `php.ini`, `.well-known`, `cgi-bin`.
5. Verify:
   ```
   curl -I https://phaseone10841.me/
   curl https://phaseone10841.me/demo.html | grep PhaseOne
   curl https://phaseone10841.me/sales.html | grep Early
   curl -I http://phaseone10841.me/   # expect 301 → https after .htaccess
   ```

Domain: **phaseone10841.me ONLY** · Company: Veracity Integrity LLC
