# PhaseOne10841.me website deployment

The public site source is maintained in this repository's `website/` directory.
The production target is `phaseone10841.me`, served from the cPanel account's
`public_html` directory on the configured `phaseone10841` SSH alias.

## Deploy

From PowerShell at the repository root:

```powershell
./website/DEPLOY_FROM_WINDOWS.ps1
```

The script validates its source files, stages the site over SSH, makes a private
timestamped copy of files currently on the server under `public_html/backup-files/`,
then promotes the new files individually. It checks the homepage, contact, hire,
and terms pages over HTTPS. It leaves `.htaccess`, PHP configuration, mail routing,
and unrelated account files untouched.

The forms currently route inquiries to the published `info@veracityintegrity.com` inbox. The requested dedicated `PhaseOneEDR@veracityintegrity.com` forwarding address was not created because cPanel UAPI/permissions are failing; set it up through a repaired cPanel service before changing form routing.

## Roll back

Use the backup directory printed by the deployment script. Restore only the files
that need rollback, for example:

```bash
cp -p ~/public_html/backup-files/phaseone-deploy-TIMESTAMP/contact.html ~/public_html/contact.html
```

Replace `TIMESTAMP` with the actual deployment directory name.
