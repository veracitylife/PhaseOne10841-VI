from pathlib import Path
from datetime import date
import re
import shutil
from time import strftime

pub = Path('/home/veracityintegrit/public_html')
backup = pub / 'backup-files'
backup.mkdir(exist_ok=True)
stamp = strftime('%Y%m%d%H%M%S')

index = pub / 'index.html'
contact = pub / 'contact-us' / 'index.html'
sitemap = pub / 'sitemap.xml'

shutil.copy2(index, backup / f'index.html.bak-phaseone-{stamp}')
shutil.copy2(contact, backup / f'contact-us.index.html.bak-phaseone-{stamp}')
shutil.copy2(sitemap, backup / f'sitemap.xml.bak-phaseone-{stamp}')

text = index.read_text(encoding='utf-8')

old_nav = """    <nav>
      <a href=\"#solutions\">Solutions</a>
      <a href=\"#verifact\">VeriFact</a>
      <a href=\"#glasses\">AR Glasses</a>
      <a href=\"#ethics\">Ethics</a>
      <a href=\"#updates\">Updates</a>
      <a href=\"#contact\">Contact</a>
    </nav>"""
new_nav = """    <nav>
      <a href=\"#solutions\">Solutions</a>
      <a href=\"#verifact\">VeriFact</a>
      <a href=\"phaseone10841/\">PhaseOne10841</a>
      <a href=\"#glasses\">AR Glasses</a>
      <a href=\"#ethics\">Ethics</a>
      <a href=\"#updates\">Updates</a>
      <a href=\"#contact\">Contact</a>
    </nav>"""

if 'href="phaseone10841/"' not in text.split('<header', 1)[1].split('</header>', 1)[0]:
    if old_nav not in text:
        raise SystemExit('homepage nav block not found')
    text = text.replace(old_nav, new_nav, 1)

pillar = """        <article>
          <h3>PhaseOne10841 Agent EDR</h3>
          <p>Defensive Agent Security Gateway for autonomous agents—policy, canaries, A2A firewall, session replay, and human approval outside the model.</p>
          <a href=\"phaseone10841/\">Explore PhaseOne10841</a>
        </article>
"""
if 'PhaseOne10841 Agent EDR' not in text:
    marker = """        <article>
          <h3>API Integration and Developer Tools</h3>"""
    if marker not in text:
        raise SystemExit('solutions pillar marker not found')
    text = text.replace(marker, pillar + marker, 1)

update_item = """          <li><a href=\"phaseone10841/\">PhaseOne10841 Defensive Agent Security Gateway (Agent EDR)</a></li>
"""
if 'PhaseOne10841 Defensive Agent Security Gateway' not in text:
    marker = """          <li><a href=\"introducing-veracity-integrity-llc/\">Introducing Veracity Integrity LLC</a></li>"""
    if marker not in text:
        raise SystemExit('updates list marker not found')
    text = text.replace(marker, update_item + marker, 1)

if 'href="phaseone10841/"' not in text.split('Footer links', 1)[1][:600]:
    old = '<a href="#verifact">VeriFact</a>\n      <a href="#contact">Contact</a>'
    new = '<a href="phaseone10841/">PhaseOne10841</a>\n      <a href="#verifact">VeriFact</a>\n      <a href="#contact">Contact</a>'
    if old not in text:
        raise SystemExit('footer links marker not found')
    text = text.replace(old, new, 1)

text = text.replace(
    'AI-driven truth verification, sincerity analytics, VeriFact fact checking, and ethical integrity technology.',
    'AI-driven truth verification, sincerity analytics, VeriFact fact checking, PhaseOne10841 Agent EDR, and ethical integrity technology.',
    1,
)

index.write_text(text, encoding='utf-8')
print('index updated')

ct = contact.read_text(encoding='utf-8')
if 'phaseone10841' not in ct:
    ct2 = ct.replace(
        '<nav><a href="../#solutions">Solutions</a><a href="../#verifact">VeriFact</a><a href="../#glasses">AR Glasses</a><a href="../#updates">Updates</a><a href="../contact-us/">Contact</a></nav>',
        '<nav><a href="../#solutions">Solutions</a><a href="../#verifact">VeriFact</a><a href="../phaseone10841/">PhaseOne10841</a><a href="../#glasses">AR Glasses</a><a href="../#updates">Updates</a><a href="../contact-us/">Contact</a></nav>',
        1,
    )
    if ct2 == ct:
        raise SystemExit('contact nav not found')
    ct = ct2.replace(
        '<a href="../verifact-put-truth-back-at-the-center-of-your-content/">VeriFact</a><a href="../#ethics">Ethical AI verification</a>',
        '<a href="../phaseone10841/">PhaseOne10841</a><a href="../verifact-put-truth-back-at-the-center-of-your-content/">VeriFact</a><a href="../#ethics">Ethical AI verification</a>',
        1,
    )
    contact.write_text(ct, encoding='utf-8')
    print('contact updated')
else:
    print('contact already has phaseone')

s = sitemap.read_text(encoding='utf-8')
today = date.today().isoformat()
if 'phaseone10841/' not in s:
    entry = f'  <url><loc>https://www.veracityintegrity.com/phaseone10841/</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>0.9</priority></url>\n'
    s = s.replace('</urlset>', entry + '</urlset>')
s = re.sub(r'(<loc>https://www.veracityintegrity.com/</loc>\s*<lastmod>)[^<]+', r'\g<1>' + today, s, count=1)
sitemap.write_text(s, encoding='utf-8')
print('sitemap updated')
print('done')