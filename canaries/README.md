# Canary files (harmless markers)

These files contain **fake** credential-shaped values used as tripwires.
They are **not** real secrets. If an agent reads or exfiltrates these marker
strings through the gateway, PhaseOne emits a high-severity `canary.trigger` event.

Do not replace these with real credentials.
