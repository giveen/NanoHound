# NanoHound

NanoHound is a lightweight, in-memory Active Directory attack path explorer built with NiceGUI and NetworkX.

## Requirements

- Python 3.11+
- `pip`

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open the local URL shown in the terminal (usually `http://127.0.0.1:8080`).

## Usage

- Upload SharpHound `.zip` or `.json` files from the UI.
- Use graph filters for Kerberoastable / AS-REP roastable users.
- Add credentials in the Loot tab.
- Click graph edges/nodes for command suggestions.
- Save and restore your work using session import/export JSON.

## Notes

- Local test ZIPs (for example `klen_bloodhound.zip`) are git-ignored.
