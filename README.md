# Sentinel — AI-Driven Honeypot SOC (Desktop Demo)

A local desktop-browser prototype for the project title:

**AI-Driven Honeypot for Dynamic Multistage Attack Prevention with Blockchain Forensic Method**

## Six modules
1. Live Security Dashboard
2. AI Threat Analysis (explainable rule-based classifier; not a trained AI model)
3. Dynamic Honeypot Simulator (safe simulated events; no network attacks)
4. Automated IP Blocking (local app blocklist only; does not change OS/firewall rules)
5. Blockchain Forensic Ledger (SHA-256 hash-linked SQLite records; not a distributed blockchain)
6. Forensic Reports (JSON export)

## Run on Windows / ThinkPad
1. Install Python 3.10 or newer from https://www.python.org/downloads/ and select **Add Python to PATH**.
2. Extract this folder anywhere, then open it in VS Code or File Explorer.
3. Open a terminal in this folder and run:

   ```powershell
   py -m venv .venv
   .\\.venv\\Scripts\\Activate.ps1
   pip install -r requirements.txt
   py app.py
   ```

   If PowerShell blocks activation, you can skip activation and run:
   ```powershell
   py -m pip install -r requirements.txt
   py app.py
   ```

4. Open http://127.0.0.1:5000 in Chrome or Edge. You will see the Sign In page; choose Create an account to register the first user.
5. Stop the server with Ctrl+C in the terminal.

## Tech stack
- Frontend: HTML, CSS, JavaScript
- Backend: Python + Flask (small local API)
- Database: SQLite (created automatically in `data/honeypot.db`)
- Forensic hashing: Python `hashlib` SHA-256
- C++ and Java: optional extensions, not required for this working prototype

## Important scope and safety
This is a college-project prototype, not a production IDS/IPS. All attack scenarios are simulated and use documentation-only IP ranges for seeded data. The local blocklist is only used by this app; it does not block packets at OS/network level. The hash chain is tamper-evident but a person with direct database access could rewrite the full chain. Production deployment needs isolated honeypot infrastructure, authentication, network controls, logging hardening, tests, and a real ML pipeline.

## Sign up / Sign in
- Visit `/signup` to create an account with full name, username, email, and password.
- Passwords are stored as Werkzeug password hashes, not plain text.
- Sign in at `/login` with username or email and password.
- Use Sign out in the workspace header. Workspace API routes require a login session.
- This is a local academic demo; set `SENTINEL_SECRET_KEY` to a private random value before any shared deployment.
