# CertiChain — Certificate Validation Application

A Flask MVP for academic certificate issuance, upload/camera capture, verification, revocation, stakeholder profiles, admin user listing, and audit logs.

## Stakeholders
- **Admin:** user list, audit log, all certificates dashboard.
- **Institution:** issue certificates, upload a PDF/image or capture an image using a camera, view issued records, revoke its own certificates.
- **Student:** profile and records associated with the account's name.
- **Employer / verifier:** public certificate lookup by certificate ID without signing in.

## Requirements
- Python 3.10+
- Modern browser
- Camera works on `localhost` or an HTTPS deployment and requires user permission.

## Run locally (Windows PowerShell)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

## Demo admin account
- Email: `admin@example.com`
- Password: `Admin123!ChangeMe`

Change/remove this seeded account before any shared or production deployment. This is a demo credential and must never be used on a public server.

## Main workflow
1. Sign in as the seeded admin and inspect user/audit pages.
2. Register a separate Institution account and sign in with it.
3. Issue a certificate with sample data; optionally upload a file or take a photo.
4. Copy the certificate ID and verify it publicly.
5. Revoke it as the issuing institution, then verify again.
6. Call `/api/chain/validate` to check local record-chain integrity.

## Important technical notes
- This is a **local integrity-chain MVP**, not a decentralized blockchain. SQLite stores records in one database; there is no peer-to-peer consensus or public-chain deployment.
- File hashes are checked during verification. The chain links certificate issuance records in database insertion order.
- Revocation is stored as a status update in SQLite in this MVP. For an immutable event history, store revocation as a separate append-only event and anchor hashes to a real blockchain.
- Public verification reveals limited-but-still-personal data (student name, course, institution, issue date). Obtain consent and review applicable privacy laws before deployment.
- File uploads are restricted by extension and size, but production should also validate actual file signatures/MIME, scan for malware, store uploads outside the web root or in private object storage, and add rate limiting.
- Add CSRF protection, email verification, password reset, institution approval workflow, MFA for admins, secure secret management, HTTPS, backups, logging/monitoring, and a security review before handling real student records.
- The built-in Flask server is for local development only. Use a production WSGI server such as Waitress or Gunicorn behind HTTPS for deployment.
- The record hash is a tamper-evidence mechanism, not a digital signature or proof of a real-world credential. A database administrator able to rewrite all records could recalculate this local chain. A production system needs stronger key management and independent anchoring.

## Environment
Copy `.env.example` to `.env` and set a strong `SECRET_KEY`. The app currently reads environment variables from the process; it does not automatically load `.env`. In PowerShell, set one for the current terminal:
```powershell
$env:SECRET_KEY = "replace-with-a-long-random-secret"
python app.py
```

## Project structure
```text
certverify-client-app/
  app.py
  requirements.txt
  .env.example
  templates/
  static/style.css
  data/                 # created at runtime
  uploads/              # uploaded files at runtime
```
