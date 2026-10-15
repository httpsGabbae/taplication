# TapLication · admissions school project

TapLication is a Flask demo for fictional college applications. It includes an application form, a QR applicant pass, camera and image QR lookup, manual reference lookup, and a demo admin ledger.

## Publish through GitHub → Vercel

1. Create a GitHub repository and add the **contents** of the clean `taplication-github-ready.zip` package at the repository root. The root must contain `app.py`, `vercel.json`, `templates/`, and `public/`.
2. In Vercel, import that GitHub repository as a new project. The repo pins Python 3.14 and includes the Vercel configuration.
3. Add `FLASK_SECRET_KEY` in Vercel Project Settings → Environment Variables. Use one stable random value of at least 32 characters for all environments. Do not commit it.
4. Enable Vercel system environment variables so `VERCEL_URL` and `VERCEL_PROJECT_PRODUCTION_URL` are available. Alternatively, set `PUBLIC_BASE_URL=https://your-project.vercel.app` and `TRUSTED_HOSTS=your-project.vercel.app`. If you use a custom domain, set these to that domain.
5. Deploy, then submit a fictional application. Print its pass, scan the QR from **Find my pass**, and verify it opens the signed pass link. The QR is also readable by a phone camera.

Vercel automatically enables demo mode. Document uploads and AI scanning are disabled. SQLite runs in the function's temporary directory, so ledger records and status changes can reset between visits or function instances. A printed signed pass can still open the sample pass, but its live status is only reliable while the record remains in the current function instance. **Do not enter real applicant information.**

## Demo admin

Type `/login.php` or `/login.html` after the site domain to enter the demo admin ledger. There is no username or password form. These URLs are **not authentication**; anyone who knows or discovers one can enter. The admin workflow is available only in demo mode and must only contain fictional data. `/staff/login` is removed. Use **Leave admin** to end the current admin session.

## Local development

Use Python 3.14:

```powershell
python -m venv venv
.\venv\Scripts\pip.exe install -r requirements.txt
$env:DEMO_MODE = '1'
$env:FLASK_SECRET_KEY = 'replace-with-a-long-random-value-for-local-demo'
.\venv\Scripts\python.exe app.py
```

Open `http://127.0.0.1:5000`. Camera scanning requires a secure context; localhost and Vercel HTTPS meet that requirement. The scanner uses the browser's `BarcodeDetector` where available and a bundled jsQR fallback elsewhere. The manual lookup remains available if camera permission is denied. Run checks with `.\venv\Scripts\python.exe -m unittest discover -s tests -v`.

## Scope

This package is for a school project. It is not a real admissions service. A real deployment needs authenticated staff accounts, a persistent database, private document storage, email delivery, backups, a retention policy, and institutional approval for processing personal data. The scanner extracts fields when configured for a non-demo environment; it does not train a model. The Vercel demo needs no Gemini key.

The browser QR fallback includes [jsQR 1.4.0](https://github.com/cozmo/jsQR) under Apache 2.0; its license is included at `public/static/vendor/jsQR-LICENSE.txt`.
