import os
import sqlite3
import secrets
import random
import json
import re
import base64
import io
import tempfile
from datetime import datetime
from functools import wraps
from urllib.parse import urlsplit
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify, Response, session, abort
from itsdangerous import URLSafeSerializer, BadSignature

# ── Gemini AI Vision Setup (loads the local .env if present) ──
def _load_dotenv():
    try:
        base = os.path.dirname(os.path.abspath(__file__))
        env_path = os.path.join(base, '.env')
        if os.path.exists(env_path):
            with open(env_path, 'r', encoding='utf-8-sig') as f:
                for line in f:
                    line = line.strip().lstrip('﻿')
                    if not line or line.startswith('#') or '=' not in line:
                        continue
                    k, v = line.split('=', 1)
                    k, v = k.strip(), v.strip().strip('"').strip("'")
                    if k and k not in os.environ:
                        os.environ[k] = v
    except Exception as e:
        print(f"[scanner] .env load skipped: {e}")

_load_dotenv()
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '').strip() or os.environ.get('GOOGLE_API_KEY', '').strip()
try:
    from google import genai
    from google.genai import types as genai_types
    if GEMINI_API_KEY:
        gemini_client = genai.Client(api_key=GEMINI_API_KEY)
        GEMINI_AVAILABLE = True
        print("[scanner] document reading enabled.")
    else:
        GEMINI_AVAILABLE = False
        print("[scanner] No GEMINI_API_KEY found. Scans will return offline message (no fake data). Add GEMINI_API_KEY to .env to enable.")
except ImportError:
    GEMINI_AVAILABLE = False
    print("[scanner] reader library not installed. Scans will return offline message (no fake data).")

# ── OCR provider chain: hybrid (OCR.space free OCR + Gemini text structuring),
#      gemini (direct vision, previous behavior), off (manual typing only) ──
OCR_PROVIDER = os.environ.get('OCR_PROVIDER', 'gemini').strip().lower() or 'gemini'
OCRSPACE_API_KEY = os.environ.get('OCRSPACE_API_KEY', 'helloworld').strip() or 'helloworld'
OCRSPACE_URL = os.environ.get('OCRSPACE_URL', 'https://api.ocr.space/parse/image').strip()
try:
    import requests as _requests
    REQUESTS_AVAILABLE = True
except ImportError:
    _requests = None
    REQUESTS_AVAILABLE = False
if OCR_PROVIDER == 'hybrid' and not REQUESTS_AVAILABLE:
    print("[scanner] 'requests' not installed — hybrid mode falls back to direct Gemini vision.")
print(f"[scanner] OCR provider chain: {OCR_PROVIDER}"
      f"{' (OCR.space + Gemini-text, Gemini-vision fallback)' if OCR_PROVIDER == 'hybrid' else ''}.")
# ──────────────────────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder='public/static')
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IS_VERCEL = bool(os.environ.get('VERCEL'))
DEMO_MODE = os.environ.get('DEMO_MODE') == '1' or IS_VERCEL
DATA_DIR = os.path.abspath(os.environ.get('DATA_DIR', os.path.join(tempfile.gettempdir(), 'taplication-demo') if DEMO_MODE else BASE_DIR))
os.makedirs(DATA_DIR, exist_ok=True)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', '').strip() or secrets.token_urlsafe(32)
app.config.update(MAX_CONTENT_LENGTH=(4 if DEMO_MODE else 40) * 1024 * 1024,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
                  SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE', '1' if IS_VERCEL else '0') == '1')
PUBLIC_BASE_URL = os.environ.get('PUBLIC_BASE_URL', '').strip().rstrip('/') or (
    'https://' + os.environ.get('VERCEL_PROJECT_PRODUCTION_URL', os.environ.get('VERCEL_URL', '')).strip()
    if IS_VERCEL and (os.environ.get('VERCEL_PROJECT_PRODUCTION_URL') or os.environ.get('VERCEL_URL')) else '')
trusted_hosts = [h.strip() for h in os.environ.get('TRUSTED_HOSTS', '').split(',') if h.strip()]
if not trusted_hosts and IS_VERCEL and PUBLIC_BASE_URL:
    trusted_hosts = list(dict.fromkeys(filter(None, (
        urlsplit(PUBLIC_BASE_URL).hostname, os.environ.get('VERCEL_URL'),
        os.environ.get('VERCEL_PROJECT_PRODUCTION_URL')))))
if not trusted_hosts and DEMO_MODE and os.environ.get('APP_ENV') == 'production':
    trusted_hosts = ['.vercel.app']
if trusted_hosts:
    app.config['TRUSTED_HOSTS'] = trusted_hosts
if os.environ.get('APP_ENV') == 'production' or IS_VERCEL:
    if len(os.environ.get('FLASK_SECRET_KEY', '').strip()) < 32:
        raise RuntimeError('Production requires FLASK_SECRET_KEY (32+ characters).')
    if not app.config['SESSION_COOKIE_SECURE'] or not app.config.get('TRUSTED_HOSTS') or (
            not DEMO_MODE and not PUBLIC_BASE_URL.startswith('https://')):
        raise RuntimeError('Production requires secure cookies, trusted hosts and an HTTPS public URL for real applications.')
UPLOAD_FOLDER = os.path.join(DATA_DIR, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
DB_PATH = os.path.join(DATA_DIR, 'database.db')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

if not os.environ.get('FLASK_SECRET_KEY', '').strip():
    print("[security] FLASK_SECRET_KEY unset; using an ephemeral key. Set a persistent secret before deployment.")


def csrf_token():
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_urlsafe(32)
    return session['_csrf']


app.jinja_env.globals['csrf_token'] = csrf_token
app.jinja_env.globals['demo_mode'] = DEMO_MODE


@app.before_request
def protect_writes():
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        submitted = request.headers.get('X-CSRF-Token') or request.form.get('_csrf', '')
        if not secrets.compare_digest(submitted, csrf_token()):
            if request.path.startswith('/api/'):
                return jsonify(success=False, error='Session expired. Reload the page and retry.'), 403
            abort(403)


@app.before_request
def disable_demo_scanning():
    if DEMO_MODE and request.path.startswith('/api/ai-lens-scan'):
        return jsonify(success=False, error='AI scanning is disabled in the school-project demo. Enter fictional details manually.'), 503


@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['X-Frame-Options'] = 'DENY'
    if app.config['SESSION_COOKIE_SECURE']:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Cache-Control'] = 'no-store' if not request.path.startswith('/static/') else 'public, max-age=3600'
    if request.path.startswith(('/admin', '/encode', '/login.php', '/login.html', '/uploads/')):
        response.headers['X-Robots-Tag'] = 'noindex, nofollow'
    return response


@app.errorhandler(413)
def payload_too_large(_error):
    if request.path.startswith('/api/'):
        return jsonify(success=False, error='Upload exceeds the 40 MB request limit.'), 413
    return 'Upload exceeds the 40 MB request limit.', 413

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def staff_required(view):
    """Limit the URL-entry admin workflow to fictional demo deployments."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if DEMO_MODE and session.get('staff_auth'):
            return view(*args, **kwargs)
        abort(404)
    return wrapped


def generate_unique_ref(conn, applicant_type):
    year_prefix = datetime.now().year
    type_code = "TR" if (applicant_type or '').strip() == "Transferee" else "FR"
    for _ in range(20):
        ref = f"{type_code}-{year_prefix}-{random.randint(10000, 99999)}"
        exists = conn.execute('SELECT 1 FROM applications WHERE student_number = ?', (ref,)).fetchone()
        if not exists:
            return ref
    return f"{type_code}-{year_prefix}-{secrets.token_hex(3).upper()}"

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_number TEXT,
            school_year TEXT NOT NULL,
            applicant_type TEXT NOT NULL,
            year_level TEXT NOT NULL,
            course TEXT NOT NULL,
            
            -- Basic Student Info
            first_name TEXT NOT NULL,
            middle_name TEXT,
            last_name TEXT NOT NULL,
            suffix TEXT,
            gender TEXT NOT NULL,
            civil_status TEXT NOT NULL,
            email TEXT NOT NULL,
            contact_number TEXT,
            address TEXT NOT NULL,
            zip_code TEXT NOT NULL,
            
            -- Guardian Information
            guardian_name TEXT NOT NULL,
            guardian_relationship TEXT NOT NULL,
            guardian_contact TEXT NOT NULL,
            
            -- Educational Background
            last_school_attended TEXT NOT NULL,
            year_graduated TEXT NOT NULL,
            
            -- Detailed PSA Verified Fields (full Form 102: boxes 1-22)
            psa_birth_date TEXT,
            psa_birth_place TEXT,
            psa_registry_number TEXT,
            psa_mother_name TEXT,
            psa_mother_citizenship TEXT,
            psa_mother_religion TEXT,
            psa_mother_occupation TEXT,
            psa_father_name TEXT,
            psa_father_citizenship TEXT,
            psa_father_religion TEXT,
            psa_father_occupation TEXT,
            psa_parents_marriage_date TEXT,
            psa_parents_marriage_place TEXT,
            psa_type_of_birth TEXT,
            psa_birth_order TEXT,
            psa_weight_grams TEXT,
            psa_attendant TEXT,
            psa_informant_name TEXT,
            psa_informant_relationship TEXT,
            psa_prepared_by TEXT,
            psa_received_date TEXT,

            -- Detailed TOR / Form 137 (SF10) Verified Fields
            tor_lrn TEXT,
            tor_shs_track_strand TEXT,
            tor_general_average TEXT,
            tor_school_id TEXT,
            tor_school_address TEXT,
            tor_school_year TEXT,
            tor_grade_11_sem1_gwa TEXT,
            tor_grade_11_sem2_gwa TEXT,
            tor_grade_12_sem1_gwa TEXT,
            tor_grade_12_sem2_gwa TEXT,
            tor_graduation_date TEXT,
            tor_section TEXT,
            tor_adviser_name TEXT,
            tor_principal_name TEXT,
            tor_jhs_general_average TEXT,
            tor_jhs_school TEXT,
            tor_jhs_school_id TEXT,

            -- College TOR (CHED) Verified Fields (transferees)
            tor_gwa_scale TEXT,
            tor_college_program TEXT,
            tor_college_student_no TEXT,
            tor_college_sem_gwa TEXT,
            tor_college_cumulative_gwa TEXT,
            tor_gwa_computed INTEGER DEFAULT 0,
            tor_gwa_method TEXT,
            tor_total_units_earned TEXT,
            tor_so_number TEXT,
            tor_subjects_found INTEGER DEFAULT 0,
            tor_registrar_name TEXT,
            tor_purpose TEXT,

            -- Extraction audit (no more silent drops)
            extraction_confidence REAL DEFAULT 0,
            extraction_doc_types TEXT DEFAULT '',
            
            status TEXT DEFAULT 'Pending',
            pic_2x2_filename TEXT,
            pic_1x1_filename TEXT,
            psa_birth_cert_filename TEXT,
            marriage_contract_filename TEXT,
            transcript_filename TEXT,
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    # Migration: add any columns missing on older databases (prevents silent data loss)
    want = {
        'source': "TEXT DEFAULT 'online'",
        'source_ref': "TEXT DEFAULT ''",
        'psa_mother_citizenship': 'TEXT', 'psa_mother_religion': 'TEXT', 'psa_mother_occupation': 'TEXT',
        'psa_father_citizenship': 'TEXT', 'psa_father_religion': 'TEXT', 'psa_father_occupation': 'TEXT',
        'psa_parents_marriage_date': 'TEXT', 'psa_parents_marriage_place': 'TEXT',
        'psa_type_of_birth': 'TEXT', 'psa_birth_order': 'TEXT', 'psa_weight_grams': 'TEXT',
        'psa_attendant': 'TEXT', 'psa_informant_name': 'TEXT', 'psa_informant_relationship': 'TEXT',
        'psa_prepared_by': 'TEXT', 'psa_received_date': 'TEXT',
        'tor_school_address': 'TEXT', 'tor_school_year': 'TEXT',
        'tor_grade_11_sem1_gwa': 'TEXT', 'tor_grade_11_sem2_gwa': 'TEXT',
        'tor_grade_12_sem1_gwa': 'TEXT', 'tor_grade_12_sem2_gwa': 'TEXT',
        'tor_graduation_date': 'TEXT', 'tor_section': 'TEXT', 'tor_adviser_name': 'TEXT',
        'tor_principal_name': 'TEXT', 'tor_jhs_general_average': 'TEXT',
        'tor_jhs_school': 'TEXT', 'tor_jhs_school_id': 'TEXT',
        'tor_gwa_scale': 'TEXT', 'tor_college_program': 'TEXT', 'tor_college_student_no': 'TEXT',
        'tor_college_sem_gwa': 'TEXT', 'tor_college_cumulative_gwa': 'TEXT',
        'tor_gwa_computed': 'INTEGER DEFAULT 0', 'tor_gwa_method': 'TEXT',
        'tor_total_units_earned': 'TEXT', 'tor_so_number': 'TEXT',
        'tor_subjects_found': 'INTEGER DEFAULT 0', 'tor_registrar_name': 'TEXT', 'tor_purpose': 'TEXT',
        'extraction_confidence': 'REAL DEFAULT 0', 'extraction_doc_types': "TEXT DEFAULT ''",
    }
    cols = [r[1] for r in c.execute('PRAGMA table_info(applications)').fetchall()]
    for col, ddl in want.items():
        if col not in cols:
            c.execute(f"ALTER TABLE applications ADD COLUMN {col} {ddl}")
    conn.commit()
    conn.close()

SUBMIT_ALLOWED_EXTS = {'.jpg', '.jpeg', '.png', '.webp', '.pdf'}
SUBMIT_MAX_MB = 10

def save_uploaded_file(file_obj, prefix):
    if not file_obj or not getattr(file_obj, 'filename', ''):
        return None
    error = validate_document(file_obj)
    if error:
        raise ValueError(error)
    ext = os.path.splitext(file_obj.filename)[1].lower()
    clean_prefix = re.sub(r'[^A-Za-z0-9_-]+', '_', (prefix or 'doc'))[:40] or 'doc'
    safe_name = f"{clean_prefix}_{int(datetime.now().timestamp())}_{secrets.token_hex(3)}{ext}"
    safe_name = secure_filename(safe_name)
    file_obj.save(os.path.join(app.config['UPLOAD_FOLDER'], safe_name))
    return safe_name


def validate_document(file_obj):
    if not file_obj or not getattr(file_obj, 'filename', ''):
        return None
    ext = os.path.splitext(file_obj.filename)[1].lower()
    if ext not in SUBMIT_ALLOWED_EXTS:
        return 'Unsupported file type. Use PDF, JPG, PNG, or WebP.'
    file_obj.seek(0, os.SEEK_END)
    size = file_obj.tell()
    file_obj.seek(0)
    if size <= 0 or size > SUBMIT_MAX_MB * 1024 * 1024:
        return f'Each file must be between 1 byte and {SUBMIT_MAX_MB} MB.'
    try:
        if ext == '.pdf':
            if file_obj.read(5) != b'%PDF-':
                return 'The PDF file is invalid.'
        else:
            from PIL import Image
            image = Image.open(file_obj)
            image.verify()
            if (ext in ('.jpg', '.jpeg') and image.format != 'JPEG') or \
               (ext == '.png' and image.format != 'PNG') or \
               (ext == '.webp' and image.format != 'WEBP'):
                return 'Image content does not match its extension.'
    except Exception:
        return 'Image file could not be read.'
    finally:
        file_obj.seek(0)
    return None

def send_email_notification(email, subject, body):
    # Email delivery is not configured. Do not put applicant details in server logs.
    app.logger.info('Notification skipped: email delivery is not configured.')


# ═══════════════════════════════════════════════════════════════════════════════
#  Document reader prompts (PSA Certificate of Live Birth + DepEd SF10 + College TOR)
# ═══════════════════════════════════════════════════════════════════════════════

PSA_PROMPT = """
You are a strict document-extraction engine. The image is a Philippine PSA Certificate of Live Birth,
Municipal Form No. 102 (Revised January 1993), quadruplicate civil registry form.

VISUAL LAYOUT ANCHORS — use these to locate fields, do not guess from memory:
- Top-right: "Registry No." (e.g. 2007-1996, or longer BReN). Top header: Province, City/Municipality.
- Box 1: NAME (First) (Middle) (Last) of CHILD.
- Box 2: SEX checkboxes "1 Male / 2 Female". Box 3: DATE OF BIRTH (day)(month)(year).
- Box 4: PLACE OF BIRTH: Name of Hospital/Clinic/Institution + House No, Street, Barangay + City/Municipality + Province.
- Box 5a: TYPE OF BIRTH checkboxes 1 Single / 2 Twin / 3 Triplet etc. Box 5b: IF MULTIPLE, child was First/Second/Other.
- Box 5c: BIRTH ORDER text e.g. "1ST","2ND". Box 5d: WEIGHT AT BIRTH in GRAMS (e.g. 2722 grams — keep grams, do NOT convert to kg).
- Box 6: MOTHER MAIDEN NAME (First)(Middle)(Last). Box 7: CITIZENSHIP. Box 8: RELIGION.
- Box 9a/9b/9c: children born alive counts. Box 10: OCCUPATION. Box 11: Age at time of birth. Box 12: RESIDENCE.
- Box 13: FATHER NAME (First)(Middle)(Last). Box 14: CITIZENSHIP. Box 15: RELIGION. Box 16: OCCUPATION. Box 17: Age.
- Box 18: DATE AND PLACE OF MARRIAGE OF PARENTS — if "NOT APPLICABLE" or blank, return "".
- Box 19a: ATTENDANT checkboxes 1 Physician / 2 Nurse / 3 Midwife / 4 Hilot / 5 Others. Box 19b: certification time.
- Box 20: INFORMANT signature/name/relationship/date. Box 21: PREPARED BY. Box 22: RECEIVED/REGISTERED AT CIVIL REGISTRAR + date.
- Bottom/remarks block: REMARKS/ANNOTATION — legitimation, RA 9255 acknowledgement, RA 10172 corrections.

ANTI-HALLUCINATION RULES (CRITICAL):
1. Extract ONLY text clearly visible in the image. If a field is blank, blurred, cropped, or unreadable, return "".
2. NEVER invent names, dates, registry numbers, weights, or occupations. NEVER reuse example values from these instructions.
3. "gender" must be exactly "Male" or "Female" ONLY if the checkbox is visibly marked; else "".
4. "psa_birth_date" must be YYYY-MM-DD derived ONLY from Box 3. If day/month/year incomplete, return "".
5. "psa_registry_number": copy Registry No. character-for-character as printed. Do not reformat.
6. Names: transcribe exactly, Title Case. Do not expand initials. Do not guess maiden vs married names.
7. If the document is NOT a PSA Certificate of Live Birth / Form 102 (e.g. it is a TOR, ID, selfie), return {"error": "Not a PSA document", "document_type": "Unknown"}.
8. Set "confidence" 0.0-1.0: 1.0 = all key boxes crisp; <0.6 = major blur/crop. Set per-field "" when unsure.

Return ONLY a valid JSON object (no markdown, no commentary) with these keys:
{
  "document_type": "PSA-Form102",
  "confidence": 0.0,
  "first_name": "",
  "middle_name": "",
  "last_name": "",
  "suffix": "",
  "gender": "",
  "psa_birth_date": "YYYY-MM-DD",
  "psa_birth_place": "",
  "psa_registry_number": "",
  "psa_mother_name": "",
  "psa_mother_citizenship": "",
  "psa_mother_religion": "",
  "psa_mother_occupation": "",
  "psa_father_name": "",
  "psa_father_citizenship": "",
  "psa_father_religion": "",
  "psa_father_occupation": "",
  "psa_parents_marriage_date": "",
  "psa_parents_marriage_place": "",
  "psa_type_of_birth": "",
  "psa_birth_order": "",
  "psa_weight_grams": "",
  "psa_attendant": "",
  "psa_informant_name": "",
  "psa_informant_relationship": "",
  "psa_prepared_by": "",
  "psa_received_date": ""
}
"""

SF10_PROMPT = """
You are a strict document-extraction engine for Philippine DepEd School Form 10 — Senior High School
Learner's Permanent Academic Record (SF10-SHS, DepEd Order No. 58 s. 2017, formerly Form 137).
This form is used for NEW FRESHMAN applicants.

REAL SF10-SHS LAYOUT (do not assume fields that are not on this form):
- You may receive 1-2 images = front + back page. COMBINE both pages into one record.
- Header title: "SENIOR HIGH SCHOOL LEARNER'S PERMANENT RECORD". School name, DepEd School ID (exactly 6 digits),
  District / Division / Region.
- LEARNER'S INFORMATION block: LRN (exactly 12 digits, prominent box — copy ONLY if 12 digits visible),
  Name in order Last, First, Middle, Extension/Suffix; Sex; Birthdate (MM/DD/YYYY on the form — convert to YYYY-MM-DD);
  Date of SHS Admission.
- ELIGIBILITY FOR SHS ENROLLMENT block: JHS General Average, JHS school name + school ID, JHS graduation date.
- SCHOLASTIC RECORD tables: Grade 11 Semester 1 & 2 and Grade 12 Semester 1 & 2. Each row = Subject (Core or Elective/
  Specialized), Final Rating per subject (75-100 scale), Action Taken (Passed/Failed). There is NO per-semester GWA
  box on the official 2026 form — semestral averages were REMOVED. Do NOT invent "Grade 11 Sem1 GWA" etc.
- SUMMARY section: "Summary of Final Grades" / "General Average" — copy ONLY if literally printed as overall average.
- TRACK/STRAND header (if printed): Track = Academic / TVL / Sports / Arts and Design; Strand = STEM, ABM, HUMSS,
  GAS, TVL-ICT, TVL-HE, TVL-IA, TVL-AFA. Copy verbatim; do not expand abbreviations from memory.
- CERTIFICATION block: School Head / Principal name + signature + date + dry seal. Class Adviser name if printed.

CHED COLLEGE TOR WARNING: If the image is a university Transcript of Records (subjects with Course Code,
Units/Credits, 1.0-5.0 grades, Semester GWA, S.O. number, Registrar seal) then this is NOT an SF10.
Return {"error": "Not an SF10 — looks like College TOR", "document_type": "College-TOR"} so the caller can
use the college prompt instead.

ANTI-HALLUCINATION RULES (CRITICAL):
1. Extract ONLY visible printed text. Blank/blurred/cropped = "".
2. NEVER invent LRN, School ID, grades, averages, strand, or school names. NEVER reuse examples from instructions.
3. "tor_lrn": exactly 12 digits or "". "tor_school_id": exactly 6 digits or "".
4. "tor_general_average": copy ONLY the printed overall General Average (75.00-100.00). Do NOT average subjects yourself.
   Per-semester averages: if the record prints per-semester/grade-level averages (common on older Form 137 /
   Report Cards: Grade 11 Sem1/Sem2, Grade 12 Sem1/Sem2), copy each into tor_grade_11_* / tor_grade_12_*.
   On the official 2026 SF10-SHS those boxes were removed — leave them "" in that case.
5. "year_graduated": 4-digit year ONLY if printed (graduation/completion date). Else "".
6. Names: transcribe exactly as on Learner's Information box. Do not reorder creatively.
7. Set "confidence" 0.0-1.0. If document is Report Card SF9, Diploma, or ID, return {"error": "...", "document_type": "Other"}.

Return ONLY valid JSON (no markdown):
{
  "document_type": "SF10-SHS",
  "confidence": 0.0,
  "first_name": "",
  "middle_name": "",
  "last_name": "",
  "suffix": "",
  "gender": "",
  "psa_birth_date": "YYYY-MM-DD",
  "tor_lrn": "",
  "tor_shs_track_strand": "",
  "tor_general_average": "",
  "tor_school_id": "",
  "last_school_attended": "",
  "tor_school_address": "",
  "tor_school_year": "",
  "tor_grade_11_sem1_gwa": "",
  "tor_grade_11_sem2_gwa": "",
  "tor_grade_12_sem1_gwa": "",
  "tor_grade_12_sem2_gwa": "",
  "year_graduated": "",
  "tor_graduation_date": "",
  "tor_section": "",
  "tor_adviser_name": "",
  "tor_principal_name": "",
  "tor_jhs_general_average": "",
  "tor_jhs_school": "",
  "tor_jhs_school_id": ""
}
"""

COLLEGE_TOR_PROMPT = """
You are a strict document-extraction engine for Philippine university TRANSCRIPT OF RECORDS (TOR)
governed by CHED Memorandum Orders. This is used for TRANSFEREE applicants — NOT SHS.

REAL CHED TOR LAYOUT (do not assume SHS fields here):
- You may receive 1-3 images = Page 1 (front: student block + first subjects) + Page 2 / back page
  (continuation subjects + summary footer). COMBINE all pages: identity from Page 1, subjects from every page,
  GWA/units/registrar/purpose from the LAST page footer.
- Institutional header: university/college name + address, CHED institutional code, recognition / Special Order (S.O.)
  number for private schools (e.g. "S.O. No. ... s. 2024").
- Student block: full name, Student Number/ID, Program/Degree (e.g. BS Computer Science), Date of Admission,
  Date of Graduation (if graduated), Birthdate.
- TRANSCRIPT TABLE columns: Term/Semester + School Year | Course Code (e.g. ENG 101, CS 201) | Course Title /
  Description (CHED-approved curriculum title) | Final Grade on 1.0-5.0 scale (1.00 best, 3.00 passing, 5.00 failure;
  also INC = Incomplete, DRP/Dropped, W = Withdrawn) | Credits/Units (e.g. 3, 1, 2) | Remarks (PASSED / FAILED / INC).
- Per-term footer: Semester GWA (unit-weighted, 1.0-5.0 scale). Running Cumulative GWA.
- Final footer: Total Units Earned, Cumulative GWA at last term, Degree Conferred + date, Latin Honours
  (Summa / Magna / Cum Laude) ONLY if printed, Registrar name + signature + dry seal, Purpose remark
  (e.g. "Valid for Transfer", "For Board Examination", "Granted Honorable Dismissal").
- Grading legend box is often printed (1=97-100%, 1.25=94-96%, ... 3.0=75-77%, 5.0=below 75).

ANTI-HALLUCINATION RULES (CRITICAL):
1. Extract ONLY visible text. Blank/blurred/cropped = "". NEVER invent course codes, grades, units, GWAs, S.O. numbers.
2. NEVER convert 1.0-5.0 grades to 75-100 scale. Keep original scale. Put semester GWA into tor_college_sem_gwa,
   cumulative GWA into tor_college_cumulative_gwa.
3. For the shared "tor_general_average" key, copy the Cumulative GWA exactly as printed (e.g. "1.75") and set
   "tor_gwa_scale" to "1.0-5.0-college". Do NOT fabricate an SHS-style 91.50 average.
4. FOOTER SCAN FIRST: the summary block is usually at the very bottom of the last page / back page in small print:
   look for labels "Average", "General Average", "GWA", "Weighted Average", "Total Units", "Units Earned",
   "Total No. of Units". Copy those numbers verbatim into tor_college_sem_gwa / tor_college_cumulative_gwa /
   tor_total_units_earned. Student No. is usually near the name block ("Student No.", "ID No.", "Stud. No.").
5. COMPUTED FALLBACK (allowed, must be flagged): if NO printed average/units exist BUT you can read at least 4
   subject rows with BOTH a numeric 1.0-5.0 grade AND credit units, compute unit-weighted GWA =
   SUM(grade*units)/SUM(units), rounded to 2 decimals. Exclude rows graded INC/DRP/Dropped/W/Failed-unresolved.
   Put the result in tor_college_cumulative_gwa, set tor_gwa_computed=true and tor_gwa_method to e.g.
   "Computed from 22 readable subject rows (no printed average found)". Sum passed units into
   tor_total_units_earned the same way. If fewer than 4 computable rows, leave blank and set tor_gwa_computed=false.
6. PROGRAM NAME: copy the FULL degree as printed including major in parentheses (e.g. "Bachelor of Science in
   Business Administration Major in ..."). Never truncate. If it wraps to 2 lines, join with a space.
7. If the image is actually DepEd SF10/Form 137 (LRN, SHS strand, 75-100 grades), return
   {"error": "Not a College TOR — looks like SF10", "document_type": "SF10-SHS"}.
8. Count subject rows you actually see; set "tor_subjects_found" to that count. If 0 readable rows, confidence <= 0.3.
   Lower confidence by 0.15 when tor_gwa_computed=true (computed, not printed).

Return ONLY valid JSON (no markdown):
{
  "document_type": "College-TOR",
  "confidence": 0.0,
  "first_name": "",
  "middle_name": "",
  "last_name": "",
  "suffix": "",
  "gender": "",
  "psa_birth_date": "YYYY-MM-DD",
  "tor_lrn": "",
  "tor_shs_track_strand": "",
  "tor_general_average": "",
  "tor_gwa_scale": "",
  "tor_school_id": "",
  "last_school_attended": "",
  "tor_school_address": "",
  "tor_school_year": "",
  "year_graduated": "",
  "tor_graduation_date": "",
  "tor_college_program": "",
  "tor_college_student_no": "",
  "tor_college_sem_gwa": "",
  "tor_college_cumulative_gwa": "",
  "tor_gwa_computed": false,
  "tor_gwa_method": "",
  "tor_total_units_earned": "",
  "tor_so_number": "",
  "tor_subjects_found": 0,
  "tor_registrar_name": "",
  "tor_purpose": ""
}
"""

def read_file_as_pil(file_obj):
    """Read an uploaded file as a PIL Image or raw bytes for Gemini."""
    from PIL import Image
    file_obj.seek(0)
    raw = file_obj.read()
    file_obj.seek(0)

    ext = os.path.splitext(file_obj.filename)[1].lower()
    if ext in ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tiff']:
        img = Image.open(io.BytesIO(raw)).convert('RGB')
        return img, 'image/jpeg', raw
    elif ext == '.pdf':
        # Return raw bytes for PDF — we pass as base64 inline part
        return None, 'application/pdf', raw
    else:
        img = Image.open(io.BytesIO(raw)).convert('RGB')
        return img, 'image/jpeg', raw


ALLOWED_EXTS = {'.jpg', '.jpeg', '.png', '.webp', '.bmp', '.tiff', '.pdf'}
MAX_SCAN_MB = 10


def validate_scan_file(file_obj, label):
    """Reject missing / wrong-type / oversized / unreadable uploads before calling Gemini."""
    if not file_obj or not getattr(file_obj, 'filename', ''):
        return f"No {label} file attached."
    ext = os.path.splitext(file_obj.filename)[1].lower()
    if ext not in ALLOWED_EXTS:
        return f"{label}: unsupported file type '{ext}'. Use PDF, JPG, or PNG."
    file_obj.seek(0, os.SEEK_END)
    size = file_obj.tell()
    file_obj.seek(0)
    if size <= 0:
        return f"{label}: file is empty."
    if size > MAX_SCAN_MB * 1024 * 1024:
        return f"{label}: file exceeds {MAX_SCAN_MB}MB. Please upload a smaller scan."
    if ext == '.pdf':
        valid_pdf = file_obj.read(5) == b'%PDF-'
        file_obj.seek(0)
        if not valid_pdf:
            return f'{label}: PDF file is invalid.'
    if ext != '.pdf':
        try:
            from PIL import Image
            raw = file_obj.read()
            file_obj.seek(0)
            Image.open(io.BytesIO(raw)).verify()
            file_obj.seek(0)
        except Exception:
            return f"{label}: image could not be read. Re-scan as clear JPG/PNG."
    return None


def sanitize_ai_dict(parsed, allowed_keys):
    """Drop unexpected keys, coerce to string, enforce empty-string defaults (anti-hallucination hygiene)."""
    clean = {}
    for k in allowed_keys:
        if k == 'tor_gwa_computed':
            v = parsed.get(k, False)
            clean[k] = bool(v is True or (isinstance(v, str) and v.strip().lower() in ('true', '1', 'yes')))
            continue
        v = parsed.get(k, '')
        if v is None:
            v = ''
        if isinstance(v, (int, float)):
            v = str(v)
        clean[k] = str(v).strip() if isinstance(v, str) else ''
    # LRN / School ID format guard: never trust a malformed model guess
    if 'tor_lrn' in clean and clean['tor_lrn'] and not re.fullmatch(r'\d{12}', re.sub(r'\s+', '', clean['tor_lrn'])):
        clean['tor_lrn'] = ''
    if 'tor_school_id' in clean and clean['tor_school_id'] and not re.fullmatch(r'\d{6}', re.sub(r'\s+', '', clean['tor_school_id'])):
        clean['tor_school_id'] = ''
    if 'tor_jhs_school_id' in clean and clean['tor_jhs_school_id'] and not re.fullmatch(r'\d{6}', re.sub(r'\s+', '', clean['tor_jhs_school_id'])):
        clean['tor_jhs_school_id'] = ''
    try:
        clean['confidence'] = float(parsed.get('confidence', 0) or 0)
    except Exception:
        clean['confidence'] = 0.0
    clean['confidence'] = max(0.0, min(1.0, clean['confidence']))
    clean['document_type'] = str(parsed.get('document_type', '') or '')
    return clean


def extraction_report(data, keys, optional=()):
    """Completeness summary so the UI can show exactly what the AI could not read.
    `optional` = keys that are legitimately absent from many real forms
    (e.g. per-semester GWAs were removed from the official 2026 SF10-SHS)
    — still returned as "" but never counted as 'unreadable'."""
    opt = set(optional or ())
    missing = [k for k in keys if k not in ('suffix',) and k not in opt
               and not (data.get(k) or '').__str__().strip()
               and k not in ('tor_gwa_computed', 'confidence', 'document_type')]
    try:
        conf = float(data.get('confidence', 0) or 0)
    except Exception:
        conf = 0.0
    return {"missing_fields": missing, "missing_count": len(missing),
            "confidence": conf, "document_type": data.get('document_type', '')}


PSA_KEYS = ['first_name', 'middle_name', 'last_name', 'suffix', 'gender', 'psa_birth_date',
    'psa_birth_place', 'psa_registry_number', 'psa_mother_name', 'psa_mother_citizenship',
    'psa_mother_religion', 'psa_mother_occupation', 'psa_father_name', 'psa_father_citizenship',
    'psa_father_religion', 'psa_father_occupation', 'psa_parents_marriage_date',
    'psa_parents_marriage_place', 'psa_type_of_birth', 'psa_birth_order', 'psa_weight_grams',
    'psa_attendant', 'psa_informant_name', 'psa_informant_relationship', 'psa_prepared_by', 'psa_received_date']

SF10_KEYS = ['first_name', 'middle_name', 'last_name', 'suffix', 'gender', 'psa_birth_date',
    'tor_lrn', 'tor_shs_track_strand', 'tor_general_average', 'tor_school_id', 'last_school_attended',
    'tor_school_address', 'tor_school_year', 'tor_grade_11_sem1_gwa', 'tor_grade_11_sem2_gwa',
    'tor_grade_12_sem1_gwa', 'tor_grade_12_sem2_gwa', 'year_graduated', 'tor_graduation_date',
    'tor_section', 'tor_adviser_name', 'tor_principal_name', 'tor_jhs_general_average',
    'tor_jhs_school', 'tor_jhs_school_id']

COLLEGE_KEYS = SF10_KEYS + ['tor_gwa_scale', 'tor_college_program', 'tor_college_student_no',
    'tor_college_sem_gwa', 'tor_college_cumulative_gwa', 'tor_gwa_computed', 'tor_gwa_method',
    'tor_total_units_earned', 'tor_so_number', 'tor_subjects_found', 'tor_registrar_name', 'tor_purpose']

# Fields that are legitimately NOT printed on many real school records.
# The official 2026 SF10-SHS removed per-semester GWA boxes, and older Form 137 /
# Report Cards often lack JHS blocks, section, adviser, or graduation date.
# These stay "" when absent but must NOT inflate the "unreadable" count.
SF10_OPTIONAL_KEYS = ('tor_grade_11_sem1_gwa', 'tor_grade_11_sem2_gwa',
    'tor_grade_12_sem1_gwa', 'tor_grade_12_sem2_gwa',
    'tor_section', 'tor_adviser_name', 'tor_principal_name',
    'tor_graduation_date', 'tor_jhs_general_average',
    'tor_jhs_school', 'tor_jhs_school_id')


GEMINI_MODELS = [m.strip() for m in os.environ.get(
    'GEMINI_MODEL', 'gemini-flash-latest').split(',') if m.strip()] or ['gemini-flash-latest']
SCAN_MAX_DIM = int(os.environ.get('SCAN_MAX_DIM', '1568'))
SCAN_JPEG_QUALITY = int(os.environ.get('SCAN_JPEG_QUALITY', '82'))
SCAN_RETRIES = int(os.environ.get('SCAN_RETRIES', '2'))


def _is_quota_error(exc):
    s = f"{type(exc).__name__}: {exc}".lower()
    return ('429' in s or 'quota' in s or 'rate' in s or 'resourceexhausted' in s
            or 'retry' in s and 'seconds' in s)


def _is_dead_model(exc):
    s = f"{type(exc).__name__}: {exc}".lower()
    return ('404' in s or 'not found' in s or 'no longer available' in s
            or 'unsupported model' in s or 'does not exist' in s)


def _gemini_generate(payload):
    """Call Gemini trying each configured model in order.

    Rotates past retired models (404) immediately, backs off briefly on quota
    (429) per model, and fails fast on anything else. Returns (text, model).
    """
    import time
    last_err = Exception("No AI model configured (GEMINI_MODEL is empty).")
    for model_name in GEMINI_MODELS:
        for attempt in range(SCAN_RETRIES + 1):
            try:
                response = gemini_client.models.generate_content(
                    model=model_name, contents=payload if isinstance(payload, str) else list(payload))
                return (getattr(response, 'text', '') or '').strip(), model_name
            except Exception as e:
                last_err = e
                if _is_dead_model(e):
                    print(f"[scanner] model retired: {model_name} — trying next.")
                    break
                if _is_quota_error(e) and attempt < SCAN_RETRIES:
                    # Short server-side backoff only; long cooldown goes to the browser.
                    time.sleep(3 * (attempt + 1))
                    continue
                break
        if last_err is not None and not _is_dead_model(last_err) and not _is_quota_error(last_err):
            break
    raise last_err


def _friendly_gemini_error(e):
    if e is not None and _is_quota_error(e):
        wait = _retry_after_seconds(e)
        return {"error": (f"Google AI quota is full right now (free-tier 429). "
                          f"Wait ~{wait}s, then press Scan again — your files are still attached, "
                          f"nothing to re-upload. Tip: scan PSA first, wait, then TOR; avoid double-clicking Scan."),
                "retryable": True, "retry_after": wait}
    if e is not None and _is_dead_model(e):
        tried = ', '.join(GEMINI_MODELS)
        return {"error": (f"Google retired all configured AI models ({tried}). "
                          f"Set GEMINI_MODEL in .env to a current model name.")}
    return {"error": f"Scanner error: {str(e)[:200]}" if e else "Scanner error."}


def _retry_after_seconds(exc, default=20):
    m = re.search(r'retry in (\d+(?:\.\d+)?)\s*s', str(exc), re.IGNORECASE)
    if m:
        try:
            return max(5, min(120, int(float(m.group(1)))))
        except Exception:
            pass
    m = re.search(r'retry-after[:\s]+(\d+)', str(exc), re.IGNORECASE)
    if m:
        try:
            return max(5, min(120, int(m.group(1))))
        except Exception:
            pass
    return default


def _downscale_for_gemini(img):
    """Shrink camera-size scans so each request burns far fewer quota tokens."""
    try:
        w, h = img.size
        m = max(w, h)
        if m > SCAN_MAX_DIM:
            scale = SCAN_MAX_DIM / float(m)
            img = img.resize((max(1, int(w * scale)), max(1, int(h * scale))))
        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=SCAN_JPEG_QUALITY, optimize=True)
        buf.seek(0)
        from PIL import Image as _I
        return _I.open(buf), buf.getvalue()
    except Exception:
        return img, None


def gemini_vision_extract(files, prompt):
    """Send one or more images/PDF pages to Gemini and return parsed JSON dict. No guessing — model must return "" when unsure."""
    if not GEMINI_AVAILABLE:
        return {"error": "Document reading is offline: missing server key. No data was auto-generated."}
    if not isinstance(files, (list, tuple)):
        files = [files]
    files = [f for f in files if f and getattr(f, 'filename', '')]
    if not files:
        return {"error": "No file attached."}
    # Build payload once (downscaled images = fewer tokens = less quota burn)
    parts_template = [prompt]
    try:
        for f in files:
            f.seek(0)
            img, mime_type, raw_bytes = read_file_as_pil(f)
            if mime_type == 'application/pdf':
                parts_template.append(genai_types.Part.from_bytes(data=raw_bytes, mime_type='application/pdf'))
            else:
                _, small_bytes = _downscale_for_gemini(img)
                parts_template.append(genai_types.Part.from_bytes(
                    data=small_bytes or raw_bytes, mime_type='image/jpeg'))
    except Exception as e:
        return {"error": f"Could not prepare the scan: {str(e)[:150]}"}
    try:
        text, _used = _gemini_generate(parts_template)
    except Exception as e:
        return _friendly_gemini_error(e)
    try:
        # Strip markdown code blocks if present
        text = re.sub(r'^```(?:json)?\s*', '', text)
        text = re.sub(r'\s*```$', '', text)
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {"error": "Could not read the scan. Re-scan a clearer copy.", "raw": text[:300]}
    if not isinstance(parsed, dict):
        return {"error": "Unexpected scanner response. Please re-scan a clearer copy."}
    return parsed


OCR_TEXT_HEADER = """
You are given plain OCR text scraped from a scanned Philippine document (no image, so layout may be jumbled and some characters misread).
STRICT RULES:
1. Use ONLY information present in the OCR text below. Absent/unclear/garbled = "".
2. NEVER invent names, dates, numbers, or grades. NEVER reuse example values from these instructions.
3. Return ONLY a valid JSON object (no markdown, no commentary) with EXACTLY these keys:
{keys_json}
4. "confidence": 0.0-1.0 based on how complete and clean the OCR text looks.
5. "document_type": one of "PSA-Form102", "SF10-SHS", "College-TOR", "Unknown".
If the text is clearly NOT the expected document kind, return {"error": "<short reason>", "document_type": "Unknown"}.
"""

KIND_HINTS = {
    'psa': 'Expected: PSA Certificate of Live Birth (Registry No. like 2007-19996; child name; date of birth; birth place; mother maiden name; father name). "gender" is "Male"/"Female" only if stated, else "". "psa_birth_date" as YYYY-MM-DD or "".',
    'sf10': 'Expected: DepEd SF10-SHS (12-digit LRN; 6-digit School ID; SHS track/strand like STEM/ABM/HUMSS/GAS/TVL; General Average on 75-100 scale; school name; graduation year). "tor_lrn" must be exactly 12 digits or "". "tor_school_id" exactly 6 digits or "".',
    'college': 'Expected: CHED college Transcript of Records (program/degree; student number; subject grades on the 1.0-5.0 scale; semester/cumulative GWA; total units; S.O. number; registrar). Keep 1.0-5.0 grades as-is, NEVER convert. Put the cumulative GWA in both "tor_general_average" and "tor_college_cumulative_gwa".',
}

KIND_KEYS = {'psa': PSA_KEYS, 'sf10': SF10_KEYS, 'college': COLLEGE_KEYS}

OCRSPACE_FREE_BYTE_LIMIT = 1 * 1024 * 1024


def ocrspace_extract_text(files):
    """Free OCR pass (OCR.space, no credit card): image/PDF -> raw text. Dict with 'text' or error."""
    if not REQUESTS_AVAILABLE:
        return {"error": "OCR engine unavailable (requests library missing)."}
    if not isinstance(files, (list, tuple)):
        files = [files]
    files = [f for f in files if f and getattr(f, 'filename', '')]
    if not files:
        return {"error": "No file attached."}
    pages = []
    for f in files:
        try:
            f.seek(0)
            img, mime_type, raw_bytes = read_file_as_pil(f)
            if mime_type == 'application/pdf':
                payload, fname, ftype = raw_bytes, 'doc.pdf', 'application/pdf'
            else:
                _, small_bytes = _downscale_for_gemini(img)
                payload = small_bytes if small_bytes else raw_bytes
                fname, ftype = 'scan.jpg', 'image/jpeg'
            if len(payload) > OCRSPACE_FREE_BYTE_LIMIT:
                return {"error": "OCRSPACE_TOO_BIG"}
            r = _requests.post(OCRSPACE_URL,
                               data={'apikey': OCRSPACE_API_KEY, 'OCREngine': 2,
                                     'scale': 'true', 'isTable': 'true'},
                               files={'file': (fname, payload, ftype)},
                               timeout=75)
            body = r.json()
        except Exception as e:
            return {"error": f"OCR service unreachable: {str(e)[:120]}"}
        msg = str(body.get('ErrorMessage', '') or '')
        if 'request limit' in msg.lower() or 'too many requests' in msg.lower():
            return {"error": "OCR.space free quota hit for today — falling back to direct AI read.",
                    "retryable": True, "retry_after": 30}
        results = body.get('ParsedResults') or []
        text = '\n'.join([(x.get('ParsedText') or '') for x in results]).strip()
        if text:
            pages.append(text)
    combined = '\n\n--- NEXT PAGE ---\n\n'.join(pages).strip()
    if len(combined) < 20:
        return {"error": "OCRSPACE_EMPTY"}
    return {"text": combined, "pages": len(pages)}


def gemini_text_extract(ocr_text, kind):
    """Cheap structuring pass: OCR text (2-4k tokens) -> strict JSON. Same models/retries as vision."""
    import time
    keys = KIND_KEYS[kind]
    keys_json = json.dumps({k: "" for k in keys + ['confidence', 'document_type']}, indent=1)
    prompt = (OCR_TEXT_HEADER.replace('{keys_json}', keys_json) + "\n" + KIND_HINTS[kind]
              + "\n\n--- OCR TEXT (may contain misreads; never guess beyond it) ---\n"
              + ocr_text[:12000])
    try:
        text, _used = _gemini_generate(prompt)
    except Exception as e:
        return _friendly_gemini_error(e)
    try:
        text = re.sub(r'^```(?:json)?\s*', '', text)
        text = re.sub(r'\s*```$', '', text)
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {"error": "Could not structure the OCR text. Re-scan a clearer copy."}
    if not isinstance(parsed, dict):
        return {"error": "Unexpected structuring response. Please re-scan a clearer copy."}
    return parsed


def extract_document(files, kind):
    """Provider dispatcher. Returns a raw parsed dict (or error dict), same contract as gemini_vision_extract."""
    if OCR_PROVIDER == 'off':
        return {"error": "Document reading is disabled. Enter the details manually."}
    if not GEMINI_AVAILABLE:
        return {"error": "Document reading is offline: missing server key. No data was auto-generated."}
    vision_prompts = {'psa': PSA_PROMPT, 'sf10': SF10_PROMPT, 'college': COLLEGE_TOR_PROMPT}
    if OCR_PROVIDER != 'hybrid':
        return gemini_vision_extract(files, vision_prompts[kind])
    ocr = ocrspace_extract_text(files)
    if 'text' in ocr:
        structured = gemini_text_extract(ocr['text'], kind)
        if 'error' not in structured:
            structured.setdefault('ocr_pages', ocr.get('pages', 1))
            structured.setdefault('ocr_engine', 'ocrspace+gemini-text')
            return structured
        if structured.get('retryable'):
            # Gemini-text quota hit: do NOT burn even more with a vision fallback.
            return structured
    # OCR.space failed/empty (or non-quota structuring failure): fall back to direct vision.
    if ocr.get('error') not in (None, '', 'OCRSPACE_EMPTY', 'OCRSPACE_TOO_BIG'):
        print(f"[scanner] hybrid OCR pass issue ({ocr.get('error', '')[:80]}), trying direct vision.")
    return gemini_vision_extract(files, vision_prompts[kind])


def _DEPRECATED_smart_simulation_DISABLED(psa_name='', tor_name=''):
    """DISABLED anti-hallucination: never auto-generate fake PSA/TOR data. Kept only to avoid import errors."""
    return {"error": "Simulation disabled. Set GEMINI_API_KEY for real OCR.", "document_type": "Disabled"}


def _UNUSED_old_simulation_body_quarantined(psa_name_unused=None, tor_name_unused=None):
    """Old hallucinated generator quarantined below (never called).
    """
    # ── Common Philippine first names and surnames ──────────────────────────
    male_first = ['Juan', 'Jose', 'Carlo', 'Miguel', 'Angelo', 'Rafael', 'Andrei', 'Christian', 'Mark', 'Paulo']
    female_first = ['Maria', 'Ana', 'Karla', 'Patricia', 'Isabel', 'Katrina', 'Andrea', 'Bianca', 'Sophia', 'Camille']
    middle_names = ['Santos', 'Garcia', 'Reyes', 'Cruz', 'Torres', 'Ramos', 'Flores', 'Bautista', 'Mendoza', 'Aquino']
    surnames = ['Dela Cruz', 'Reyes', 'Santos', 'Garcia', 'Torres', 'Flores', 'Lopez', 'Bautista', 'Mendoza', 'Castro']
    ph_cities = ['Quezon City, Metro Manila', 'Manila, Metro Manila', 'Cebu City, Cebu',
                 'Davao City, Davao del Sur', 'Caloocan City, Metro Manila', 'Makati City, Metro Manila',
                 'Pasig City, Metro Manila', 'Marikina City, Metro Manila', 'Antipolo City, Rizal',
                 'Las Pinas City, Metro Manila']

    # Parse filename for name hints
    all_names = f"{psa_name} {tor_name}".replace('-', ' ').replace('_', ' ').replace('.', ' ')
    stop_words = {'psa', 'birth', 'cert', 'certificate', 'tor', 'form', 'transcript',
                  'sf10', 'doc', 'pdf', 'jpg', 'jpeg', 'png', 'scan', 'img', 'file', '137', '138'}
    tokens = [t.strip().capitalize() for t in all_names.split() if len(t) > 2 and t.lower() not in stop_words]

    # Determine gender from first name cues
    female_cues = {'maria', 'mary', 'ana', 'anne', 'clara', 'sarah', 'jane', 'patricia',
                   'catherine', 'rose', 'karla', 'bianca', 'sophia', 'camille', 'andrea',
                   'katrina', 'isabel', 'kat', 'bea', 'bella'}
    gender = 'Female' if tokens and tokens[0].lower() in female_cues else 'Male'

    if tokens and len(tokens) >= 2:
        first_name = tokens[0]
        last_name = tokens[-1]
        middle_name = tokens[1] if len(tokens) >= 3 else random.choice(middle_names)
    else:
        name_pool = female_first if gender == 'Female' else male_first
        first_name = random.choice(name_pool)
        middle_name = random.choice(middle_names)
        last_name = random.choice(surnames)

    # ── PSA Birth Certificate Fields ────────────────────────────────────────
    birth_year = random.randint(2004, 2008)
    birth_month = random.randint(1, 12)
    birth_day = random.randint(1, 28)
    birth_date = f"{birth_year}-{birth_month:02d}-{birth_day:02d}"

    # Registry Number: YYYY-NNNNN (year of registration + 5-digit serial)
    reg_year = birth_year if random.random() > 0.1 else birth_year + 1  # occasional delayed registration
    registry_number = f"{reg_year}-{random.randint(10000, 99999)}"

    birth_place = random.choice(ph_cities)
    city_part = birth_place.split(',')[0]

    # Mother's maiden name
    mother_middle = random.choice(middle_names)
    mother_maiden = f"Maria {mother_middle} Gonzales"
    if gender == 'Female':
        mother_maiden = f"Rosa {random.choice(middle_names)} {random.choice(surnames).split()[-1]}"

    # Father's name
    father_middle = random.choice(middle_names)
    father_name = f"Roberto {father_middle} {last_name.split()[-1]}"

    # Parents' marriage
    marriage_year = birth_year - random.randint(1, 5)
    marriage_month = random.randint(1, 12)
    marriage_day = random.randint(1, 28)
    marriage_date = f"{marriage_month:02d}/{marriage_day:02d}/{marriage_year}"
    marriage_place = random.choice(ph_cities)

    # ── DepEd SF10 / Form 137 Fields ────────────────────────────────────────
    # 12-digit LRN: first 3 digits = region/division code
    region_codes = ['100', '200', '300', '400', '500', '600', '700', '800', '900', '100', '110', '120']
    lrn = random.choice(region_codes) + str(random.randint(100000000, 999999999))

    # School ID: 6-digit DepEd school code
    school_id = str(random.randint(100000, 999999))

    # SHS Tracks and Strands (actual DepEd programs)
    tracks_strands = [
        'STEM - Science, Technology, Engineering, and Mathematics',
        'ABM - Accountancy, Business, and Management',
        'HUMSS - Humanities and Social Sciences',
        'GAS - General Academic Strand',
        'TVL - ICT (Information and Communications Technology)',
        'TVL - HE (Home Economics)',
        'TVL - IA (Industrial Arts)',
        'TVL - AFA (Agri-Fishery Arts)',
        'SPORTS Track',
        'ARTS AND DESIGN Track',
    ]
    strand = random.choice(tracks_strands)

    # Schools list
    shs_schools = [
        'Quezon City Science High School', 'Pasig City Science High School',
        'Manila Science High School', 'Makati Science High School',
        'Caloocan City Science High School', 'Marikina Science High School',
        'San Juan National High School', 'Valenzuela City School of Mathematics and Science',
        'Bulacan National High School', 'Laguna National Polytechnic University SHS',
        'Rizal High School', 'Ateneo de Manila Senior High School (Loyola Heights)',
        'De La Salle Zobel Senior High School', 'Philippine Science High School NCR Campus',
        'Polytechnic University of the Philippines Integrated Laboratory School',
        'University of the Philippines Integrated School',
        'Colegio de San Juan de Letran Integrated School',
        'Far Eastern University Senior High School',
        'Mapua Malayan Colleges Integrated School SHS',
        'Saint Pedro Calungsod Senior High School',
    ]

    # GWA: Philippine SHS uses 60-100 scale, most college-bound students are 85-98
    gwa_int = random.randint(85, 97)
    gwa_dec = random.randint(0, 99)
    gwa = f"{gwa_int}.{gwa_dec:02d}"

    grad_year = birth_year + 18  # typical graduation age
    if grad_year > 2026:
        grad_year = 2025
    grad_month = random.choice([3, 4])  # March or April graduation
    grad_day = random.randint(25, 31) if grad_month == 3 else random.randint(1, 15)

    school_name = random.choice(shs_schools)

    # Per-semester GWAs (Grade 11 & 12)
    def rand_gwa():
        return f"{random.randint(84, 97)}.{random.randint(0, 99):02d}"

    return {
        # Core student profile
        'first_name': first_name,
        'middle_name': middle_name,
        'last_name': last_name,
        'suffix': '',
        'gender': gender,
        'civil_status': 'Single',

        # PSA Birth Certificate
        'psa_birth_date': birth_date,
        'psa_birth_place': birth_place,
        'psa_registry_number': registry_number,
        'psa_mother_name': mother_maiden,
        'psa_mother_citizenship': 'Filipino',
        'psa_mother_religion': random.choice(['Roman Catholic', 'Protestant', 'Born Again Christian', 'Islam', 'Iglesia ni Cristo']),
        'psa_mother_occupation': random.choice(['Housewife', 'Teacher', 'Nurse', 'Government Employee', 'Business Owner', 'Domestic Helper']),
        'psa_father_name': father_name,
        'psa_father_citizenship': 'Filipino',
        'psa_father_religion': random.choice(['Roman Catholic', 'Protestant', 'Born Again Christian', 'Islam']),
        'psa_father_occupation': random.choice(['Farmer', 'Driver', 'Engineer', 'Government Employee', 'OFW', 'Businessman', 'Carpenter']),
        'psa_parents_marriage_date': marriage_date,
        'psa_parents_marriage_place': marriage_place,
        'psa_type_of_birth': 'Single',
        'psa_birth_order': str(random.randint(1, 4)),
        'psa_birth_weight_kg': f"{random.uniform(2.5, 4.2):.1f}",
        'psa_attendant': random.choice(['Physician', 'Nurse', 'Midwife']),
        'psa_informant_name': mother_maiden,
        'psa_prepared_by': f"Rosario {random.choice(surnames)}",
        'psa_lcro_received_date': f"{(birth_day + 7) % 28 + 1:02d}/{birth_month:02d}/{birth_year}",

        # DepEd SF10 / Form 137
        'tor_lrn': lrn,
        'tor_shs_track_strand': strand,
        'tor_general_average': gwa,
        'tor_school_id': school_id,
        'tor_school_address': f"Barangay {random.randint(1,100)}, {city_part}",
        'tor_school_year': f"{grad_year - 1}-{grad_year}",
        'tor_grade_11_sem1_gwa': rand_gwa(),
        'tor_grade_11_sem2_gwa': rand_gwa(),
        'tor_grade_12_sem1_gwa': rand_gwa(),
        'tor_grade_12_sem2_gwa': gwa,
        'year_graduated': str(grad_year),
        'tor_graduation_date': f"{grad_month:02d}/{grad_day:02d}/{grad_year}",
        'tor_section': f"{strand.split('-')[0].strip()}-{random.choice(['Rizal', 'Bonifacio', 'Luna', 'Mabini', 'Silang', 'Aguinaldo'])}",
        'tor_adviser_name': f"Ma. {random.choice(['Grace', 'Joy', 'Faith', 'Hope'])} {random.choice(surnames)}",
        'tor_principal_name': f"{random.choice(['Eduardo', 'Roberto', 'Marlene', 'Cynthia'])} {random.choice(surnames)}",
        'tor_jhs_general_average': f"{random.randint(86, 95)}.{random.randint(0, 99):02d}",
        'tor_jhs_school': f"{city_part} National High School",
        'tor_jhs_school_id': str(random.randint(100000, 999999)),
        'last_school_attended': school_name,
        'guardian_name': mother_maiden,
        'guardian_relationship': 'Mother',
        'guardian_contact': f"09{random.randint(10, 99)}{random.randint(1000000, 9999999)}",
    }


@app.route('/api/ai-lens-scan-psa', methods=['POST'])
def ai_lens_scan_psa():
    """Step 1 — PSA only. Strict Form 102 extraction. Never invents data."""
    psa_file = request.files.get('psa_file')
    err = validate_scan_file(psa_file, 'PSA Birth Certificate')
    if err:
        return jsonify({"success": False, "error": err}), 400
    if not GEMINI_AVAILABLE:
        return jsonify({"success": False,
            "error": "Document reading is offline. Attach a clear scan and type the PSA details manually — nothing was auto-generated."}), 503
    psa_file.seek(0)
    raw = extract_document(psa_file, 'psa')
    if 'error' in raw:
        code = 429 if raw.get('retryable') else 422
        out = {"success": False, "error": raw.get('error', 'PSA scan failed. Try a clearer copy.')}
        if raw.get('retryable'):
            out.update({"retryable": True, "retry_after": raw.get('retry_after', 20)})
        return jsonify(out), code
    data = sanitize_ai_dict(raw, PSA_KEYS)
    data['civil_status'] = 'Single'
    data['guardian_name'] = data.get('psa_mother_name', '')
    data['guardian_relationship'] = 'Mother' if data.get('psa_mother_name') else ''
    data['sources'] = [f"PSA Form 102 ({psa_file.filename})"]
    data['extraction_mode'] = 'strict'
    data.update(extraction_report(data, PSA_KEYS))
    if raw.get('ocr_engine'):
        data['ocr_engine'] = raw['ocr_engine']
    return jsonify({"success": True, "message": "Step 1/2: PSA extracted. Confirm to continue to TOR.", "data": data})


@app.route('/api/ai-lens-scan-tor', methods=['POST'])
def ai_lens_scan_tor():
    """Step 2 — TOR only. Picks SF10-SHS (Freshman) vs College TOR (Transferee). Accepts 1-3 pages. Never invents data."""
    tor_files = request.files.getlist('tor_file')
    if not tor_files or not any(getattr(f, 'filename', '') for f in tor_files):
        single = request.files.get('tor_file')
        tor_files = [single] if single else []
    # Backward compat: separate second-page field
    extra = request.files.get('tor_file2')
    if extra and getattr(extra, 'filename', ''):
        tor_files.append(extra)
    tor_files = [f for f in tor_files if f and getattr(f, 'filename', '')][:3]
    applicant_type = (request.form.get('applicant_type') or request.args.get('applicant_type') or 'New Freshman').strip()
    is_transferee = applicant_type.lower().startswith('trans')
    if not tor_files:
        return jsonify({"success": False, "error": "No TOR / SF10 file attached."}), 400
    for f in tor_files:
        err = validate_scan_file(f, 'TOR / SF10')
        if err:
            return jsonify({"success": False, "error": err}), 400
    if not GEMINI_AVAILABLE:
        return jsonify({"success": False,
            "error": "Document reading is offline. Attach a clear scan and type the school details manually — nothing was auto-generated."}), 503
    for f in tor_files:
        f.seek(0)
    raw = extract_document(tor_files, 'college' if is_transferee else 'sf10')
    if 'error' in raw:
        code = 429 if raw.get('retryable') else 422
        out = {"success": False, "error": raw.get('error', 'TOR scan failed. Try a clearer copy.')}
        if raw.get('retryable'):
            out.update({"retryable": True, "retry_after": raw.get('retry_after', 20)})
        return jsonify(out), code
    allowed = COLLEGE_KEYS if is_transferee else SF10_KEYS
    data = sanitize_ai_dict(raw, allowed)
    # Cross-type guard: warn but still return what was found
    doc = (data.get('document_type') or '')
    if is_transferee and doc == 'SF10-SHS':
        data['type_warning'] = 'Document looks like DepEd SF10 (SHS), but applicant is Transferee. Verify you uploaded a College TOR.'
    if (not is_transferee) and doc == 'College-TOR':
        data['type_warning'] = 'Document looks like a College TOR, but applicant is New Freshman. Verify you uploaded DepEd SF10/Form 137.'
    label = 'College TOR (CHED)' if is_transferee else 'DepEd SF10-SHS'
    data['sources'] = [f"{label} ({', '.join(f.filename for f in tor_files)})"]
    data['extraction_mode'] = 'strict'
    data['pages_scanned'] = len(tor_files)
    data.update(extraction_report(data, allowed, SF10_OPTIONAL_KEYS))
    if raw.get('ocr_engine'):
        data['ocr_engine'] = raw['ocr_engine']
    return jsonify({"success": True, "message": "Step 2/2: school record extracted. Confirm to auto-fill.", "data": data})


@app.route('/api/ai-lens-scan', methods=['POST'])
def ai_lens_scan():
    """Legacy combined endpoint: process PSA before the school record."""
    psa_file = request.files.get('psa_file')
    tor_file = request.files.get('tor_file')

    if not psa_file or not getattr(psa_file, 'filename', '') or not tor_file or not getattr(tor_file, 'filename', ''):
        return jsonify({"success": False, "error": "Attach both PSA and school record files, or use the separate scan buttons."}), 400

    if not GEMINI_AVAILABLE:
        return jsonify({"success": False,
            "error": "Document reading is offline. Use the separate PSA then TOR scan buttons; nothing will be auto-generated."}), 503

    psa_data = {}
    tor_data = {}
    sources = []
    is_transferee = False

    if psa_file and getattr(psa_file, 'filename', ''):
        err = validate_scan_file(psa_file, 'PSA Birth Certificate')
        if err:
            return jsonify({"success": False, "error": err}), 400
        psa_file.seek(0)
        raw_psa = extract_document(psa_file, 'psa')
        if 'error' in raw_psa:
            code = 429 if raw_psa.get('retryable') else 422
            return jsonify({"success": False, "error": f"PSA: {raw_psa.get('error')}",
                            "retryable": bool(raw_psa.get('retryable')),
                            "retry_after": raw_psa.get('retry_after', 20)}), code
        psa_data = sanitize_ai_dict(raw_psa, PSA_KEYS)
        sources.append(f"PSA Form 102 ({psa_file.filename})")

    if tor_file and getattr(tor_file, 'filename', ''):
        err = validate_scan_file(tor_file, 'TOR / SF10')
        if err:
            return jsonify({"success": False, "error": err}), 400
        tor_file.seek(0)
        raw_tor = extract_document(tor_file, 'sf10')
        if 'error' in raw_tor:
            code = 429 if raw_tor.get('retryable') else 422
            return jsonify({"success": False, "error": f"TOR: {raw_tor.get('error')}",
                            "retryable": bool(raw_tor.get('retryable')),
                            "retry_after": raw_tor.get('retry_after', 20)}), code
        tor_data = sanitize_ai_dict(raw_tor, SF10_KEYS)
        sources.append(f"DepEd SF10 / TOR ({tor_file.filename})")

    # ── Merge PSA + TOR data (PSA wins for identity; TOR never overwrites PSA names) ───────
    merged = {}
    for key in ['first_name', 'middle_name', 'last_name', 'suffix', 'gender', 'psa_birth_date']:
        merged[key] = psa_data.get(key) or tor_data.get(key) or ''

    for key in PSA_KEYS:
        if key not in merged:
            merged[key] = psa_data.get(key, '')

    for key in SF10_KEYS:
        if key not in ('first_name', 'middle_name', 'last_name', 'suffix', 'gender', 'psa_birth_date'):
            merged[key] = tor_data.get(key, merged.get(key, ''))

    # Guardian defaults from PSA mother
    merged['guardian_name'] = psa_data.get('psa_mother_name') or ''
    merged['guardian_relationship'] = 'Mother' if merged['guardian_name'] else ''
    merged['guardian_contact'] = ''
    merged['civil_status'] = 'Single'
    merged['sources'] = sources
    merged['extraction_mode'] = 'strict'

    return jsonify({
        "success": True,
        "message": "Documents read (strict mode).",
        "data": merged
    })

@app.route('/')
def landing():
    """TapLication landing page."""
    return render_template('landing.html')

@app.route('/apply')
def index():
    return render_template('index.html')

@app.route('/login.php')
@app.route('/login.html')
def staff_entry():
    """Fictional-data demo entrance. The URL itself is not authentication."""
    if not DEMO_MODE:
        abort(404)
    session['staff_auth'] = True
    return redirect(url_for('admin'))


@app.route('/staff/logout', methods=['POST'])
def staff_logout():
    session.pop('staff_auth', None)
    session.pop('staff_user', None)
    flash("Admin view closed.")
    return redirect(url_for('landing'))


@app.route('/encode')
@staff_required
def encode():
    """Digitization hub (STAFF ONLY): batch-scan old paper dossiers or type them in by hand."""
    return render_template('encode.html')

# Full field list persisted from AI extraction (no more silent drops)
FULL_FORM_FIELDS = [
    'school_year', 'applicant_type', 'year_level', 'course',
    'first_name', 'middle_name', 'last_name', 'suffix', 'gender', 'civil_status',
    'email', 'contact_number', 'address', 'zip_code',
    'guardian_name', 'guardian_relationship', 'guardian_contact',
    'last_school_attended', 'year_graduated',
    'psa_birth_date', 'psa_birth_place', 'psa_registry_number',
    'psa_mother_name', 'psa_mother_citizenship', 'psa_mother_religion', 'psa_mother_occupation',
    'psa_father_name', 'psa_father_citizenship', 'psa_father_religion', 'psa_father_occupation',
    'psa_parents_marriage_date', 'psa_parents_marriage_place',
    'psa_type_of_birth', 'psa_birth_order', 'psa_weight_grams', 'psa_attendant',
    'psa_informant_name', 'psa_informant_relationship', 'psa_prepared_by', 'psa_received_date',
    'tor_lrn', 'tor_shs_track_strand', 'tor_general_average', 'tor_school_id',
    'tor_school_address', 'tor_school_year',
    'tor_grade_11_sem1_gwa', 'tor_grade_11_sem2_gwa', 'tor_grade_12_sem1_gwa', 'tor_grade_12_sem2_gwa',
    'tor_graduation_date', 'tor_section', 'tor_adviser_name', 'tor_principal_name',
    'tor_jhs_general_average', 'tor_jhs_school', 'tor_jhs_school_id',
    'tor_gwa_scale', 'tor_college_program', 'tor_college_student_no',
    'tor_college_sem_gwa', 'tor_college_cumulative_gwa', 'tor_gwa_method',
    'tor_total_units_earned', 'tor_so_number', 'tor_registrar_name', 'tor_purpose',
    'source_ref', 'extraction_doc_types',
]

INSERT_COLS = ['student_number'] + FULL_FORM_FIELDS + [
    'tor_gwa_computed', 'tor_subjects_found', 'extraction_confidence',
    'pic_2x2_filename', 'pic_1x1_filename', 'psa_birth_cert_filename',
    'marriage_contract_filename', 'transcript_filename', 'source',
]


def _to_int(value, default=0):
    try:
        if value is None or str(value).strip() == '':
            return default
        return int(float(str(value).strip()))
    except Exception:
        return default


def _to_float(value, default=0.0):
    try:
        if value is None or str(value).strip() == '':
            return default
        return float(str(value).strip())
    except Exception:
        return default


def collect_full_form(defaults=None):
    data = {}
    defaults = defaults or {}
    for key in FULL_FORM_FIELDS:
        v = request.form.get(key, '')
        data[key] = v.strip() if isinstance(v, str) else v
        if not data[key] and key in defaults:
            data[key] = defaults[key]
    return data


def save_transcript_files(last_name):
    tor_uploads = request.files.getlist('transcript')
    if not tor_uploads or not any(getattr(f, 'filename', '') for f in tor_uploads):
        single_tor = request.files.get('transcript')
        tor_uploads = [single_tor] if single_tor and getattr(single_tor, 'filename', '') else []
    tor_saved = []
    try:
        for i, f in enumerate([x for x in tor_uploads if x and getattr(x, 'filename', '')]):
            tor_saved.append(save_uploaded_file(f, f"tor_{last_name or 'doc'}_p{i+1}"))
    except Exception:
        for filename in tor_saved:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            except OSError:
                pass
        raise
    return ';'.join([s for s in tor_saved if s])


def insert_application(conn, data, files, source):
    cols = ','.join(INSERT_COLS)
    placeholders = ','.join(['?'] * len(INSERT_COLS))
    vals = [data.get('student_number', '')]
    for key in FULL_FORM_FIELDS:
        vals.append(data.get(key, ''))
    vals.append(_to_int(data.get('tor_gwa_computed'), 0))
    vals.append(_to_int(data.get('tor_subjects_found'), 0))
    vals.append(_to_float(data.get('extraction_confidence'), 0.0))
    vals.extend([files.get('pic_2x2'), files.get('pic_1x1'), files.get('psa_cert'),
                 files.get('marriage_contract'), files.get('transcript')])
    vals.append(source)
    conn.execute(f'INSERT INTO applications ({cols}) VALUES ({placeholders})', vals)


def submitted_uploads(required=False):
    names = ('pic_2x2', 'pic_1x1', 'psa_birth_cert', 'marriage_contract')
    uploads = [request.files.get(name) for name in names]
    transcripts = [f for f in request.files.getlist('transcript') if f and f.filename]
    if DEMO_MODE and (any(f and f.filename for f in uploads) or transcripts):
        raise ValueError('The public demo does not accept document uploads. Use fictional details only.')
    if len(transcripts) > 3:
        raise ValueError('Upload at most 3 school record pages.')
    if required and (any(not f or not f.filename for f in uploads[:3]) or not transcripts):
        raise ValueError('Attach PSA, school record, 2x2 and 1x1 photos.')
    for f in uploads + transcripts:
        error = validate_document(f)
        if error:
            raise ValueError(error)


def save_application_files(last_name):
    saved = {}
    try:
        for key, field, prefix in (
            ('pic_2x2', 'pic_2x2', '2x2'), ('pic_1x1', 'pic_1x1', '1x1'),
            ('psa_cert', 'psa_birth_cert', 'psa'),
            ('marriage_contract', 'marriage_contract', 'marriage')):
            saved[key] = save_uploaded_file(request.files.get(field), f'{prefix}_{last_name}')
        saved['transcript'] = save_transcript_files(last_name)
        return saved
    except Exception:
        for value in saved.values():
            for filename in (value or '').split(';'):
                if filename:
                    try:
                        os.remove(os.path.join(UPLOAD_FOLDER, filename))
                    except OSError:
                        pass
        raise


@app.route('/encode/submit', methods=['POST'])
@staff_required
def encode_submit():
    """Save a digitized old record. Files optional; tagged source='digitized' with a paper reference."""
    if DEMO_MODE and request.form.get('demo_ack') != 'yes':
        flash('Confirm that you are using fictional demo data.')
        return redirect(url_for('encode'))
    try:
        data = collect_full_form(defaults={
            'school_year': str(datetime.now().year),
            'applicant_type': 'New Freshman', 'year_level': '1st Year',
            'gender': 'Male', 'civil_status': 'Single', 'guardian_relationship': 'Mother',
        })
    except Exception:
        flash("Could not read the submitted form.")
        return redirect(url_for('encode'))

    if not data.get('first_name') or not data.get('last_name'):
        flash("Digitized record needs at least a first and last name.")
        return redirect(url_for('encode'))

    conn = get_db_connection()
    try:
        data['student_number'] = generate_unique_ref(conn, data.get('applicant_type'))
        try:
            submitted_uploads()
            files = save_application_files(data['last_name'])
        except ValueError as e:
            flash(str(e))
            return redirect(url_for('encode'))
        insert_application(conn, data, files, 'digitized')
        conn.commit()
    finally:
        conn.close()

    flash(f"Digitized record saved. TapCard ready below. Reference No: {data['student_number']}")
    return redirect(url_for('tap_card', student_number=data['student_number']))

@app.route('/submit', methods=['POST'])
def submit():
    # Full-fidelity submit: every AI-extracted field the form carries is persisted.
    if request.form.get('privacy_ack') != 'yes':
        flash('Please acknowledge the application data notice before submitting.')
        return redirect(url_for('index'))
    if DEMO_MODE and request.form.get('demo_ack') != 'yes':
        flash('Confirm that you are using fictional demo data.')
        return redirect(url_for('index'))
    data = collect_full_form()
    required = ['school_year', 'applicant_type', 'year_level', 'course', 'first_name', 'last_name',
                'gender', 'civil_status', 'email', 'contact_number', 'address', 'zip_code',
                'guardian_name', 'guardian_relationship', 'guardian_contact',
                'last_school_attended', 'year_graduated',
                'psa_birth_date', 'psa_birth_place', 'psa_registry_number',
                'psa_mother_name', 'psa_father_name',
                'tor_lrn', 'tor_shs_track_strand', 'tor_general_average']
    missing = [k for k in required if not (data.get(k) or '').strip()]
    if missing:
        flash(f"Missing required fields: {', '.join(missing)}. Please complete the form.")
        return redirect(url_for('index'))
    if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', data.get('email', '')):
        flash("Please enter a valid email address.")
        return redirect(url_for('index'))

    conn = get_db_connection()
    try:
        data['student_number'] = generate_unique_ref(conn, data.get('applicant_type'))
        try:
            submitted_uploads(required=not DEMO_MODE)
            files = save_application_files(data['last_name'])
        except ValueError as e:
            flash(str(e))
            return redirect(url_for('index'))
        insert_application(conn, data, files, 'online')
        conn.commit()
    finally:
        conn.close()

    session['visible_refs'] = [data['student_number']]
    if DEMO_MODE:
        session['demo_pass'] = {k: data.get(k, '') for k in (
            'student_number', 'first_name', 'middle_name', 'last_name', 'suffix',
            'applicant_type', 'year_level', 'course', 'school_year')}
        session['demo_pass']['status'] = 'Pending'
    send_email_notification(
        data.get('email', ''),
        f"College Application Received [{data.get('course')}] - Ref #{data['student_number']}",
        f"Dear {data.get('first_name')} {data.get('last_name')},\n\nYour admissions application for {data.get('course')} ({data.get('year_level')}, {data.get('applicant_type')}) has been recorded.\n\nAssigned Reference No.: {data['student_number']}\nLRN Verified: {data.get('tor_lrn')}\nPSA Registry No.: {data.get('psa_registry_number')}\nParent/Guardian: {data.get('guardian_name')} ({data.get('guardian_contact')})\n\nPlease keep your reference number for status verification."
    )

    flash(f"Application submitted! Your TapCard is ready below. Reference No: {data['student_number']}")
    return redirect(url_for('tap_card', student_number=data['student_number']))

@app.route('/status', methods=['GET', 'POST'])
def status_lookup():
    """Applicant status check: reference number + last name (prevents ref enumeration)."""
    if request.method == 'POST':
        ref = (request.form.get('ref') or '').strip()
        last = (request.form.get('last_name') or '').strip()
        if not ref or not last:
            flash("Type your reference number and last name.")
            return render_template('status.html')
        conn = get_db_connection()
        row = conn.execute('SELECT student_number, last_name FROM applications WHERE student_number = ?',
                           (ref,)).fetchone()
        conn.close()
        if DEMO_MODE and not row:
            demo = session.get('demo_pass') or {}
            if demo.get('student_number') == ref and demo.get('last_name', '').lower() == last.lower():
                session['visible_refs'] = [ref]
                return redirect(url_for('tap_card', student_number=ref))
        if not row or (row['last_name'] or '').strip().lower() != last.lower():
            flash("No match for that reference number + last name.")
            return render_template('status.html')
        session['visible_refs'] = [row['student_number']]
        return redirect(url_for('tap_card', student_number=row['student_number']))
    return render_template('status.html')


def _public_tap_row(row):
    """Minimal fields safe for the public pass. Full PII/docs stay staff-only."""
    keys = ['student_number', 'first_name', 'middle_name', 'last_name', 'suffix',
            'applicant_type', 'year_level', 'course', 'school_year', 'status']
    return {k: row[k] for k in keys if k in row.keys()}


def _pass_token(ref, demo=None):
    payload = demo if DEMO_MODE and demo else ref
    return URLSafeSerializer(app.secret_key, salt='tap-card').dumps(payload)


def _demo_pass(ref):
    if not DEMO_MODE:
        return None
    stored = session.get('demo_pass') or {}
    if stored.get('student_number') == ref:
        return stored
    try:
        signed = URLSafeSerializer(app.secret_key, salt='tap-card').loads(request.args.get('token', ''))
        if isinstance(signed, dict) and signed.get('student_number') == ref:
            return signed
    except BadSignature:
        pass
    return None


def _can_view_pass(ref):
    if DEMO_MODE and session.get('staff_auth'):
        return True
    if ref in session.get('visible_refs', []):
        return True
    try:
        signed = URLSafeSerializer(app.secret_key, salt='tap-card').loads(request.args.get('token', ''))
        return signed == ref or (DEMO_MODE and isinstance(signed, dict) and signed.get('student_number') == ref)
    except BadSignature:
        return False


@app.route('/tap/<student_number>')
def tap_card(student_number):
    """Applicant pass: public minimal view. Staff see the full record + documents."""
    if not _can_view_pass(student_number.strip()):
        abort(404)
    conn = get_db_connection()
    app_row = conn.execute('SELECT * FROM applications WHERE student_number = ?', (student_number.strip(),)).fetchone()
    conn.close()
    if not app_row:
        demo = _demo_pass(student_number.strip())
        if demo:
            return render_template('tap.html', app=demo, staff_view=False,
                                   pass_token=_pass_token(student_number.strip(), demo))
        flash(f"No record found for {student_number}. Check your reference number.")
        return redirect(url_for('status_lookup'))
    is_staff = bool(DEMO_MODE and session.get('staff_auth'))
    demo = _demo_pass(student_number.strip())
    if is_staff:
        return render_template('tap.html', app=app_row, staff_view=True, pass_token=_pass_token(student_number.strip(), demo))
    return render_template('tap.html', app=_public_tap_row(app_row), staff_view=False, pass_token=_pass_token(student_number.strip(), demo))


@app.route('/tap/<student_number>/qr.png')
def tap_qr(student_number):
    """QR code pointing at this applicant's TapCard (scan with any phone camera)."""
    if not _can_view_pass(student_number.strip()):
        abort(404)
    conn = get_db_connection()
    exists = conn.execute('SELECT 1 FROM applications WHERE student_number = ?', (student_number.strip(),)).fetchone()
    conn.close()
    demo = _demo_pass(student_number.strip())
    if not exists and not demo:
        return Response("Not found", status=404)
    import qrcode
    url = (PUBLIC_BASE_URL or request.host_url.rstrip('/')) + url_for('tap_card', student_number=student_number.strip(), token=_pass_token(student_number.strip(), demo))
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return Response(buf.getvalue(), mimetype='image/png')


@app.route('/admin')
@staff_required
def admin():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM applications ORDER BY id DESC')
    applications = c.fetchall()
    conn.close()
    return render_template('admin.html', applications=applications)

@app.route('/admin/update_status/<int:id>', methods=['POST'])
@staff_required
def update_status(id):
    new_status = request.form.get('status')
    if new_status not in ('Pending', 'Accepted', 'Rejected'):
        flash("Invalid status.")
        return redirect(url_for('admin'))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM applications WHERE id = ?', (id,))
    applicant = c.fetchone()

    c.execute('UPDATE applications SET status = ? WHERE id = ?', (new_status, id))
    conn.commit()
    conn.close()

    if applicant:
        send_email_notification(
            applicant['email'],
            f"Admissions Status Update: {new_status}",
            f"Dear {applicant['first_name']} {applicant['last_name']},\n\nYour application for {applicant['course']} has been updated to: {new_status}.\n\nReference No.: {applicant['student_number']}"
        )

    flash(f"Status for Application #{id} updated to {new_status}.")
    return redirect(url_for('admin'))

@app.route('/admin/delete/<int:id>', methods=['POST'])
@staff_required
def delete_application(id):
    conn = get_db_connection()
    c = conn.cursor()
    row = c.execute('SELECT * FROM applications WHERE id = ?', (id,)).fetchone()
    # Remove orphaned upload files with the record
    if row:
        for col in ('pic_2x2_filename', 'pic_1x1_filename', 'psa_birth_cert_filename',
                    'marriage_contract_filename', 'transcript_filename'):
            try:
                for fn in (row[col] or '').split(';'):
                    fn = (fn or '').strip()
                    if fn and '..' not in fn and '/' not in fn and '\\' not in fn:
                        p = os.path.join(app.config['UPLOAD_FOLDER'], fn)
                        if os.path.isfile(p):
                            os.remove(p)
            except Exception:
                pass
    c.execute('DELETE FROM applications WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash(f"Application #{id} deleted successfully.")
    return redirect(url_for('admin'))

@app.route('/uploads/<filename>')
@staff_required
def uploaded_file(filename):
    # Staff-only: applicants use the public TapCard, never direct file URLs.
    if '..' in filename or '/' in filename or '\\' in filename:
        return Response("Not found", status=404)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

init_db()

if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5000)
