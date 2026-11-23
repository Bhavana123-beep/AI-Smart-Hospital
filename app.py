from functools import wraps
import hmac
import ipaddress
import json
import os
import re
import sqlite3
import socket
import textwrap
import click
import threading
import time
from math import asin, cos, radians, sin, sqrt
from datetime import date, datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from secrets import token_urlsafe
from urllib.error import HTTPError
from urllib.parse import quote_plus, urlencode, urlsplit
from urllib.request import ProxyHandler, Request, build_opener
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import joblib
import pandas as pd
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from database_config import configured_database_path

BASE_DIR = Path(__file__).resolve().parent
APP_ENV = os.environ.get("APP_ENV", "development").strip().lower()
IS_PRODUCTION = APP_ENV == "production"
SECRET_KEY = os.environ.get("SECRET_KEY") or os.environ.get("FLASK_SECRET_KEY")
if IS_PRODUCTION and not SECRET_KEY:
    raise RuntimeError("SECRET_KEY must be set when APP_ENV=production.")

def development_secret_key():
    """Keep local signed sessions valid across Flask debug-reloader restarts."""
    key_path = BASE_DIR / "instance" / "flask_secret_key"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with key_path.open("x", encoding="utf-8") as key_file:
            key = token_urlsafe(48)
            key_file.write(key)
            key_file.flush()
    except FileExistsError:
        key = key_path.read_text(encoding="utf-8").strip()
    if len(key) < 32:
        raise RuntimeError("The local Flask session key is invalid. Remove instance/flask_secret_key and restart.")
    return key

app = Flask(__name__)
app.config.update(
    # Production requires a deployment secret; local development stores one ignored key.
    SECRET_KEY=SECRET_KEY or development_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
)
DATABASE_PATH = configured_database_path(APP_ENV)

class DatabaseConnection(sqlite3.Connection):
    """Closes connections automatically after a with-block commits or rolls back."""
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()

def get_db():
    conn = sqlite3.connect(DATABASE_PATH, timeout=10, factory=DatabaseConnection)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 10000")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def public_identifier(conn, table, column, prefix, database_id):
    """Create a permanent, collision-free public identifier from an internal id."""
    number = 100000 + database_id
    while True:
        candidate = f"{prefix}-{number}"
        if not conn.execute(f"SELECT 1 FROM {table} WHERE {column}=?", (candidate,)).fetchone():
            return candidate
        number += 1

def password_matches(stored_password, submitted_password):
    """Support legacy plaintext records without storing any newly-created password plainly."""
    if not stored_password:
        return False
    if stored_password.startswith(("pbkdf2:", "scrypt:")):
        return check_password_hash(stored_password, submitted_password)
    return hmac.compare_digest(stored_password, submitted_password)

def is_valid_email(value):
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value))

def normalize_email(value):
    """Apply the same email canonicalization before validation and DB lookup."""
    return (value or "").strip().lower()

def clear_patient_session():
    for key in ("patient_id", "patient_database_id", "patient_name", "patient_email", "last_prediction"):
        session.pop(key, None)

def clear_doctor_session():
    for key in ("doctor_id", "doctor_database_id", "doctor_name", "doctor_email", "doctor_department"):
        session.pop(key, None)

def clear_admin_session():
    for key in ("admin_id", "admin_email"):
        session.pop(key, None)

def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = token_urlsafe(32)
        session["_csrf_token"] = token
    return token

def valid_csrf():
    submitted = request.form.get("csrf_token", "")
    expected = session.get("_csrf_token", "")
    return bool(submitted and expected and hmac.compare_digest(submitted, expected))

TELUGU_TRANSLATIONS = {
    "Language": "భాష", "Password": "పాస్‌వర్డ్", "Login": "లాగిన్", "Register": "నమోదు",
    "Email or Patient ID": "ఈమెయిల్ లేదా రోగి ఐడి",
    "Enter a valid email address.": "చెల్లుబాటు అయ్యే ఈమెయిల్ చిరునామాను నమోదు చేయండి.",
    "Enter a valid email address or Patient ID.": "చెల్లుబాటు అయ్యే ఈమెయిల్ చిరునామా లేదా రోగి ఐడిని నమోదు చేయండి.",
    "No patient account is registered with that email address.": "ఈ ఈమెయిల్ చిరునామాతో రోగి ఖాతా నమోదు కాలేదు.",
    "No patient account is registered with that Patient ID.": "ఈ రోగి ఐడితో ఖాతా నమోదు కాలేదు.",
    "Incorrect password.": "పాస్‌వర్డ్ తప్పు.",
    "This patient account is inactive. Contact the hospital administrator.": "ఈ రోగి ఖాతా క్రియాశీలంగా లేదు. ఆసుపత్రి నిర్వాహకుడిని సంప్రదించండి.",
    "Enter your password.": "మీ పాస్‌వర్డ్‌ను నమోదు చేయండి.",
    "Recommended Doctors": "సిఫార్సు చేసిన వైద్యులు", "Alternative Doctors": "ప్రత్యామ్నాయ వైద్యులు",
    "Other Hospitals": "ఇతర ఆసుపత్రులు", "Available Appointment Slots": "అందుబాటులో ఉన్న అపాయింట్‌మెంట్ సమయాలు",
    "Consultation type": "సంప్రదింపు విధానం", "In-person": "ప్రత్యక్షంగా",
    "Online (doctor confirmation required)": "ఆన్‌లైన్ (వైద్యుని నిర్ధారణ అవసరం)",
    "No matching doctor available in": "ఈ విభాగంలో సరిపోలే వైద్యుడు అందుబాటులో లేరు:",
    "No matching doctor available. No Active doctor in this hospital is listed in this or a related department.": "సరిపోలే వైద్యుడు అందుబాటులో లేరు. ఈ లేదా సంబంధిత విభాగంలో క్రియాశీల వైద్యుడు లేరు.",
    "This prediction is not a medical diagnosis.": "ఈ అంచనా వైద్య నిర్ధారణ కాదు.",
    "City or location": "నగరం లేదా ప్రదేశం", "Search other hospitals": "ఇతర ఆసుపత్రులను వెతకండి",
    "Search hospitals near this location on Google Maps": "ఈ ప్రదేశానికి సమీపంలోని ఆసుపత్రుల కోసం Google Mapsలో వెతకండి",
    "Patient": "రోగి", "Doctor": "వైద్యుడు", "Date": "తేదీ", "Time": "సమయం", "Status": "స్థితి",
    "Symptoms": "లక్షణాలు", "Disease": "వ్యాధి", "Doctor message": "వైద్యుని సందేశం", "Actions": "చర్యలు",
    "View appointments": "అపాయింట్‌మెంట్లు చూడండి", "Appointment History": "అపాయింట్‌మెంట్ చరిత్ర",
    "My Profile": "నా ప్రొఫైల్", "Cancel": "రద్దు చేయండి", "Edit Profile": "ప్రొఫైల్ సవరించండి",
    "Confirm Appointment": "అపాయింట్‌మెంట్ నిర్ధారించండి", "Reason": "కారణం", "Send Request": "అభ్యర్థన పంపండి",
    "Appointment booked successfully!": "అపాయింట్‌మెంట్ విజయవంతంగా బుక్ అయింది!",
    "Your appointment request has been sent to the doctor.": "మీ అపాయింట్‌మెంట్ అభ్యర్థన వైద్యునికి పంపబడింది.",
    "View My Appointments": "నా అపాయింట్‌మెంట్లు చూడండి", "Back to Dashboard": "డాష్‌బోర్డ్‌కు తిరిగి వెళ్లండి",
    "Confirm Password": "పాస్‌వర్డ్ నిర్ధారించండి", "Create Account": "ఖాతా సృష్టించండి",
    "Scores are saved model outputs, not medical probabilities or diagnoses.": "స్కోర్లు మోడల్ ఫలితాలు మాత్రమే; వైద్య సంభావ్యతలు లేదా నిర్ధారణలు కావు.",
    "No prediction history available.": "అంచనా చరిత్ర అందుబాటులో లేదు.", "Select Gender": "లింగాన్ని ఎంచుకోండి",
    "Select Blood Group": "రక్త వర్గాన్ని ఎంచుకోండి", "Terms & Conditions": "నిబంధనలు మరియు షరతులు",
    "Already have an account?": "ఇప్పటికే ఖాతా ఉందా?", "Don't have an account?": "ఖాతా లేదా?",
    "Login Here": "ఇక్కడ లాగిన్ చేయండి", "Create your account to access AI healthcare services.": "AI ఆరోగ్య సేవలను ఉపయోగించడానికి మీ ఖాతాను సృష్టించండి.",
    "Enter a date and time that works for you.": "మీకు అనుకూలమైన తేదీ మరియు సమయాన్ని నమోదు చేయండి.",
    "Current appointment": "ప్రస్తుత అపాయింట్‌మెంట్", "Send Request": "అభ్యర్థన పంపండి",
    "Welcome back to AI Smart Hospital": "AI Smart Hospital‌కు తిరిగి స్వాగతం",
    "Machine Learning Based Healthcare": "మెషిన్ లెర్నింగ్ ఆధారిత ఆరోగ్య సేవలు",
    "Select & Book": "ఎంచుకుని బుక్ చేయండి", "Predicted Disease": "అంచనా వ్యాధి",
    "Additional notes": "అదనపు గమనికలు", "Back to Result": "ఫలితానికి తిరిగి వెళ్లండి",
    "No appointments yet.": "ఇంకా అపాయింట్‌మెంట్లు లేవు.", "No appointments available.": "అపాయింట్‌మెంట్లు అందుబాటులో లేవు.",
    "Select or enter at least one symptom.": "కనీసం ఒక లక్షణాన్ని ఎంచుకోండి లేదా నమోదు చేయండి.",
    "Choose no more than 20 symptoms.": "20 కంటే ఎక్కువ లక్షణాలను ఎంచుకోకండి.",
    "No matching symptoms found. Choose a listed symptom or check your spelling.": "సరిపోలే లక్షణాలు కనబడలేదు. జాబితాలోని లక్షణాన్ని ఎంచుకోండి లేదా అక్షరాలను తనిఖీ చేయండి.",
    "Prediction failed. Please try again.": "అంచనా విఫలమైంది. మళ్లీ ప్రయత్నించండి.",
    "The model score is low; the ranking is especially uncertain and is not a medical probability.": "మోడల్ స్కోరు తక్కువగా ఉంది; ఈ క్రమం అనిశ్చితమైనది, వైద్య సంభావ్యత కాదు.",
    "Few recognized symptoms were provided. Add more detail and discuss symptoms with a clinician.": "గుర్తించిన లక్షణాలు చాలా తక్కువ. మరింత వివరాలు జోడించి వైద్య నిపుణుడితో చర్చించండి.",
    "Some entered symptoms can require urgent attention.": "మీరు నమోదు చేసిన కొన్ని లక్షణాలకు తక్షణ వైద్య సహాయం అవసరమవచ్చు.",
    "Call your local emergency services or go to the nearest emergency department now. Do not wait for this app or its model output.": "స్థానిక అత్యవసర సేవలకు కాల్ చేయండి లేదా సమీప అత్యవసర విభాగానికి వెళ్లండి. ఈ యాప్ లేదా దాని మోడల్ ఫలితం కోసం వేచి ఉండకండి.",
    "Prediction History": "అంచనా చరిత్ర", "Date / Time": "తేదీ / సమయం", "Reschedule": "సమయం మార్చండి",
    "Home": "హోమ్", "Patient Login": "రోగి లాగిన్", "Patient Registration": "రోగి నమోదు",
    "Doctor Portal": "వైద్యుల పోర్టల్", "Admin Login": "అడ్మిన్ లాగిన్", "Dashboard": "డాష్‌బోర్డ్",
    "Welcome": "స్వాగతం", "Patient ID": "రోగి ఐడి", "Disease Prediction": "వ్యాధి అంచనా",
    "Appointments": "అపాయింట్‌మెంట్లు", "My Appointments": "నా అపాయింట్‌మెంట్లు",
    "History": "చరిత్ర", "Prediction History": "అంచనా చరిత్ర", "Profile": "ప్రొఫైల్",
    "Logout": "లాగ్ అవుట్", "Smart Symptom Analyzer": "లక్షణాల విశ్లేషణ",
    "Search symptoms": "లక్షణాలను వెతకండి", "Choose up to 20 symptoms": "20 వరకు లక్షణాలు ఎంచుకోండి",
    "Other symptoms (optional)": "ఇతర లక్షణాలు (ఐచ్ఛికం)", "Analyze Symptoms": "లక్షణాలను విశ్లేషించండి",
    "Prediction Result": "అంచనా ఫలితం", "Top model rankings": "మోడల్ అంచనాలు",
    "Disease label": "వ్యాధి పేరు", "Model score": "మోడల్ స్కోరు", "Mapped department": "సంబంధిత విభాగం",
    "Department": "విభాగం", "Matched symptoms": "గుర్తించిన లక్షణాలు",
    "Book Appointment": "అపాయింట్‌మెంట్ బుక్ చేయండి", "Appointment Date": "అపాయింట్‌మెంట్ తేదీ",
    "Appointment Time": "అపాయింట్‌మెంట్ సమయం", "Reason / Notes": "కారణం / గమనికలు",
    "Confirm Appointment": "అపాయింట్‌మెంట్ నిర్ధారించండి", "Save Changes": "మార్పులను సేవ్ చేయండి",
    "Edit Profile": "ప్రొఫైల్ సవరించండి", "Full Name": "పూర్తి పేరు", "Email": "ఈమెయిల్",
    "Phone": "ఫోన్", "Age": "వయస్సు", "Gender": "లింగం", "Blood Group": "రక్త వర్గం",
    "Address": "చిరునామా", "Download PDF Health Report": "ఆరోగ్య నివేదిక PDF డౌన్‌లోడ్ చేయండి",
    "Emergency warning": "అత్యవసర హెచ్చరిక", "Notifications": "నోటిఫికేషన్లు",
    "Request Online Consultation": "ఆన్‌లైన్ సంప్రదింపును అభ్యర్థించండి",
    "English": "English", "Telugu": "తెలుగు", "No prediction history available.": "అంచనా చరిత్ర అందుబాటులో లేదు.",
    "The model output is educational decision support, not a diagnosis.": "మోడల్ ఫలితం విద్యాపరమైన సహాయం మాత్రమే; ఇది వైద్య నిర్ధారణ కాదు.",
    "If symptoms are severe or worsening, contact a qualified healthcare professional.": "లక్షణాలు తీవ్రమైతే లేదా పెరుగుతుంటే అర్హత కలిగిన వైద్య నిపుణుడిని సంప్రదించండి.",
}

def current_language():
    return "te" if session.get("language") == "te" else "en"

def translate(text):
    return TELUGU_TRANSLATIONS.get(text, text) if current_language() == "te" else text

@app.context_processor
def inject_security_helpers():
    return {"csrf_token": csrf_token, "tr": translate, "language": current_language()}

def admin_login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "admin_id" not in session:
            flash("Please log in as an administrator.", "warning")
            return redirect(url_for("admin_login"))
        with get_db() as conn:
            admin = conn.execute("SELECT 1 FROM admin_users WHERE id=?", (session.get("admin_id"),)).fetchone()
        if not admin:
            clear_admin_session()
            flash("Your administrator session is no longer valid. Please log in again.", "warning")
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped

def init_db():
    with get_db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS admin_users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
        conn.execute("""CREATE TABLE IF NOT EXISTS patients (id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT NOT NULL, age INTEGER NOT NULL, gender TEXT, blood_group TEXT, address TEXT, password TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS prediction_history (id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, symptoms TEXT NOT NULL, disease TEXT NOT NULL, confidence REAL, department TEXT NOT NULL, doctor TEXT NOT NULL, FOREIGN KEY(patient_id) REFERENCES patients(id))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS doctors (id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT NOT NULL, password TEXT NOT NULL, department TEXT NOT NULL, specialization TEXT NOT NULL, experience INTEGER NOT NULL, qualification TEXT NOT NULL, availability TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Active')""")
        conn.execute("""CREATE TABLE IF NOT EXISTS appointments (id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER NOT NULL, doctor_id INTEGER NOT NULL, disease TEXT NOT NULL, department TEXT NOT NULL, symptoms TEXT NOT NULL, appointment_date TEXT NOT NULL, appointment_time TEXT NOT NULL, reason TEXT NOT NULL, patient_notes TEXT, doctor_notes TEXT, status TEXT NOT NULL DEFAULT 'Pending', original_date TEXT, original_time TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(patient_id) REFERENCES patients(id), FOREIGN KEY(doctor_id) REFERENCES doctors(id))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS appointment_reschedule_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, appointment_id INTEGER NOT NULL, requested_by TEXT NOT NULL, requested_date TEXT NOT NULL, requested_time TEXT NOT NULL, reason TEXT, status TEXT NOT NULL DEFAULT 'Pending', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(appointment_id) REFERENCES appointments(id))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS consultation_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            appointment_id INTEGER NOT NULL UNIQUE,
            patient_id INTEGER NOT NULL,
            doctor_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending','Accepted','Rejected')),
            meeting_url TEXT,
            doctor_message TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(appointment_id) REFERENCES appointments(id),
            FOREIGN KEY(patient_id) REFERENCES patients(id),
            FOREIGN KEY(doctor_id) REFERENCES doctors(id)
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS appointment_reminders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            appointment_id INTEGER NOT NULL,
            patient_id INTEGER NOT NULL,
            scheduled_for TEXT NOT NULL,
            notification_text TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            read_at TEXT,
            UNIQUE(appointment_id, scheduled_for),
            FOREIGN KEY(appointment_id) REFERENCES appointments(id),
            FOREIGN KEY(patient_id) REFERENCES patients(id)
        )""")
        prediction_columns = {row[1] for row in conn.execute("PRAGMA table_info(prediction_history)")}
        if "top_predictions" not in prediction_columns:
            conn.execute("ALTER TABLE prediction_history ADD COLUMN top_predictions TEXT")
        patient_columns = {row[1] for row in conn.execute("PRAGMA table_info(patients)")}
        if "status" not in patient_columns:
            conn.execute("ALTER TABLE patients ADD COLUMN status TEXT NOT NULL DEFAULT 'Active'")
            patient_columns.add("status")
        doctor_columns = {row[1] for row in conn.execute("PRAGMA table_info(doctors)")}
        if "patient_id" not in patient_columns:
            conn.execute("ALTER TABLE patients ADD COLUMN patient_id TEXT")
        if "doctor_id" not in doctor_columns:
            conn.execute("ALTER TABLE doctors ADD COLUMN doctor_id TEXT")
        if "created_at" not in doctor_columns:
            conn.execute("ALTER TABLE doctors ADD COLUMN created_at TEXT")
            conn.execute("UPDATE doctors SET created_at=CURRENT_TIMESTAMP WHERE created_at IS NULL")
        for row in conn.execute("SELECT id FROM patients WHERE patient_id IS NULL OR patient_id='' ").fetchall():
            conn.execute("UPDATE patients SET patient_id=? WHERE id=?", (public_identifier(conn, "patients", "patient_id", "PAT", row["id"]), row["id"]))
        for row in conn.execute("SELECT id FROM doctors WHERE doctor_id IS NULL OR doctor_id='' ").fetchall():
            conn.execute("UPDATE doctors SET doctor_id=? WHERE id=?", (public_identifier(conn, "doctors", "doctor_id", "DOC", row["id"]), row["id"]))
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_patients_public_id ON patients(patient_id)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_doctors_public_id ON doctors(doctor_id)")
        columns = {row[1] for row in conn.execute("PRAGMA table_info(appointments)")}
        if "doctor_message" not in columns:
            conn.execute("ALTER TABLE appointments ADD COLUMN doctor_message TEXT")
        if "proposed_date" not in columns:
            conn.execute("ALTER TABLE appointments ADD COLUMN proposed_date TEXT")
        if "proposed_time" not in columns:
            conn.execute("ALTER TABLE appointments ADD COLUMN proposed_time TEXT")
        if "consultation_type" not in columns:
            conn.execute("ALTER TABLE appointments ADD COLUMN consultation_type TEXT NOT NULL DEFAULT 'In-person'")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_consultations_doctor_status ON consultation_requests(doctor_id,status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_reminders_patient_created ON appointment_reminders(patient_id,created_at)")
        conn.execute("PRAGMA journal_mode=WAL")
        for row in conn.execute("SELECT id FROM doctors WHERE doctor_id IS NULL OR doctor_id='' ").fetchall():
            conn.execute("UPDATE doctors SET doctor_id=? WHERE id=?", (public_identifier(conn, "doctors", "doctor_id", "DOC", row["id"]), row["id"]))

@app.cli.command("create-admin")
@click.option("--email", required=True, help="Email address for the first administrator account.")
def create_admin_command(email):
    """Create the first administrator with a generated, one-time password."""
    email = email.strip().lower()
    if not is_valid_email(email):
        raise click.ClickException("Enter a valid administrator email address.")

    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute("SELECT 1 FROM admin_users LIMIT 1").fetchone():
            raise click.ClickException("An administrator account already exists; one-time setup is disabled.")
        password = token_urlsafe(32)
        conn.execute(
            "INSERT INTO admin_users (email,password) VALUES (?,?)",
            (email, generate_password_hash(password)),
        )

    click.echo("Administrator account created.")
    click.echo(f"Email: {email}")
    click.echo(f"Generated password (shown once): {password}")
    click.echo("Save the password in a password manager before closing this terminal.")

@app.cli.command("update-admin-email")
def update_admin_email_command():
    """Change the email for one existing admin without touching its password."""
    old_email = click.prompt("Current admin email").strip().lower()
    new_email = click.prompt("New admin email").strip().lower()
    if not is_valid_email(old_email):
        raise click.ClickException("Enter a valid current admin email address.")
    if not is_valid_email(new_email):
        raise click.ClickException("Enter a valid new admin email address.")

    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        matches = conn.execute(
            "SELECT id FROM admin_users WHERE LOWER(TRIM(email))=?",
            (old_email,),
        ).fetchall()
        if len(matches) != 1:
            raise click.ClickException("The current email must match exactly one admin account.")
        admin_id = matches[0]["id"]
        duplicate = conn.execute(
            "SELECT 1 FROM admin_users WHERE LOWER(TRIM(email))=? AND id<>?",
            (new_email, admin_id),
        ).fetchone()
        if duplicate:
            raise click.ClickException("That new email is already assigned to another admin account.")
        conn.execute("UPDATE admin_users SET email=? WHERE id=?", (new_email, admin_id))

    click.echo("Admin email updated. The existing password is unchanged.")

@app.cli.command("reset-admin-password")
def reset_admin_password_command():
    """Reset the password hash for one existing admin account."""
    email = click.prompt("Admin email").strip().lower()
    if not is_valid_email(email):
        raise click.ClickException("Enter a valid admin email address.")

    with get_db() as conn:
        matches = conn.execute(
            "SELECT id,email FROM admin_users WHERE LOWER(TRIM(email))=?",
            (email,),
        ).fetchall()
    if len(matches) != 1:
        raise click.ClickException("The email must match exactly one existing admin account.")

    admin_id, stored_email = matches[0]["id"], matches[0]["email"]
    password = click.prompt("New admin password", hide_input=True, confirmation_prompt=True)
    if len(password) < 12:
        raise click.ClickException("The new admin password must contain at least 12 characters.")
    password_hash = generate_password_hash(password)

    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = conn.execute(
            "SELECT 1 FROM admin_users WHERE id=? AND LOWER(TRIM(email))=?",
            (admin_id, stored_email.strip().lower()),
        ).fetchone()
        if not current:
            raise click.ClickException("The admin account changed during the reset; no password was updated.")
        conn.execute("UPDATE admin_users SET password=? WHERE id=?", (password_hash, admin_id))

    click.echo("Admin password reset successfully.")

@app.cli.command("process-appointment-reminders")
def process_appointment_reminders_command():
    """Create due in-app reminders; call from a real scheduler, not a web timer."""
    created = process_appointment_reminders()
    click.echo(f"Created {created} appointment reminder(s).")

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "patient_id" not in session:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("login"))
        with get_db() as conn:
            active = conn.execute("SELECT 1 FROM patients WHERE id=? AND status='Active'", (session.get("patient_database_id"),)).fetchone()
        if not active:
            clear_patient_session()
            flash("This patient account is inactive. Contact the hospital administrator.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def doctor_login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "doctor_id" not in session:
            flash("Please log in as a doctor to access that page.", "warning")
            return redirect(url_for("doctor_login"))
        with get_db() as conn:
            active = conn.execute("SELECT 1 FROM doctors WHERE id=? AND LOWER(TRIM(status))='active'", (session.get("doctor_database_id"),)).fetchone()
        if not active:
            clear_doctor_session()
            flash("This doctor account is not approved or is inactive.", "warning")
            return redirect(url_for("doctor_login"))
        return view(*args, **kwargs)
    return wrapped

def appointment_slot_is_valid(appointment_date, appointment_time):
    try:
        requested = datetime.strptime(f"{appointment_date} {appointment_time}", "%Y-%m-%d %H:%M")
        return requested.date() >= date.today() and requested.weekday() < 5 and 9 <= requested.hour < 17
    except ValueError:
        return False

def doctor_availability_is_valid(availability, appointment_date, appointment_time):
    """Validate a requested slot against the registered doctor's displayed schedule."""
    try:
        requested = datetime.strptime(f"{appointment_date} {appointment_time}", "%Y-%m-%d %H:%M")
    except ValueError:
        return False, "Choose a valid appointment date and time."
    if requested.date() < date.today():
        return False, "Appointment dates cannot be in the past."

    schedule = re.sub(r"\s+", " ", (availability or "").strip().lower())
    time_match = re.search(r"(\d{1,2}:\d{2})\s*-\s*(\d{1,2}:\d{2})", schedule)
    if not time_match:
        return False, "This doctor's availability is not configured with a valid time range."
    try:
        start = datetime.strptime(time_match.group(1), "%H:%M").time()
        end = datetime.strptime(time_match.group(2), "%H:%M").time()
    except ValueError:
        return False, "This doctor's availability has an invalid time range."
    weekday_names = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
    available_days = set(range(7))
    day_match = re.search(r"(monday|tuesday|wednesday|thursday|friday|saturday|sunday)\s*-\s*(monday|tuesday|wednesday|thursday|friday|saturday|sunday)", schedule)
    if day_match:
        first, last = weekday_names.index(day_match.group(1)), weekday_names.index(day_match.group(2))
        available_days = set(range(first, last + 1)) if first <= last else set(range(first, 7)) | set(range(last + 1))
    elif any(day in schedule for day in weekday_names):
        available_days = {index for index, day in enumerate(weekday_names) if day in schedule}
    if requested.weekday() not in available_days or not start <= requested.time() < end:
        return False, f"Select a time within the doctor's registered availability: {availability}."
    return True, ""

try:
    model = joblib.load(BASE_DIR / "model" / "disease_model.pkl")
    MODEL_FEATURES = [feature for feature in model.feature_names_in_ if not feature.lower().startswith("unnamed:")]
    print(f"Disease model loaded successfully. Type: {type(model).__name__}; features: {len(MODEL_FEATURES)}; classes: {len(getattr(model, 'classes_', []))}.")
except Exception as error:
    model, MODEL_FEATURES = None, []
    print(f"ERROR: Could not load disease model: {error}")
if model is not None and not MODEL_FEATURES:
    try:
        MODEL_FEATURES = [feature for feature in pd.read_csv(BASE_DIR / "dataset" / "Training.csv", nrows=0).columns.drop("prognosis", errors="ignore") if not feature.lower().startswith("unnamed:")]
    except Exception as error:
        print(f"ERROR: Could not load model features: {error}")
if model is not None:
    try:
        dataset_features = [feature for feature in pd.read_csv(BASE_DIR / "dataset" / "Training.csv", nrows=0).columns.drop("prognosis", errors="ignore") if not feature.lower().startswith("unnamed:")]
        if MODEL_FEATURES != dataset_features:
            raise ValueError("Saved model features do not exactly match the training CSV feature names and order.")
    except Exception as error:
        model, MODEL_FEATURES = None, []
        print(f"ERROR: Disease model feature schema is invalid: {error}")

DISEASE_SYMPTOM_RATES = {}
GLOBAL_FEATURE_IMPORTANCE = {}
if model is not None:
    try:
        _training = pd.read_csv(BASE_DIR / "dataset" / "Training.csv")
        _training_features = [name for name in _training.columns if name in MODEL_FEATURES]
        if _training_features != MODEL_FEATURES or "prognosis" not in _training:
            raise ValueError("Training symptom data do not match the validated model feature schema.")
        _rates = _training.groupby("prognosis")[MODEL_FEATURES].mean()
        DISEASE_SYMPTOM_RATES = {
            str(label): {feature: float(rates[feature]) for feature in MODEL_FEATURES}
            for label, rates in _rates.iterrows()
        }
        if hasattr(model, "feature_importances_"):
            GLOBAL_FEATURE_IMPORTANCE = {
                feature: float(value)
                for feature, value in zip(MODEL_FEATURES, model.feature_importances_)
            }
    except Exception as error:
        print(f"WARNING: Prediction explanations are unavailable: {error}")

ALIASES = {
    "motions":"diarrhoea", "loose motions":"diarrhoea", "loose motion":"diarrhoea", "diarrhea":"diarrhoea",
    "high temperature":"high fever", "throwing up":"vomiting", "vomit":"vomiting", "stomach upset":"stomach pain",
    "heart pain":"chest pain", "breathing difficulty":"breathlessness", "shortness of breath":"breathlessness",
    "burning urination":"burning micturition", "high blood sugar":"irregular sugar level", "yellow skin":"yellowish skin",
    "yellow eyes":"yellowing of eyes",
    "దురద":"itching", "చర్మంపై దద్దుర్లు":"skin rash", "అధిక జ్వరం":"high fever", "తేలికపాటి జ్వరం":"mild fever",
    "వాంతులు":"vomiting", "వికారం":"nausea", "తలనొప్పి":"headache", "ఛాతి నొప్పి":"chest pain",
    "గుండె నొప్పి":"chest pain", "శ్వాస తీసుకోవడంలో ఇబ్బంది":"breathlessness", "ఊపిరి తీసుకోవడంలో ఇబ్బంది":"breathlessness",
    "దగ్గు":"cough", "చలి":"chills", "అలసట":"fatigue", "కీళ్ల నొప్పి":"joint pain", "కడుపు నొప్పి":"stomach pain",
    "విరేచనాలు":"diarrhoea", "అతిసారం":"diarrhoea", "మలబద్ధకం":"constipation", "ఆకలి లేకపోవడం":"loss of appetite",
    "కండరాల నొప్పి":"muscle pain", "పసుపు చర్మం":"yellowish skin", "కళ్ళు పసుపు":"yellowing of eyes",
    "మూత్రవిసర్జనలో మంట":"burning micturition", "నోరు పొడిబారడం":"dehydration",
}
TELUGU_SYMPTOM_LABELS = {
    "itching":"దురద", "skin_rash":"చర్మంపై దద్దుర్లు", "chills":"చలి", "joint_pain":"కీళ్ల నొప్పి",
    "vomiting":"వాంతులు", "fatigue":"అలసట", "high_fever":"అధిక జ్వరం", "mild_fever":"తేలికపాటి జ్వరం",
    "breathlessness":"శ్వాస తీసుకోవడంలో ఇబ్బంది", "cough":"దగ్గు", "headache":"తలనొప్పి", "nausea":"వికారం",
    "stomach_pain":"కడుపు నొప్పి", "chest_pain":"ఛాతి నొప్పి", "diarrhoea":"విరేచనాలు", "constipation":"మలబద్ధకం",
    "loss_of_appetite":"ఆకలి లేకపోవడం", "muscle_pain":"కండరాల నొప్పి", "yellowish_skin":"పసుపు చర్మం",
    "yellowing_of_eyes":"కళ్ళు పసుపు", "burning_micturition":"మూత్రవిసర్జనలో మంట", "dehydration":"నోరు పొడిబారడం",
}
DEPARTMENTS = {
    # Cardiology
    "heart attack": "Cardiology", "heart disease": "Cardiology", "hypertension": "Cardiology",
    # Neurology
    "migraine": "Neurology", "paralysis (brain hemorrhage)": "Neurology",
    # Orthopedics
    "arthritis": "Orthopedics", "osteoarthritis": "Orthopedics", "osteoarthristis": "Orthopedics", "cervical spondylosis": "Orthopedics",
    # Pulmonology
    "pneumonia": "Pulmonology", "tuberculosis": "Pulmonology", "bronchial asthma": "Pulmonology",
    # Endocrinology and Urology
    "diabetes": "Endocrinology", "urinary tract infection": "Urology", "kidney stones": "Urology",
    # Gastroenterology
    "gastroenteritis": "Gastroenterology", "gerd": "Gastroenterology", "jaundice": "Gastroenterology",
    "hepatitis a": "Gastroenterology", "hepatitis b": "Gastroenterology", "hepatitis c": "Gastroenterology",
    "hepatitis d": "Gastroenterology", "hepatitis e": "Gastroenterology", "alcoholic hepatitis": "Gastroenterology",
    "chronic cholestasis": "Gastroenterology", "peptic ulcer diseae": "Gastroenterology",
    # Dermatology
    "fungal infection": "Dermatology", "allergy": "Dermatology", "drug reaction": "Dermatology", "acne": "Dermatology",
    "psoriasis": "Dermatology", "impetigo": "Dermatology",
    # General Medicine and infectious conditions
    "dengue": "General Medicine", "typhoid": "General Medicine", "malaria": "General Medicine", "common cold": "General Medicine",
    "chicken pox": "General Medicine", "measles": "General Medicine", "aids": "Infectious Disease", "hiv": "Infectious Disease",
}
LOW_MODEL_SCORE_THRESHOLD = 0.50
MIN_RECOGNIZED_SYMPTOMS = 2
GENERAL_EVALUATION_SYMPTOMS = {"headache", "stomach pain", "fever", "vomiting"}

def normalized_disease_label(label):
    """Normalize formatting only; disease classification always remains the model's job."""
    return re.sub(r"\s+", " ", str(label).strip().lower())

def department_for_disease(disease):
    """Resolve the model's disease label to its centralized department mapping."""
    return DEPARTMENTS.get(normalized_disease_label(disease), "General Medicine")

def registered_doctors(conn, department, disease=""):
    """Return only active doctors matching the mapped department or specialization."""
    specialization_hint = f"%{disease.strip().lower()}%"
    return conn.execute("""SELECT id, full_name, department, specialization, experience, qualification, availability
        FROM doctors
        WHERE LOWER(TRIM(status))='active'
          AND (LOWER(TRIM(department))=LOWER(TRIM(?)) OR LOWER(TRIM(specialization))=LOWER(TRIM(?)))
        ORDER BY CASE WHEN LOWER(TRIM(department))=LOWER(TRIM(?)) THEN 0 ELSE 1 END,
                 CASE WHEN LOWER(specialization) LIKE ? THEN 0 ELSE 1 END,
                 CASE WHEN TRIM(COALESCE(availability, '')) <> '' THEN 0 ELSE 1 END,
                 experience DESC, id ASC""", (department, department, department, specialization_hint)).fetchall()

RELATED_DEPARTMENTS = {
    "Cardiology": ("General Medicine",),
    "Neurology": ("General Medicine",),
    "Orthopedics": ("General Medicine",),
    "Pulmonology": ("General Medicine", "Infectious Disease"),
    "Gastroenterology": ("General Medicine", "Infectious Disease"),
    "Dermatology": ("General Medicine", "Infectious Disease"),
    "Endocrinology": ("General Medicine",),
    "Urology": ("General Medicine",),
    "Infectious Disease": ("General Medicine", "Dermatology"),
    "General Medicine": ("Infectious Disease",),
}

def doctor_recommendations(conn, department, disease=""):
    """Separate direct matches from explicitly labeled, active alternative specialists."""
    matching = registered_doctors(conn, department, disease)
    if matching:
        return [dict(row) for row in matching], []
    related = RELATED_DEPARTMENTS.get(department, ("General Medicine",))
    placeholders = ",".join("?" for _ in related)
    alternatives = conn.execute(f"""SELECT id,full_name,department,specialization,experience,qualification,availability
        FROM doctors WHERE LOWER(TRIM(status))='active'
          AND (LOWER(TRIM(department)) IN ({placeholders})
               OR LOWER(TRIM(specialization)) IN ({placeholders}))
        ORDER BY CASE WHEN LOWER(TRIM(department))='general medicine' THEN 0 ELSE 1 END,
                 experience DESC,id ASC""", tuple(item.lower() for item in related) * 2).fetchall()
    return [], [{**dict(row),
                 "recommendation_reason": (
                     f"No Active doctor is listed for {department}. This Active {row['department']} / "
                     f"{row['specialization']} doctor is shown as a related option for a broader evaluation; "
                     "please confirm suitability directly with the doctor."
                 )} for row in alternatives]

def available_doctor_slots(conn, doctor, appointment_date, interval_minutes=30):
    """Generate open, 30-minute starts from the doctor's registered weekly hours."""
    try:
        selected_day = datetime.strptime(appointment_date, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return []
    if selected_day < date.today():
        return []
    match = re.search(r"(\d{1,2}:\d{2})\s*-\s*(\d{1,2}:\d{2})", (doctor["availability"] or ""))
    if not match:
        return []
    try:
        start = datetime.strptime(match.group(1), "%H:%M")
        end = datetime.strptime(match.group(2), "%H:%M")
    except ValueError:
        return []
    slots = []
    cursor = start
    while cursor + timedelta(minutes=interval_minutes) <= end:
        value = cursor.strftime("%H:%M")
        valid, _ = doctor_availability_is_valid(doctor["availability"], appointment_date, value)
        if valid and not conn.execute("""SELECT 1 FROM appointments
                WHERE doctor_id=? AND appointment_date=? AND appointment_time=?
                  AND status NOT IN ('Declined','Cancelled') LIMIT 1""",
                (doctor["id"], appointment_date, value)).fetchone():
            slots.append(value)
        cursor += timedelta(minutes=interval_minutes)
    return slots

def google_maps_hospital_search(location):
    location = (location or "").strip()[:120]
    return f"https://www.google.com/maps/search/hospitals+near+{quote_plus(location)}" if location else None


OSM_NOMINATIM_URL = os.environ.get("OSM_NOMINATIM_URL", "https://nominatim.openstreetmap.org/search")
OSM_OVERPASS_DEFAULTS = (
    "https://overpass-api.de/api/interpreter",
    "https://overpass.private.coffee/api/interpreter",
    "https://maps.mail.ru/osm/tools/overpass/api/interpreter",
)
OSM_DRESEL_ASIA = "https://ovp.dresel.systems/api-as/interpreter"
OSM_ASIA_COUNTRY_CODES = frozenset((
    "af", "am", "az", "bh", "bd", "bt", "bn", "kh", "cn", "cy", "ge", "in", "id", "ir", "iq", "il",
    "jp", "jo", "kz", "kp", "kr", "kw", "kg", "la", "lb", "my", "mv", "mn", "mm", "np", "om", "pk",
    "ps", "ph", "qa", "sa", "sg", "lk", "sy", "tw", "tj", "th", "tl", "tm", "ae", "uz", "vn", "ye",
    "hk", "mo",
))
OSM_OVERPASS_TIMEOUT = 8
OSM_OVERPASS_TOTAL_TIMEOUT = 30
OSM_OVERPASS_RETRIES_PER_ENDPOINT = 1
OSM_NOMINATIM_RETRIES = 1
OSM_USER_AGENT = os.environ.get(
    "OSM_USER_AGENT", "AI-Smart-Hospital-Assistant/1.0 (OpenStreetMap hospital search)"
)
# Do not inherit ambient HTTP(S)_PROXY values: local development environments can
# inject unusable proxy endpoints (for example, 127.0.0.1:9). Deployments that
# require an outbound proxy can configure it explicitly for these public OSM APIs.
OSM_HTTP_PROXY = os.environ.get("OSM_HTTP_PROXY", "").strip()
OSM_CACHE_SECONDS = 300
OSM_GEOCODE_CACHE_SECONDS = 3600
_osm_cache = {}
_osm_cache_lock = threading.Lock()
_geocode_cache = {}
_geocode_cache_lock = threading.Lock()
_nominatim_lock = threading.Lock()
_last_nominatim_request = 0.0


class HospitalSearchError(Exception):
    """A safe, user-displayable error from the external OSM directory."""

    def __init__(self, message, *, retryable=True, failure="unavailable", status=None, retry_after=0):
        super().__init__(message)
        self.retryable = retryable
        self.failure = failure
        self.status = status
        self.retry_after = retry_after


class HospitalLocationError(HospitalSearchError):
    """The entered place could not be safely resolved to the requested city."""


OSM_KNOWN_INDIAN_CITIES = {
    "banglore": {"canonical": "Bengaluru", "aliases": ("Banglore", "Bangalore", "Bengaluru")},
    "bangalore": {"canonical": "Bengaluru", "aliases": ("Banglore", "Bangalore", "Bengaluru")},
    "bengaluru": {"canonical": "Bengaluru", "aliases": ("Banglore", "Bangalore", "Bengaluru")},
    "hyderabad": {"canonical": "Hyderabad", "aliases": ("Hyderabad",)},
    "vijayawada": {"canonical": "Vijayawada", "aliases": ("Vijayawada",)},
}
OSM_COUNTRY_CODES = {
    "india": "in", "pakistan": "pk", "bangladesh": "bd", "nepal": "np", "sri lanka": "lk",
    "united states": "us", "usa": "us", "united kingdom": "gb", "uk": "gb", "canada": "ca",
    "australia": "au", "new zealand": "nz", "united arab emirates": "ae", "uae": "ae",
}


def _normalized_place_text(value):
    return re.sub(r"[^a-z0-9]+", " ", (value or "").casefold()).strip()


def _requested_place(location):
    parts = [part.strip() for part in location.split(",") if part.strip()]
    first = _normalized_place_text(parts[0] if parts else location)
    known = OSM_KNOWN_INDIAN_CITIES.get(first)
    if not known:
        for city_alias, city_record in OSM_KNOWN_INDIAN_CITIES.items():
            if first.startswith(city_alias + " "):
                known = city_record
                break
    country_codes = set()
    normalized_location = f" {_normalized_place_text(location)} "
    for country_name, code in OSM_COUNTRY_CODES.items():
        if f" {country_name} " in normalized_location:
            country_codes.add(code)
    if len(country_codes) > 1:
        raise HospitalLocationError("The search contains conflicting countries. Enter one intended country.", retryable=False)
    country_code = next(iter(country_codes), None)
    region_hints = tuple(part for part in parts[1:]
                         if _normalized_place_text(part) not in OSM_COUNTRY_CODES)
    if known:
        if country_code and country_code != "in":
            raise HospitalLocationError("That city name conflicts with the requested country. Search for the city and country you intended.", retryable=False)
        return {"city_key": known["canonical"].casefold(), "city_name": known["canonical"],
                "aliases": known["aliases"], "country_code": "in", "region_hints": region_hints}
    return {"city_key": _normalized_place_text(location), "city_name": parts[0] if parts else location,
            "aliases": (parts[0] if parts else location,), "country_code": country_code or "",
            "region_hints": region_hints}


def _contains_place_name(text, aliases):
    normalized = f" {_normalized_place_text(text)} "
    return any(f" {_normalized_place_text(alias)} " in normalized for alias in aliases if alias)


def _is_city_boundary(geometry):
    if not isinstance(geometry, dict):
        return False
    coordinates = geometry.get("coordinates")
    if geometry.get("type") == "Polygon":
        polygons = [coordinates]
    elif geometry.get("type") == "MultiPolygon":
        polygons = coordinates
    else:
        return False
    return bool(polygons and all(isinstance(poly, list) and poly and isinstance(poly[0], list) and len(poly[0]) >= 4 for poly in polygons))


def _point_in_ring(lon, lat, ring):
    inside = False
    j = len(ring) - 1
    for i, point in enumerate(ring):
        xi, yi = float(point[0]), float(point[1])
        xj, yj = float(ring[j][0]), float(ring[j][1])
        if (yi > lat) != (yj > lat):
            cross = (xj - xi) * (lat - yi) / (yj - yi) + xi
            if lon < cross:
                inside = not inside
        j = i
    return inside


def _point_in_city_boundary(lat, lon, geometry):
    if not _is_city_boundary(geometry):
        return False
    polygons = [geometry["coordinates"]] if geometry["type"] == "Polygon" else geometry["coordinates"]
    for polygon in polygons:
        try:
            if _point_in_ring(lon, lat, polygon[0]) and not any(_point_in_ring(lon, lat, hole) for hole in polygon[1:]):
                return True
        except (TypeError, ValueError, IndexError):
            continue
    return False


def _hospital_country_matches(tags, country_code):
    tag_country = str(tags.get("addr:country") or "").strip()
    if not tag_country:
        return True
    normalized = _normalized_place_text(tag_country)
    tag_code = OSM_COUNTRY_CODES.get(normalized)
    if not tag_code and normalized in ("in", "pk"):
        tag_code = normalized
    return tag_code == country_code


def _hospital_address_matches_city(tags, city_aliases):
    tagged_city = str(tags.get("addr:city") or tags.get("addr:town") or tags.get("addr:village") or "").strip()
    return not tagged_city or _contains_place_name(tagged_city, city_aliases)


def _osm_json_request(url, *, data=None, timeout=8, stage="OpenStreetMap"):
    host = urlsplit(url).hostname or "unknown-host"
    headers = {"User-Agent": OSM_USER_AGENT, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
    req = Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
    try:
        if OSM_HTTP_PROXY:
            proxy_parts = urlsplit(OSM_HTTP_PROXY)
            if proxy_parts.scheme not in ("http", "https") or not proxy_parts.hostname:
                raise HospitalSearchError("The configured OpenStreetMap proxy URL is invalid.", retryable=False)
            opener = build_opener(ProxyHandler({"http": OSM_HTTP_PROXY, "https": OSM_HTTP_PROXY}))
        else:
            opener = build_opener(ProxyHandler({}))
        with opener.open(req, timeout=timeout) as response:
            if response.status != 200:
                raise HospitalSearchError(
                    f"{stage} returned HTTP {response.status}.", retryable=response.status >= 500,
                    failure="http", status=response.status,
                )
            return json.loads(response.read(4_000_000).decode("utf-8"))
    except HTTPError as exc:
        try:
            response_body = exc.read(512).decode("utf-8", "replace").replace("\r", " ").replace("\n", " ")
        except Exception:
            response_body = "<unavailable>"
        app.logger.warning("hospital_search stage=%s host=%s status=%s body=%r",
                           stage, host, exc.code, response_body[:300])
        retry_after = 0
        try:
            retry_after = min(3.0, max(0.0, float(exc.headers.get("Retry-After", 0))))
        except (TypeError, ValueError, AttributeError):
            pass
        if exc.code == 429:
            message = f"{stage} rate-limited the request (HTTP 429)."
        elif exc.code >= 500:
            message = f"{stage} is temporarily unavailable (HTTP {exc.code})."
        else:
            message = f"{stage} rejected the request (HTTP {exc.code})."
        raise HospitalSearchError(message, retryable=exc.code in (408, 425, 429, 500, 502, 503, 504),
                                 failure="http", status=exc.code, retry_after=retry_after) from exc
    except (TimeoutError, socket.timeout) as exc:
        app.logger.warning("hospital_search stage=%s host=%s failure=timeout timeout_seconds=%s",
                           stage, host, timeout)
        raise HospitalSearchError(f"{stage} request timed out after {timeout} seconds.",
                                 retryable=True, failure="timeout") from exc
    except OSError as exc:
        reason = str(getattr(exc, "reason", exc))[:240]
        app.logger.warning("hospital_search stage=%s host=%s failure=connection reason=%r", stage, host, reason)
        raise HospitalSearchError(f"{stage} could not be reached.", retryable=True, failure="connection") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        app.logger.warning("hospital_search stage=%s host=%s failure=invalid_json", stage, host)
        raise HospitalSearchError(f"{stage} returned invalid data.", retryable=True, failure="invalid_response") from exc


def _request_nominatim_locked(url):
    """Retry one transient geocode failure while holding the global request throttle."""
    global _last_nominatim_request
    for attempt in range(OSM_NOMINATIM_RETRIES + 1):
        wait = 1.05 - (time.monotonic() - _last_nominatim_request)
        if wait > 0:
            time.sleep(wait)
        _last_nominatim_request = time.monotonic()
        try:
            return _osm_json_request(url, timeout=8, stage="Nominatim")
        except HospitalSearchError as exc:
            if not exc.retryable or attempt >= OSM_NOMINATIM_RETRIES:
                raise
            backoff = max(0.5 * (attempt + 1), exc.retry_after)
            time.sleep(min(3.0, backoff))


def _overpass_endpoints(country_code=""):
    """Return configured HTTPS Overpass hosts first, followed by public fallbacks."""
    configured = os.environ.get("OSM_OVERPASS_URLS", "").strip()
    if configured:
        candidates = [url.strip() for url in configured.split(",") if url.strip()]
    else:
        primary = os.environ.get("OSM_OVERPASS_URL", OSM_OVERPASS_DEFAULTS[0]).strip()
        # A free regional mirror can serve Asia when the global instances are down.
        if country_code.casefold() in OSM_ASIA_COUNTRY_CODES:
            candidates = [OSM_DRESEL_ASIA, primary, *(url for url in OSM_OVERPASS_DEFAULTS if url != primary)]
        else:
            candidates = [primary, *(url for url in OSM_OVERPASS_DEFAULTS if url != primary)]
    urls, seen = [], set()
    for candidate in candidates:
        parts = urlsplit(candidate)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
            continue
        normalized = candidate.rstrip("/")
        if normalized not in seen:
            seen.add(normalized)
            urls.append(normalized)
    return urls[:5]


def _request_overpass(payload, endpoints=None):
    """Query public Overpass instances sequentially, retrying transient host errors."""
    endpoints = endpoints if endpoints is not None else _overpass_endpoints()
    if not endpoints:
        raise HospitalSearchError("No valid HTTPS OpenStreetMap Overpass endpoint is configured.", retryable=False)
    last_error = None
    deadline = time.monotonic() + OSM_OVERPASS_TOTAL_TIMEOUT
    for endpoint in endpoints:
        if time.monotonic() >= deadline:
            break
        for attempt in range(OSM_OVERPASS_RETRIES_PER_ENDPOINT + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                data = _osm_json_request(endpoint, data=payload,
                                         timeout=min(OSM_OVERPASS_TIMEOUT, remaining), stage="Overpass")
                if isinstance(data, dict) and data.get("remark"):
                    remark = str(data.get("remark", ""))[:240]
                    app.logger.warning("hospital_search stage=Overpass host=%s status=200 remark=%r",
                                       urlsplit(endpoint).hostname, remark)
                    raise HospitalSearchError("Overpass returned a query error.", retryable=True, failure="query")
                if not isinstance(data, dict) or not isinstance(data.get("elements"), list):
                    raise HospitalSearchError("Overpass returned an invalid response.", retryable=True, failure="invalid_response")
                return data
            except HospitalSearchError as exc:
                last_error = exc
                if not exc.retryable or attempt >= OSM_OVERPASS_RETRIES_PER_ENDPOINT:
                    break
                # Brief backoff before retrying this host; move to the next host on failure.
                time.sleep(min(3.0, max(0.35 * (attempt + 1), exc.retry_after)))
    if not last_error:
        last_error = HospitalSearchError(
            f"The Overpass search exceeded its {OSM_OVERPASS_TOTAL_TIMEOUT}-second time limit.",
            retryable=False, failure="timeout",
        )
    raise HospitalSearchError(
        f"Overpass is unavailable after trying {len(endpoints)} endpoints. Last failure: {last_error}",
        retryable=False, failure=last_error.failure,
    ) from last_error


def _geocode_osm_location(location):
    global _last_nominatim_request
    requested = _requested_place(location)
    cache_key = (requested["city_key"], requested["country_code"],
                 tuple(_normalized_place_text(hint) for hint in requested["region_hints"]))
    with _geocode_cache_lock:
        cached = _geocode_cache.get(cache_key)
        if cached and cached[0] > time.monotonic():
            return cached[1]
    query = f"{requested['city_name']}, India" if requested["country_code"] == "in" else location
    search_params = {"q": query, "format": "jsonv2", "limit": 5, "addressdetails": 1, "polygon_geojson": 1}
    if requested["country_code"]:
        search_params["countrycodes"] = requested["country_code"]
    params = urlencode(search_params)
    nominatim = urlsplit(OSM_NOMINATIM_URL)
    if nominatim.scheme != "https" or not nominatim.hostname:
        raise HospitalSearchError("The configured Nominatim endpoint must be a valid HTTPS URL.",
                                 retryable=False, failure="configuration")
    with _nominatim_lock:
        with _geocode_cache_lock:
            cached = _geocode_cache.get(cache_key)
            if cached and cached[0] > time.monotonic():
                return cached[1]
        results = _request_nominatim_locked(f"{OSM_NOMINATIM_URL}?{params}")
    if not isinstance(results, list) or not results:
        raise HospitalLocationError("We could not find that city. Check the spelling or include its state and country.", retryable=False)
    matching = []
    for item in results:
        address = item.get("address") or {}
        country_code = str(address.get("country_code", "")).lower()
        if requested["country_code"] and country_code != requested["country_code"]:
            continue
        place_labels = [item.get("name", ""), item.get("display_name", "")]
        place_labels.extend(address.get(key, "") for key in (
            "city", "town", "municipality", "village", "suburb", "city_district", "county"
        ))
        joined_labels = " ".join(str(label) for label in place_labels)
        if (_contains_place_name(joined_labels, requested["aliases"])
                and all(_contains_place_name(joined_labels, (hint,)) for hint in requested["region_hints"])):
            matching.append((item, address, country_code))
    if not matching:
        expected = "India" if requested["country_code"] == "in" else "the requested country"
        raise HospitalLocationError(
            f"We could not verify that result as {requested['city_name']} in {expected}. Enter the city and country explicitly.",
            retryable=False,
        )
    countries = {country_code for _, _, country_code in matching if country_code}
    if len(countries) > 1:
        raise HospitalLocationError("That city name matches multiple countries. Add the country to your search.", retryable=False)
    regions = {_normalized_place_text(address.get("state") or address.get("region") or address.get("county") or "")
               for _, address, _ in matching}
    regions.discard("")
    if not requested["region_hints"] and len(regions) > 1:
        raise HospitalLocationError("That city name matches multiple regions. Add its state and country to your search.", retryable=False)
    selected = next((candidate for candidate in matching
                     if _is_city_boundary(candidate[0].get("geojson"))
                     and (candidate[0].get("type") in ("administrative", "city", "town", "municipality", "local_authority")
                          or candidate[0].get("addresstype") in ("city", "town", "municipality", "local_authority"))), None)
    if not selected:
        raise HospitalLocationError("We found the city name but could not verify its boundary. Try adding the state and country.", retryable=False)
    item, address, country_code = selected
    try:
        lat, lon = float(item["lat"]), float(item["lon"])
        bounds = [float(value) for value in item["boundingbox"]]
    except (KeyError, TypeError, ValueError) as exc:
        raise HospitalLocationError("The location service did not provide a usable city boundary. Try another search.", retryable=False) from exc
    if (not (-90 <= lat <= 90 and -180 <= lon <= 180) or len(bounds) != 4
            or not (-90 <= bounds[0] < bounds[1] <= 90 and -180 <= bounds[2] < bounds[3] <= 180)):
        raise HospitalLocationError("The location service returned an invalid city boundary. Try another search.", retryable=False)
    center = {
        "lat": lat, "lon": lon, "display_name": str(item.get("display_name", ""))[:500],
        "country_code": country_code, "city_name": requested["city_name"], "city_key": requested["city_key"],
        "city_aliases": requested["aliases"], "bounds": bounds, "boundary": item["geojson"],
        "osm_type": item.get("osm_type"), "osm_id": item.get("osm_id"),
    }
    with _geocode_cache_lock:
        _geocode_cache[cache_key] = (time.monotonic() + OSM_GEOCODE_CACHE_SECONDS, center)
        for key, (expires, _) in list(_geocode_cache.items()):
            if expires <= time.monotonic():
                _geocode_cache.pop(key, None)
    return center


def _distance_km(lat1, lon1, lat2, lon2):
    d_lat, d_lon = radians(lat2 - lat1), radians(lon2 - lon1)
    hav = sin(d_lat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(d_lon / 2) ** 2
    return round(6371.0088 * 2 * asin(min(1, sqrt(hav))), 1)


def _hospital_address(tags, fallback_location):
    addr = []
    house = " ".join(filter(None, [tags.get("addr:housenumber"), tags.get("addr:street")]))
    if house:
        addr.append(house)
    for key in ("addr:suburb", "addr:neighbourhood", "addr:city", "addr:town", "addr:village", "addr:district", "addr:state", "addr:postcode", "addr:country"):
        value = tags.get(key)
        if value and value not in addr:
            addr.append(value)
    return ", ".join(addr) if addr else f"Address details not provided by OpenStreetMap · near {fallback_location}"


def _hospital_specialty_match(tags, department):
    specialties = " ".join(str(value) for key, value in tags.items()
                            if key in ("healthcare:speciality", "healthcare:specialty", "speciality", "specialty"))
    if not specialties or not department:
        return False
    terms = re.findall(r"[a-z0-9]+", department.lower())
    tagged = re.findall(r"[a-z0-9]+", specialties.lower().replace("_", " "))
    return bool(terms and any(term in tagged for term in terms if len(term) > 3))


def search_osm_hospitals(location, department=""):
    center = _geocode_osm_location(location)
    # Resolve first, then key the result cache by the verified boundary identity.
    # Bangalore/Bengaluru share a key; different cities/countries cannot collide.
    cache_key = (center["city_key"], center["country_code"], center["osm_type"], center["osm_id"],
                 tuple(center["bounds"]), department.casefold())
    now = time.monotonic()
    with _osm_cache_lock:
        cached = _osm_cache.get(cache_key)
        if cached and cached[0] > now:
            return cached[1]

    south, north, west, east = center["bounds"]
    bbox = f"({south},{west},{north},{east})"
    query = (f"[out:json][timeout:20];(nwr{bbox}[amenity=hospital];"
             f"nwr{bbox}[healthcare=hospital];);out center tags 500;")
    payload = urlencode({"data": query}).encode("utf-8")
    data = _request_overpass(payload, endpoints=_overpass_endpoints(center.get("country_code", "")))
    hospitals, seen = [], set()
    for item in data.get("elements", []):
        tags = item.get("tags") or {}
        name = str(tags.get("name") or tags.get("name:en") or "").strip()
        if not name:
            continue
        coords = item.get("center") or item
        try:
            lat, lon = float(coords["lat"]), float(coords["lon"])
        except (KeyError, TypeError, ValueError):
            continue
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            continue
        if not _point_in_city_boundary(lat, lon, center["boundary"]):
            continue
        if not _hospital_country_matches(tags, center["country_code"]):
            continue
        if not _hospital_address_matches_city(tags, center["city_aliases"]):
            continue
        osm_type, osm_id = item.get("type"), item.get("id")
        identity = (osm_type, osm_id)
        if identity in seen:
            continue
        seen.add(identity)
        hospitals.append({
            "name": name[:200], "address": _hospital_address(tags, center["city_name"]),
            "distance_km": _distance_km(center["lat"], center["lon"], lat, lon),
            "phone": str(tags.get("phone") or tags.get("contact:phone") or "")[:100],
            "website": str(tags.get("website") or tags.get("contact:website") or "")[:300],
            "type": str(tags.get("healthcare") or tags.get("amenity") or "hospital").replace("_", " ")[:80],
            "specialty_match": _hospital_specialty_match(tags, department),
            "lat": lat, "lon": lon,
            "osm_url": f"https://www.openstreetmap.org/{osm_type}/{osm_id}" if osm_type in ("node", "way", "relation") and isinstance(osm_id, int) else "",
        })
    hospitals.sort(key=lambda hospital: (not hospital["specialty_match"], hospital["distance_km"], hospital["name"].casefold()))
    result = {"hospitals": hospitals[:60], "location": center["display_name"], "reason": None if hospitals else "no_results"}
    with _osm_cache_lock:
        _osm_cache[cache_key] = (time.monotonic() + OSM_CACHE_SECONDS, result)
        for key, (expires, _) in list(_osm_cache.items()):
            if expires <= time.monotonic():
                _osm_cache.pop(key, None)
    return result


def valid_hospital_search_location(location):
    return bool(location and len(location) <= 120 and re.fullmatch(r"[\w\s.,'’()/-]+", location, flags=re.UNICODE))

def normalized_symptom(text):
    """Normalize free-text symptom wording before matching real model features."""
    return re.sub(r"\s+", " ", text.strip().lower().replace("_", " ").replace("-", " "))

def match_symptoms(raw_symptoms):
    """Match aliases only when their canonical target is an actual model feature."""
    lookup = {normalized_symptom(feature): feature for feature in MODEL_FEATURES}
    entered = [normalized_symptom(item) for item in re.split(r"[,;，；\n]+", raw_symptoms) if item.strip()]
    matched, unmatched = [], []
    for symptom in entered:
        candidate = normalized_symptom(ALIASES.get(symptom, symptom))
        feature = lookup.get(candidate)
        if feature:
            matched.append(feature)
        else:
            unmatched.append(symptom)
    return entered, list(dict.fromkeys(matched)), unmatched

def rank_diseases(matched):
    """Run the existing Random Forest on exactly its validated ordered features."""
    if model is None or not MODEL_FEATURES or not matched:
        return []
    input_df = pd.DataFrame(0, index=[0], columns=MODEL_FEATURES)
    input_df.loc[0, list(dict.fromkeys(matched))] = 1
    if not hasattr(model, "predict_proba"):
        label = str(model.predict(input_df)[0])
        return [{"disease": label, "vote_share": None, "department": department_for_disease(label)}]
    probabilities = model.predict_proba(input_df)[0]
    indices = sorted(range(len(probabilities)), key=lambda index: (-float(probabilities[index]), index))[:3]
    return [
        {
            "disease": str(model.classes_[index]),
            "vote_share": round(float(probabilities[index]) * 100, 2),
            "department": department_for_disease(model.classes_[index]),
        }
        for index in indices
    ]

def explain_rankings(top_predictions, matched):
    """Describe training-set co-occurrence and global importance without implying causation."""
    explanations = []
    for prediction in top_predictions:
        disease = prediction["disease"]
        rates = DISEASE_SYMPTOM_RATES.get(disease, {})
        selected = sorted(
            matched,
            key=lambda feature: (
                float(rates.get(feature, 0.0)),
                GLOBAL_FEATURE_IMPORTANCE.get(feature, 0.0),
            ),
            reverse=True,
        )[:5]
        explanations.append({
            "disease": disease,
            "symptoms": [
                {
                    "name": feature.replace("_", " "),
                    "training_rate": round(100 * float(rates.get(feature, 0.0)), 1),
                    "importance": round(100 * GLOBAL_FEATURE_IMPORTANCE.get(feature, 0.0), 3),
                }
                for feature in selected
            ],
        })
    return explanations

EMERGENCY_FEATURES = {
    "chest_pain", "breathlessness", "coma", "altered_sensorium",
    "weakness_of_one_body_side", "slurred_speech",
}
EMERGENCY_PHRASES = (
    "chest pain", "difficulty breathing", "shortness of breath", "cannot breathe", "can't breathe",
    "unconscious", "passed out", "seizure", "slurred speech", "weakness on one side",
    "severe bleeding", "vomiting blood", "blood in vomit", "ఛాతి నొప్పి", "గుండె నొప్పి",
    "శ్వాస తీసుకోవడంలో ఇబ్బంది", "ఊపిరి తీసుకోవడంలో ఇబ్బంది", "అపస్మారక స్థితి", "మూర్ఛ",
)
NEGATION_MARKERS = ("no ", "not ", "without ", "denies ", "లేదు", "కాదు")

def emergency_risk(raw_symptoms, matched):
    """Rule-based symptom warning independent of model output or model score."""
    if set(matched).intersection(EMERGENCY_FEATURES):
        return True
    for item in re.split(r"[,;，；\n]+", raw_symptoms or ""):
        phrase = normalized_symptom(item)
        if any(marker in phrase for marker in NEGATION_MARKERS):
            continue
        if any(term in phrase for term in EMERGENCY_PHRASES):
            return True
    return False

def valid_meeting_url(value):
    value = (value or "").strip()
    if not value:
        return True
    if len(value) > 2048:
        return False
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme.lower() != "https" or not host or parsed.username or parsed.password:
            return False
        if host in {"localhost", "localhost.localdomain"} or host.endswith((".local", ".internal", ".localhost")):
            return False
        try:
            if not ipaddress.ip_address(host).is_global:
                return False
        except ValueError:
            pass
        return True
    except ValueError:
        return False

def hospital_timezone():
    try:
        return ZoneInfo(os.environ.get("HOSPITAL_TIMEZONE", "Asia/Kolkata"))
    except ZoneInfoNotFoundError:
        return timezone.utc

def process_appointment_reminders(now=None, window_hours=24):
    """Persist upcoming appointment reminders; a scheduler can call this repeatedly safely."""
    zone = hospital_timezone()
    current = now or datetime.now(zone)
    if current.tzinfo is None:
        current = current.replace(tzinfo=zone)
    horizon = current + timedelta(hours=window_hours)
    with get_db() as conn:
        rows = conn.execute("""SELECT a.id,a.patient_id,a.appointment_date,a.appointment_time,d.full_name doctor_name
            FROM appointments a JOIN doctors d ON d.id=a.doctor_id
            JOIN patients p ON p.id=a.patient_id
            WHERE a.status IN ('Pending','Accepted') AND p.status='Active'
              AND a.appointment_date BETWEEN ? AND ?
            ORDER BY a.appointment_date,a.appointment_time""", (current.date().isoformat(), horizon.date().isoformat())).fetchall()
        created = 0
        for row in rows:
            try:
                scheduled = datetime.strptime(
                    f"{row['appointment_date']} {row['appointment_time']}", "%Y-%m-%d %H:%M"
                ).replace(tzinfo=zone)
            except ValueError:
                continue
            if not current <= scheduled <= horizon:
                continue
            scheduled_key = scheduled.isoformat(timespec="minutes")
            text = f"Appointment reminder: {row['doctor_name']} on {scheduled.strftime('%Y-%m-%d %H:%M')}"
            cursor = conn.execute("""INSERT OR IGNORE INTO appointment_reminders
                (appointment_id,patient_id,scheduled_for,notification_text)
                VALUES (?,?,?,?)""", (row["id"], row["patient_id"], scheduled_key, text))
            created += cursor.rowcount
    return created

def pdf_text_line(label, value):
    value = str(value or "")
    try:
        value.encode("cp1252")
    except UnicodeEncodeError:
        value = "[non-Latin text omitted from this PDF]"
    return f"{label}: {value}"

def create_pdf(lines):
    """Build a small dependency-free English PDF report using standard Helvetica."""
    wrapped = []
    for line in lines:
        wrapped.extend(textwrap.wrap(str(line), width=88, replace_whitespace=True) or [""])
    page_lines = [wrapped[i:i + 50] for i in range(0, max(len(wrapped), 1), 50)]
    objects = []
    page_ids = [3 + index * 2 for index in range(len(page_lines))]
    content_ids = [page_id + 1 for page_id in page_ids]
    font_id = 3 + 2 * len(page_lines)
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("ascii"))
    for page_id, content_id, lines_for_page in zip(page_ids, content_ids, page_lines):
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>".encode("ascii")
        )
        commands = [b"BT /F1 10 Tf 48 748 Td 13 TL"]
        for line in lines_for_page:
            safe = line.encode("cp1252", "replace").decode("cp1252")
            escaped = safe.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            commands.append(b"(" + escaped.encode("cp1252") + b") Tj T*")
        commands.append(b"ET")
        stream = b"\n".join(commands)
        objects.append(b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, body in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode("ascii"))
        output.extend(body)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    return bytes(output)

def symptom_choices():
    return sorted(
        [{"value": feature,
          "label": re.sub(r"\s+", " ", feature.replace("_", " ")).strip().title(),
          "label_te": TELUGU_SYMPTOM_LABELS.get(feature, re.sub(r"\s+", " ", feature.replace("_", " ")).strip().title())}
         for feature in MODEL_FEATURES],
        key=lambda item: item["label"].casefold(),
    )

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if not valid_csrf():
            return render_template("admin_login.html", error="Your session expired. Reload the page and try again."), 400
        email = normalize_email(request.form.get("email", ""))
        password = request.form.get("password", "")
        with get_db() as conn:
            admin = conn.execute(
                "SELECT id,email,password FROM admin_users WHERE LOWER(TRIM(email))=?",
                (email,),
            ).fetchone()
        if not admin or not password_matches(admin["password"], password):
            return render_template("admin_login.html", error="Invalid administrator email or password."), 401
        clear_patient_session()
        clear_doctor_session()
        clear_admin_session()
        session["_csrf_token"] = token_urlsafe(32)
        session.update(admin_id=admin["id"], admin_email=admin["email"])
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_login.html")

@app.route("/admin/logout", methods=["POST"])
@admin_login_required
def admin_logout():
    if not valid_csrf():
        return "Invalid CSRF token", 400
    clear_admin_session()
    flash("You have been logged out.", "success")
    return redirect(url_for("admin_login"))

@app.route("/admin")
@app.route("/admin/dashboard")
@admin_login_required
def admin_dashboard():
    with get_db() as conn:
        patients = conn.execute("SELECT id,patient_id,full_name,email,phone,status FROM patients ORDER BY id DESC").fetchall()
        doctors = conn.execute("SELECT id,doctor_id,full_name,email,department,specialization,status,created_at FROM doctors ORDER BY CASE status WHEN 'Pending' THEN 0 ELSE 1 END, id DESC").fetchall()
        appointments = conn.execute("""SELECT a.id,a.disease,a.department,a.appointment_date,a.appointment_time,a.status,
            p.patient_id public_patient_id,p.full_name patient_name,p.email patient_email,d.full_name doctor_name
            FROM appointments a JOIN patients p ON p.id=a.patient_id JOIN doctors d ON d.id=a.doctor_id
            ORDER BY a.appointment_date DESC,a.appointment_time DESC,a.id DESC LIMIT 100""").fetchall()
        stats = {
            "patients": conn.execute("SELECT COUNT(*) FROM patients").fetchone()[0],
            "active_doctors": conn.execute("SELECT COUNT(*) FROM doctors WHERE LOWER(TRIM(status))='active'").fetchone()[0],
            "pending_doctors": conn.execute("SELECT COUNT(*) FROM doctors WHERE LOWER(TRIM(status))='pending'").fetchone()[0],
            "appointments": conn.execute("SELECT COUNT(*) FROM appointments").fetchone()[0],
            "pending_appointments": conn.execute("SELECT COUNT(*) FROM appointments WHERE status='Pending'").fetchone()[0],
            "consultations": conn.execute("SELECT COUNT(*) FROM consultation_requests").fetchone()[0],
        }
    return render_template("admin_dashboard.html", patients=patients, doctors=doctors,
                           appointments=appointments, stats=stats)

@app.route("/admin/doctor/<int:doctor_id>/<decision>", methods=["POST"])
@admin_login_required
def admin_doctor_decision(doctor_id, decision):
    if not valid_csrf():
        return "Invalid CSRF token", 400
    transitions = {
        "pending": {"approve": ("Active", "Doctor account approved."),
                    "reject": ("Rejected", "Doctor account rejected.")},
        "active": {"deactivate": ("Inactive", "Doctor account deactivated.")},
        "inactive": {"activate": ("Active", "Doctor account activated.")},
        "rejected": {"reconsider": ("Pending", "Doctor account returned to Pending review.")},
    }
    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        doctor = conn.execute("SELECT status FROM doctors WHERE id=?", (doctor_id,)).fetchone()
        if doctor is None:
            flash("Doctor account not found.", "warning")
            return redirect(url_for("admin_dashboard"))
        current_status = (doctor["status"] or "").strip().lower()
        transition = transitions.get(current_status, {}).get(decision)
        if transition is None:
            return "Invalid action for the doctor's current status.", 400
        new_status, message = transition
        conn.execute("UPDATE doctors SET status=? WHERE id=?", (new_status, doctor_id))
    flash(message, "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/patient/<int:patient_id>/status", methods=["POST"])
@admin_login_required
def admin_patient_status(patient_id):
    if not valid_csrf():
        return "Invalid CSRF token", 400
    status = request.form.get("status", "")
    if status not in ("Active", "Inactive"):
        return "Invalid patient status", 400
    with get_db() as conn:
        cursor = conn.execute("UPDATE patients SET status=? WHERE id=?", (status, patient_id))
    flash("Patient account updated." if cursor.rowcount else "Patient account not found.", "success" if cursor.rowcount else "warning")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/appointment/<int:appointment_id>/cancel", methods=["POST"])
@admin_login_required
def admin_cancel_appointment(appointment_id):
    if not valid_csrf():
        return "Invalid CSRF token", 400
    with get_db() as conn:
        cursor = conn.execute("""UPDATE appointments SET status='Cancelled',updated_at=CURRENT_TIMESTAMP
            WHERE id=? AND status IN ('Pending','Accepted','Reschedule Requested')""", (appointment_id,))
    if cursor.rowcount:
        flash("Appointment cancelled by hospital administration.", "success")
    else:
        flash("Appointment was not found or cannot be cancelled in its current state.", "warning")
    return redirect(url_for("admin_dashboard"))

@app.route("/")
def home(): return render_template("index.html")

@app.route("/language/<language>")
def set_language(language):
    if language not in ("en", "te"):
        abort(404)
    session["language"] = language
    target = request.args.get("next", "")
    try:
        parsed_target = urlsplit(target)
        safe_local_target = (
            target.startswith("/") and not target.startswith("//") and "\\" not in target
            and not parsed_target.scheme and not parsed_target.netloc
            and not any(ord(character) < 32 for character in target)
        )
    except ValueError:
        safe_local_target = False
    if not safe_local_target:
        target = url_for("home")
    return redirect(target)

@app.route("/internal/appointment-reminders", methods=["POST"])
def internal_appointment_reminders():
    expected = os.environ.get("REMINDER_JOB_TOKEN", "")
    provided = request.headers.get("Authorization", "")
    if not expected:
        return jsonify(error="Reminder job is not configured."), 503
    if not provided.startswith("Bearer ") or not hmac.compare_digest(provided[7:], expected):
        return jsonify(error="Unauthorized."), 401
    return jsonify(created=process_appointment_reminders())

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not valid_csrf():
            return render_template("register.html", error="Your session expired. Reload the page and try again.", form={}), 400
        data = {key: request.form.get(key, "").strip() for key in ("full_name", "email", "phone", "age", "gender", "blood_group", "address")}
        data["email"] = normalize_email(data["email"]); password = request.form.get("password", ""); confirm = request.form.get("confirm_password", "")
        if not all(data.values()) or not password or not confirm: return render_template("register.html", error="Please fill all required fields.", form=data)
        if not is_valid_email(data["email"]):
            return render_template("register.html", error="Please enter a valid email address.", form=data)
        if not request.form.get("terms"): return render_template("register.html", error="You must accept the Terms & Conditions.", form=data)
        try:
            age = int(data["age"])
            if not 1 <= age <= 120: raise ValueError
        except ValueError: return render_template("register.html", error="Please enter a valid age between 1 and 120.", form=data)
        if password != confirm: return render_template("register.html", error="Passwords do not match.", form=data)
        if len(password) < 8: return render_template("register.html", error="Password must contain at least 8 characters.", form=data)
        try:
            with get_db() as conn:
                cursor = conn.execute("INSERT INTO patients (full_name,email,phone,age,gender,blood_group,address,password) VALUES (?,?,?,?,?,?,?,?)", (data["full_name"], data["email"], data["phone"], age, data["gender"], data["blood_group"], data["address"], generate_password_hash(password)))
                public_id = public_identifier(conn, "patients", "patient_id", "PAT", cursor.lastrowid)
                conn.execute("UPDATE patients SET patient_id=? WHERE id=?", (public_id, cursor.lastrowid))
        except sqlite3.IntegrityError: return render_template("register.html", error="An account with this email already exists.", form=data)
        except sqlite3.Error: return render_template("register.html", error="Database error. Please try again.", form=data)
        flash(f"Registration successful. Your Patient ID is {public_id}. Please log in.", "success"); return redirect(url_for("login"))
    return render_template("register.html", form={})

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not valid_csrf():
            return render_template("login.html", error="Your session expired. Reload the page and try again."), 400
        submitted_login = (request.form.get("email") or request.form.get("patient_id") or "").strip()
        password = request.form.get("password", "")
        if not submitted_login:
            return render_template("login.html", error="Enter your email address or Patient ID.")
        if "@" in submitted_login:
            email = normalize_email(submitted_login)
            if not is_valid_email(email):
                return render_template("login.html", error="Enter a valid email address.")
            with get_db() as conn:
                matches = conn.execute("""SELECT id,patient_id,full_name,email,password,status FROM patients
                    WHERE LOWER(TRIM(email))=? ORDER BY id LIMIT 2""", (email,)).fetchall()
            if not matches:
                return render_template("login.html", error="No patient account is registered with that email address.")
            if len(matches) > 1:
                return render_template("login.html", error="This email matches multiple patient accounts. Contact the hospital administrator.")
            patient = matches[0]
        else:
            public_id = submitted_login.upper()
            if not re.fullmatch(r"PAT-\d+", public_id):
                return render_template("login.html", error="Enter a valid email address or Patient ID.")
            with get_db() as conn:
                patient = conn.execute("SELECT id,patient_id,full_name,email,password,status FROM patients WHERE UPPER(TRIM(patient_id))=?", (public_id,)).fetchone()
            if patient is None:
                return render_template("login.html", error="No patient account is registered with that Patient ID.")
        if not password:
            return render_template("login.html", error="Enter your password.")
        if not password_matches(patient["password"], password):
            return render_template("login.html", error="Incorrect password.")
        if (patient["status"] or "").strip().lower() != "active":
            return render_template("login.html", error="This patient account is inactive. Contact the hospital administrator.")
        # Upgrade a legacy plaintext password only after the correct password is supplied.
        if not patient["password"].startswith(("pbkdf2:", "scrypt:")):
            with get_db() as conn:
                conn.execute("UPDATE patients SET password=? WHERE id=?", (generate_password_hash(password), patient["id"]))
        clear_patient_session(); clear_doctor_session(); clear_admin_session(); session.update(patient_id=patient["patient_id"], patient_database_id=patient["id"], patient_name=patient["full_name"], patient_email=patient["email"]); return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    if not valid_csrf():
        return "Invalid CSRF token", 400
    clear_patient_session()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    with get_db() as conn:
        appointments = conn.execute("""SELECT a.*,d.full_name doctor_name,d.specialization,
            c.id consultation_id,c.status consultation_status,c.meeting_url consultation_link
            FROM appointments a JOIN doctors d ON d.id=a.doctor_id
            LEFT JOIN consultation_requests c ON c.appointment_id=a.id
            WHERE a.patient_id=? ORDER BY a.appointment_date DESC,a.appointment_time DESC""", (session["patient_database_id"],)).fetchall()
        reminders = conn.execute("""SELECT id,notification_text,created_at,read_at FROM appointment_reminders
            WHERE patient_id=? ORDER BY created_at DESC,id DESC LIMIT 10""", (session["patient_database_id"],)).fetchall()
    return render_template("patient_dashboard.html", patient_name=session.get("patient_name", "Patient"),
                           public_patient_id=session.get("patient_id"), appointments=appointments, reminders=reminders)

@app.route("/prediction", methods=["GET", "POST"])
@login_required
def prediction():
    choices = symptom_choices()
    if request.method == "GET": return render_template("prediction.html", symptom_choices=choices, selected_symptoms=[])
    if not valid_csrf():
        return render_template("prediction.html", symptom_choices=choices, selected_symptoms=[], error="Your session expired. Reload the page and try again."), 400
    selected = request.form.getlist("symptom")
    free_text = request.form.get("symptoms", "").strip()
    raw = ",".join(selected + ([free_text] if free_text else []))
    if not raw: return render_template("prediction.html", symptom_choices=choices, selected_symptoms=selected, error="Select or enter at least one symptom.")
    entered_count = len([item for item in re.split(r"[,;，；\n]+", raw) if item.strip()])
    if entered_count > 20: return render_template("prediction.html", symptom_choices=choices, selected_symptoms=selected, error="Choose no more than 20 symptoms.")
    if model is None or not MODEL_FEATURES: return render_template("prediction.html", symptom_choices=choices, selected_symptoms=selected, error="Disease model is unavailable. Please try again later.")
    entered, matched, unknown = match_symptoms(raw)
    if not matched: return render_template("prediction.html", symptom_choices=choices, selected_symptoms=selected, error="No matching symptoms found. Choose a listed symptom or check your spelling.", unknown_symptoms=unknown)
    try:
        top_predictions = rank_diseases(matched)
        if not top_predictions:
            raise ValueError("No model prediction was produced.")
        disease = top_predictions[0]["disease"]
        confidence = top_predictions[0]["vote_share"]
    except Exception as error:
        print(f"PREDICTION ERROR: {error}"); return render_template("prediction.html", symptom_choices=choices, selected_symptoms=selected, error="Prediction failed. Please try again.")
    explanations = explain_rankings(top_predictions, matched)
    model_score_ratio = confidence / 100 if confidence is not None else 0
    normalized_symptoms = {item.replace("_", " ").lower() for item in matched}
    low_confidence = confidence is None or model_score_ratio < LOW_MODEL_SCORE_THRESHOLD
    insufficient_symptoms = len(set(matched)) < MIN_RECOGNIZED_SYMPTOMS
    general_symptoms = bool(normalized_symptoms) and normalized_symptoms.issubset(GENERAL_EVALUATION_SYMPTOMS)
    # The model label only maps to a department; it is not a clinical referral.
    department = department_for_disease(disease)
    with get_db() as conn:
        recommended = registered_doctors(conn, department, disease)
    doctor = recommended[0]["full_name"] if recommended else None
    doctor_id = recommended[0]["id"] if recommended else None
    doctor_specialization = recommended[0]["specialization"] if recommended else None
    doctor_experience = recommended[0]["experience"] if recommended else None
    doctor_availability = recommended[0]["availability"] if recommended else None
    symptoms = ", ".join(x.replace("_", " ") for x in dict.fromkeys(matched))
    emergency_alert = emergency_risk(raw, matched)
    with get_db() as conn:
        prediction_cursor = conn.execute("""INSERT INTO prediction_history
            (patient_id,symptoms,disease,confidence,department,doctor,top_predictions)
            VALUES (?,?,?,?,?,?,?)""", (session["patient_database_id"], symptoms, disease, confidence, department,
            doctor or "No registered doctor available", json.dumps(top_predictions, ensure_ascii=False)))
    prediction_history_id = prediction_cursor.lastrowid
    chest_pain_entered = "chest_pain" in matched
    session["last_prediction"] = {"disease":disease, "confidence":confidence, "department":department, "doctor":doctor, "doctor_id":doctor_id, "doctor_specialization":doctor_specialization, "doctor_experience":doctor_experience, "doctor_availability":doctor_availability, "matched_symptoms":symptoms, "unknown_symptoms":unknown, "low_confidence":low_confidence, "insufficient_symptoms":insufficient_symptoms, "general_evaluation":general_symptoms, "top_predictions":top_predictions, "explanations":explanations, "emergency_alert":emergency_alert, "chest_pain_entered":chest_pain_entered, "prediction_history_id":prediction_history_id}
    return redirect(url_for("result"))

@app.route("/result")
@login_required
def result():
    data = session.get("last_prediction")
    if not data: flash("Make a prediction to see its result.", "warning"); return redirect(url_for("prediction"))
    with get_db() as conn:
        doctors, alternative_doctors = doctor_recommendations(conn, data["department"], data["disease"])
    hospital_location = (request.args.get("location") or "").strip()[:120]
    return render_template("result.html", doctors=doctors, alternative_doctors=alternative_doctors,
                           hospital_location=hospital_location,
                           hospital_search_url=google_maps_hospital_search(hospital_location),
                           hospital_department=data["department"], **data)


@app.route("/api/hospitals/search")
def hospital_search_api():
    if not session.get("patient_database_id"):
        return jsonify({"error": "Please log in as a patient to search hospitals."}), 401
    location = (request.args.get("location") or "").strip()
    if not valid_hospital_search_location(location):
        return jsonify({"error": "Enter a city or location using letters, numbers, spaces, or basic punctuation (up to 120 characters)."}), 400
    department = (request.args.get("department") or "").strip()[:80]
    try:
        result = search_osm_hospitals(location, department)
    except HospitalLocationError as exc:
        return jsonify({"error": str(exc), "fallback_url": google_maps_hospital_search(location)}), 400
    except HospitalSearchError as exc:
        return jsonify({"error": str(exc), "fallback_url": google_maps_hospital_search(location)}), 502
    return jsonify({**result, "fallback_url": google_maps_hospital_search(location),
                    "attribution": "Hospital listing data © OpenStreetMap contributors (ODbL). Not verified by this application."})

@app.route("/history")
@login_required
def history():
    with get_db() as conn: predictions = conn.execute("SELECT id,created_at,symptoms,disease,confidence,department,doctor FROM prediction_history WHERE patient_id=? ORDER BY datetime(created_at) DESC,id DESC", (session["patient_database_id"],)).fetchall()
    return render_template("history.html", predictions=predictions)

@app.route("/history/<int:prediction_id>/report")
@login_required
def download_health_report(prediction_id):
    with get_db() as conn:
        report = conn.execute("""SELECT h.id,h.created_at,h.symptoms,h.disease,h.confidence,h.department,h.top_predictions,
            p.patient_id,p.full_name,p.email,p.age,p.gender
            FROM prediction_history h JOIN patients p ON p.id=h.patient_id
            WHERE h.id=? AND h.patient_id=?""", (prediction_id, session["patient_database_id"])).fetchone()
    if not report:
        abort(404)
    saved_predictions = []
    if report["top_predictions"]:
        try:
            saved_predictions = json.loads(report["top_predictions"])
        except (TypeError, json.JSONDecodeError):
            saved_predictions = []
    if not saved_predictions:
        saved_predictions = [{
            "disease": report["disease"], "vote_share": report["confidence"],
            "department": report["department"],
        }]
    matched = match_symptoms(report["symptoms"])[1]
    explanations = explain_rankings(saved_predictions, matched)
    lines = [
        "AI Smart Hospital Assistant - Patient Health Report",
        "Educational decision-support report; not a medical diagnosis.",
        "",
        pdf_text_line("Patient", report["full_name"]),
        pdf_text_line("Patient ID", report["patient_id"]),
        pdf_text_line("Email", report["email"]),
        pdf_text_line("Age / gender", f"{report['age']} / {report['gender'] or 'Not provided'}"),
        pdf_text_line("Report date", datetime.now().strftime("%Y-%m-%d %H:%M")),
        pdf_text_line("Prediction record date", report["created_at"]),
        pdf_text_line("Symptoms", report["symptoms"]),
        "",
        "Model rankings (scores are model outputs, not medical probabilities):",
    ]
    for rank, item in enumerate(saved_predictions[:3], 1):
        score = item.get("vote_share", item.get("confidence"))
        score_text = f"{score}% model score" if score is not None else "model score unavailable"
        lines.append(f"{rank}. {item.get('disease', 'Unknown label')} - {score_text} - {item.get('department', 'General Medicine')}")
    lines.extend(["", "Training-data associations and model feature importance (not causal explanations):"])
    for explanation in explanations:
        lines.append(f"{explanation['disease']}:")
        for item in explanation["symptoms"]:
            lines.append(
                f"  {item['name']}: present in {item['training_rate']}% of this label's training rows; "
                f"global feature importance {item['importance']}%."
            )
    lines.extend([
        "",
        "Emergency symptoms require urgent assessment. Do not wait for or rely on this model output.",
        "This report is for informational support only and does not confirm a condition or replace a clinician.",
    ])
    pdf = create_pdf(lines)
    return send_file(BytesIO(pdf), mimetype="application/pdf", as_attachment=True,
                     download_name=f"health-report-{report['patient_id']}-{report['id']}.pdf")

@app.route("/notifications")
@login_required
def patient_notifications():
    with get_db() as conn:
        notifications = conn.execute("""SELECT id,notification_text,created_at,read_at FROM appointment_reminders
            WHERE patient_id=? ORDER BY created_at DESC,id DESC LIMIT 100""", (session["patient_database_id"],)).fetchall()
    return render_template("notifications.html", notifications=notifications)

@app.route("/notifications/<int:notification_id>/read", methods=["POST"])
@login_required
def mark_notification_read(notification_id):
    if not valid_csrf():
        return "Invalid CSRF token", 400
    with get_db() as conn:
        conn.execute("""UPDATE appointment_reminders SET read_at=COALESCE(read_at,CURRENT_TIMESTAMP)
            WHERE id=? AND patient_id=?""", (notification_id, session["patient_database_id"]))
    return redirect(url_for("patient_notifications"))

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    patient_id = session["patient_database_id"]
    if request.method == "POST":
        if not valid_csrf():
            return "Invalid CSRF token", 400
        data = {key: request.form.get(key, "").strip() for key in ("full_name", "phone", "age", "gender", "blood_group", "address")}
        try:
            age = int(data["age"])
            if not data["full_name"] or not data["phone"] or not 1 <= age <= 120: raise ValueError
        except ValueError:
            data["email"] = session["patient_email"]; return render_template("profile.html", patient=data, editing=True, error="Enter a name, phone number, and valid age (1–120).")
        with get_db() as conn: conn.execute("UPDATE patients SET full_name=?,phone=?,age=?,gender=?,blood_group=?,address=? WHERE id=?", (data["full_name"], data["phone"], age, data["gender"], data["blood_group"], data["address"], patient_id))
        session["patient_name"] = data["full_name"]; flash("Profile updated successfully.", "success"); return redirect(url_for("profile"))
    with get_db() as conn: patient = conn.execute("SELECT full_name,email,phone,age,gender,blood_group,address FROM patients WHERE id=?", (patient_id,)).fetchone()
    return render_template("profile.html", patient=patient, editing=request.args.get("edit") == "1")

@app.route("/appointments")
@app.route("/my-appointments")
@login_required
def appointments():
    with get_db() as conn:
        items = conn.execute("""SELECT a.*,d.full_name doctor_name,d.specialization,
            c.id consultation_id,c.status consultation_status,c.meeting_url consultation_link
            FROM appointments a JOIN doctors d ON d.id=a.doctor_id
            LEFT JOIN consultation_requests c ON c.appointment_id=a.id
            WHERE a.patient_id=? ORDER BY a.appointment_date DESC,a.appointment_time DESC""", (session["patient_database_id"],)).fetchall()
    return render_template("appointments.html", appointments=items)

@app.route("/appointment/<int:appointment_id>/consultation", methods=["POST"])
@login_required
def request_online_consultation(appointment_id):
    if not valid_csrf():
        return "Invalid CSRF token", 400
    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        appointment = conn.execute("""SELECT a.id,a.patient_id,a.doctor_id,a.status appointment_status,d.status doctor_status
            FROM appointments a JOIN doctors d ON d.id=a.doctor_id
            WHERE a.id=? AND a.patient_id=?""", (appointment_id, session["patient_database_id"])).fetchone()
        if not appointment or appointment["appointment_status"] not in ("Pending", "Accepted") or (appointment["doctor_status"] or "").strip().lower() != "active":
            flash("Online consultation is unavailable for this appointment.", "warning")
            return redirect(url_for("appointments"))
        existing = conn.execute("SELECT id,status FROM consultation_requests WHERE appointment_id=?", (appointment_id,)).fetchone()
        if existing and existing["status"] != "Rejected":
            flash("A consultation request already exists for this appointment.", "info")
            return redirect(url_for("appointments"))
        if existing:
            conn.execute("""UPDATE consultation_requests SET status='Pending',meeting_url=NULL,doctor_message=NULL,
                created_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?""", (existing["id"],))
        else:
            conn.execute("""INSERT INTO consultation_requests (appointment_id,patient_id,doctor_id)
                VALUES (?,?,?)""", (appointment_id, appointment["patient_id"], appointment["doctor_id"]))
    flash("Online consultation request sent to the doctor.", "success")
    return redirect(url_for("appointments"))

@app.route("/doctor/consultation/<int:consultation_id>/<action>", methods=["POST"])
@doctor_login_required
def doctor_consultation_action(consultation_id, action):
    if not valid_csrf():
        return "Invalid CSRF token", 400
    if action not in ("accept", "reject"):
        return "Invalid consultation action.", 400
    meeting_url = request.form.get("meeting_url", "").strip() if action == "accept" else ""
    if action == "accept" and not valid_meeting_url(meeting_url):
        flash("Enter an HTTPS link from your configured external consultation provider.", "danger")
        return redirect(url_for("doctor_dashboard"))
    new_status = "Accepted" if action == "accept" else "Rejected"
    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        consultation = conn.execute("""SELECT id FROM consultation_requests
            WHERE id=? AND doctor_id=? AND status='Pending'""",
            (consultation_id, session["doctor_database_id"])).fetchone()
        if not consultation:
            flash("Consultation request not found or already handled.", "warning")
            return redirect(url_for("doctor_dashboard"))
        conn.execute("""UPDATE consultation_requests SET status=?,meeting_url=?,doctor_message=?,
            updated_at=CURRENT_TIMESTAMP WHERE id=?""",
            (new_status, meeting_url or None, request.form.get("doctor_message", "").strip(), consultation_id))
    flash("Consultation request " + new_status.lower() + "." if action == "accept" else "Consultation request rejected.", "success")
    return redirect(url_for("doctor_dashboard"))

@app.route("/book-appointment", methods=["GET", "POST"])
@app.route("/confirm-appointment", methods=["POST"])
@login_required
def book_appointment():
    prediction = session.get("last_prediction")
    if request.method == "POST" and not valid_csrf():
        return "Invalid CSRF token", 400
    if not prediction:
        flash("Please make a disease prediction before booking an appointment.", "warning")
        return redirect(url_for("prediction"))
    selected_doctor_id = request.values.get("doctor_id", type=int)
    selected_date = (request.values.get("appointment_date") or request.args.get("date") or "").strip()
    location = (request.values.get("location") or "").strip()[:120]
    error = None
    with get_db() as conn:
        if request.method == "POST":
            conn.execute("BEGIN IMMEDIATE")
            if not selected_doctor_id:
                error = "Select an Active doctor before booking."
            elif not selected_date:
                error = "Choose an appointment date."
            elif request.form.get("consultation_type") not in ("In-person", "Online"):
                error = "Choose In-person or Online consultation."
            else:
                matching, alternatives = doctor_recommendations(conn, prediction["department"], prediction["disease"])
                candidates = matching or alternatives
                selected_doctor = next((item for item in candidates if item["id"] == selected_doctor_id), None)
                if selected_doctor is None:
                    error = "The selected doctor is no longer Active or eligible for this recommendation."
                else:
                    appointment_time = (request.form.get("appointment_time") or "").strip()
                    available = available_doctor_slots(conn, selected_doctor, selected_date)
                    if appointment_time not in available:
                        error = "That slot is no longer available. Choose one of the currently open times."
                    else:
                        reason = request.form.get("reason", "").strip()
                        notes = request.form.get("patient_notes", "").strip()
                        consultation_type = request.form["consultation_type"]
                        cursor = conn.execute("""INSERT INTO appointments
                            (patient_id,doctor_id,disease,department,symptoms,appointment_date,appointment_time,
                             reason,patient_notes,consultation_type)
                            VALUES (?,?,?,?,?,?,?,?,?,?)""",
                            (session["patient_database_id"], selected_doctor_id, prediction["disease"],
                             prediction["department"], prediction.get("matched_symptoms", ""), selected_date,
                             appointment_time, reason, notes, consultation_type))
                        appointment_id = cursor.lastrowid
                        if consultation_type == "Online":
                            conn.execute("INSERT INTO consultation_requests (appointment_id,patient_id,doctor_id) VALUES (?,?,?)",
                                         (appointment_id, session["patient_database_id"], selected_doctor_id))
                        return render_template("appointment_confirmation.html", appointment_id=appointment_id,
                            doctor=selected_doctor, prediction=prediction, appointment_date=selected_date,
                            appointment_time=appointment_time, consultation_type=consultation_type)

        matching, alternatives = doctor_recommendations(conn, prediction["department"], prediction["disease"])
        candidate_list = matching or alternatives
        selected_doctor = next((item for item in candidate_list if item["id"] == selected_doctor_id), None)
        available_slots = available_doctor_slots(conn, selected_doctor, selected_date) if selected_doctor and selected_date else []
        location_candidates = [dict(item) for item in candidate_list]
    return render_template("book_appointment.html", prediction=prediction, doctor=selected_doctor,
        doctors=matching, alternative_doctors=alternatives, candidate_doctors=location_candidates,
        selected_date=selected_date, available_slots=available_slots, consultation_type=request.values.get("consultation_type", "In-person"),
        hospital_location=location, hospital_search_url=google_maps_hospital_search(location),
        hospital_department=prediction["department"],
        today=date.today().isoformat(), error=error)

@app.route("/appointment/<int:appointment_id>/reschedule", methods=["GET", "POST"])
@login_required
def patient_reschedule(appointment_id):
    if request.method == "POST" and not valid_csrf():
        return "Invalid CSRF token", 400
    with get_db() as conn:
        item = conn.execute("""SELECT a.*,d.full_name doctor_name,d.availability doctor_availability FROM appointments a JOIN doctors d ON d.id=a.doctor_id WHERE a.id=? AND a.patient_id=?""", (appointment_id, session["patient_database_id"])).fetchone()
        if not item: flash("Appointment not found.", "danger"); return redirect(url_for("appointments"))
        if request.method == "POST":
            new_date, new_time = request.form.get("appointment_date", ""), request.form.get("appointment_time", "")
            valid, error = doctor_availability_is_valid(item["doctor_availability"], new_date, new_time)
            if not valid: return render_template("reschedule_appointment.html", appointment=item, error=error)
            conn.execute("INSERT INTO appointment_reschedule_requests (appointment_id,requested_by,requested_date,requested_time,reason) VALUES (?,?,?,?,?)", (appointment_id,"Patient",new_date,new_time,request.form.get("reason", "").strip()))
            conn.execute("UPDATE appointments SET status='Reschedule Requested',updated_at=CURRENT_TIMESTAMP WHERE id=?", (appointment_id,))
            flash("Your reschedule request was sent to the doctor.", "success"); return redirect(url_for("appointments"))
    return render_template("reschedule_appointment.html", appointment=item)

@app.route("/doctor-register", methods=["GET", "POST"])
def doctor_register():
    if request.method == "POST":
        if not valid_csrf():
            return render_template("doctor_register.html", error="Your session expired. Reload the page and try again.", form={}), 400
        data = {key: request.form.get(key, "").strip() for key in ("email", "phone", "department", "specialization", "qualification", "experience")}
        data["full_name"] = request.form.get("name", "").strip()
        data["email"] = normalize_email(data["email"])
        password, confirm = request.form.get("password", ""), request.form.get("confirm_password", "")
        if not all(data.values()) or not password or not confirm:
            return render_template("doctor_register.html", error="Please fill all required fields.", form=data)
        if not is_valid_email(data["email"]):
            return render_template("doctor_register.html", error="Please enter a valid email address.", form=data)
        try:
            experience = int(data["experience"])
            if experience < 0: raise ValueError
        except ValueError:
            return render_template("doctor_register.html", error="Experience must be a valid number.", form=data)
        if password != confirm: return render_template("doctor_register.html", error="Passwords do not match.", form=data)
        if len(password) < 8: return render_template("doctor_register.html", error="Password must contain at least 8 characters.", form=data)
        try:
            with get_db() as conn:
                cursor = conn.execute("""INSERT INTO doctors (full_name,email,phone,password,department,specialization,experience,qualification,availability,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,'Pending',CURRENT_TIMESTAMP)""", (data["full_name"], data["email"], data["phone"], generate_password_hash(password), data["department"], data["specialization"], experience, data["qualification"], "Monday - Friday, 09:00 - 17:00"))
                public_id = public_identifier(conn, "doctors", "doctor_id", "DOC", cursor.lastrowid)
                conn.execute("UPDATE doctors SET doctor_id=? WHERE id=?", (public_id, cursor.lastrowid))
        except sqlite3.IntegrityError:
            return render_template("doctor_register.html", error="A doctor with this email already exists.", form=data)
        except sqlite3.Error as error:
            print(f"DOCTOR REGISTRATION ERROR: {error}")
            return render_template("doctor_register.html", error="Unable to register doctor. Please try again.", form=data)
        flash("Registration submitted. Your account will be available after administrator approval.", "success")
        return redirect(url_for("doctor_login"))
    return render_template("doctor_register.html", form={})

@app.route("/doctor-login", methods=["GET", "POST"])
@app.route("/doctor/login", methods=["GET", "POST"])
def doctor_login():
    if request.method == "POST":
        if not valid_csrf():
            return render_template("doctor_login.html", error="Your session expired. Reload the page and try again."), 400
        email, password = normalize_email(request.form.get("email", "")), request.form.get("password", "")
        if not email or not is_valid_email(email):
            return render_template("doctor_login.html", error="Enter a valid email address.")
        if not password:
            return render_template("doctor_login.html", error="Enter your password.")
        with get_db() as conn:
            matches = conn.execute("SELECT * FROM doctors WHERE LOWER(TRIM(email))=? ORDER BY id LIMIT 2", (email,)).fetchall()
        if not matches:
            return render_template("doctor_login.html", error="No doctor account is registered with that email address.")
        if len(matches) > 1:
            return render_template("doctor_login.html", error="This email matches multiple doctor accounts. Contact the hospital administrator.")
        doctor = matches[0]
        if not password_matches(doctor["password"], password):
            return render_template("doctor_login.html", error="Incorrect password.")
        if (doctor["status"] or "").strip().lower() != "active":
            if (doctor["status"] or "").strip().lower() == "pending":
                return render_template("doctor_login.html", error="Your doctor account is awaiting administrator approval.")
            return render_template("doctor_login.html", error="Your doctor account is not active. Contact the hospital administrator.")
        if not doctor["password"].startswith(("pbkdf2:", "scrypt:")):
            with get_db() as conn:
                conn.execute("UPDATE doctors SET password=? WHERE id=?", (generate_password_hash(password), doctor["id"]))
        clear_patient_session(); clear_doctor_session(); clear_admin_session(); session.update(doctor_id=doctor["doctor_id"], doctor_database_id=doctor["id"], doctor_name=doctor["full_name"], doctor_email=doctor["email"], doctor_department=doctor["department"]); return redirect(url_for("doctor_dashboard"))
    return render_template("doctor_login.html")

@app.route("/doctor-logout", methods=["POST"])
@app.route("/doctor/logout", methods=["POST"])
def doctor_logout():
    if not valid_csrf():
        return "Invalid CSRF token", 400
    clear_doctor_session()
    flash("Doctor session ended.", "success"); return redirect(url_for("doctor_login"))

def doctor_appointments():
    with get_db() as conn:
        return conn.execute("""SELECT a.*,p.patient_id public_patient_id,p.full_name patient_name,p.email patient_email,
            p.phone patient_phone,p.age patient_age,p.gender patient_gender,
            c.id consultation_id,c.status consultation_status,c.meeting_url consultation_link
            FROM appointments a JOIN patients p ON p.id=a.patient_id
            LEFT JOIN consultation_requests c ON c.appointment_id=a.id
            WHERE a.doctor_id=? ORDER BY a.appointment_date,a.appointment_time""", (session["doctor_database_id"],)).fetchall()

@app.route("/doctor-dashboard")
@app.route("/doctor/dashboard")
@doctor_login_required
def doctor_dashboard():
    with get_db() as conn: doctor = conn.execute("SELECT doctor_id,department,specialization,qualification,experience,email FROM doctors WHERE id=?", (session["doctor_database_id"],)).fetchone()
    items = doctor_appointments(); today = date.today().isoformat()
    counts = {"Total": len(items), **{status: sum(item["status"] == status for item in items) for status in ("Pending", "Accepted", "Declined", "Reschedule Requested", "Completed")}}
    return render_template("doctor_dashboard.html", doctor=doctor, appointments=items, today=today, counts=counts)

@app.route("/doctor/appointments")
@doctor_login_required
def doctor_appointments_page(): return render_template("doctor_dashboard.html", doctor=None, appointments=doctor_appointments(), today=date.today().isoformat(), counts={})

@app.route("/doctor/profile")
@doctor_login_required
def doctor_profile():
    with get_db() as conn:
        doctor = conn.execute("SELECT doctor_id,full_name,email,phone,department,specialization,experience,qualification,availability FROM doctors WHERE id=?", (session["doctor_database_id"],)).fetchone()
    return render_template("doctor_profile.html", doctor=doctor)

@app.route("/doctor/search-patient", methods=["POST"])
@doctor_login_required
def doctor_search_patient():
    if not valid_csrf():
        return "Invalid CSRF token", 400
    public_id = request.form.get("patient_id", "").strip().upper()
    if not public_id:
        flash("Enter a Patient ID to search.", "warning")
        return redirect(url_for("doctor_dashboard"))
    return redirect(url_for("doctor_patient_history", patient_id=public_id))

@app.route("/doctor/patient/<patient_id>")
@doctor_login_required
def doctor_patient_history(patient_id):
    public_id = patient_id.strip().upper()
    with get_db() as conn:
        patient_matches = conn.execute(
            "SELECT id FROM patients WHERE UPPER(TRIM(patient_id))=? ORDER BY id LIMIT 2",
            (public_id,),
        ).fetchall()
        if not patient_matches:
            flash("Patient not found.", "danger")
            return redirect(url_for("doctor_dashboard"))

        if len(patient_matches) > 1:
            flash("Multiple patient records match this ID. Contact the hospital administrator.", "danger")
            return redirect(url_for("doctor_dashboard"))

        database_id = patient_matches[0]["id"]
        authorized = conn.execute("""SELECT 1 FROM appointments
            WHERE patient_id=? AND doctor_id=?
              AND status IN ('Pending','Accepted','Reschedule Requested','Completed')
            LIMIT 1""", (database_id, session["doctor_database_id"])).fetchone()
        if not authorized:
            flash("No authorized patient record is available to your care team.", "warning")
            return redirect(url_for("doctor_dashboard"))

        patient = conn.execute("""SELECT patient_id,full_name,email,phone,age,gender,blood_group,address,id
            FROM patients WHERE id=?""", (database_id,)).fetchone()
        predictions = conn.execute("SELECT created_at,symptoms,disease,confidence,department,doctor FROM prediction_history WHERE patient_id=? ORDER BY created_at DESC", (database_id,)).fetchall()
        appointments = conn.execute("""SELECT a.*,d.full_name doctor_name FROM appointments a JOIN doctors d ON d.id=a.doctor_id
            WHERE a.patient_id=? AND a.doctor_id=? ORDER BY a.appointment_date DESC,a.appointment_time DESC""",
            (database_id, session["doctor_database_id"])).fetchall()
    return render_template("doctor_patient_history.html", patient=patient, predictions=predictions, appointments=appointments)

@app.route("/doctor/appointment/<int:appointment_id>/<action>", methods=["POST"])
@doctor_login_required
def update_appointment(appointment_id, action):
    statuses = {"accept":"Accepted", "decline":"Declined", "complete":"Completed"}
    if not valid_csrf():
        return "Invalid CSRF token", 400
    with get_db() as conn:
        if action == "reschedule":
            conn.execute("BEGIN IMMEDIATE")
        item = conn.execute("""SELECT a.id,d.availability FROM appointments a JOIN doctors d ON d.id=a.doctor_id
                            WHERE a.id=? AND a.doctor_id=?""", (appointment_id,session["doctor_database_id"])).fetchone()
        if not item: flash("Appointment not found.", "danger"); return redirect(url_for("doctor_dashboard"))
        if action in statuses:
            message = request.form.get("doctor_message", request.form.get("doctor_notes", "")).strip()
            conn.execute("UPDATE appointments SET status=?,doctor_notes=?,doctor_message=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (statuses[action],message,message,appointment_id))
        elif action == "reschedule":
            new_date,new_time=request.form.get("appointment_date", ""),request.form.get("appointment_time", "")
            valid, error = doctor_availability_is_valid(item["availability"], new_date, new_time)
            if not valid: flash(error, "danger"); return redirect(url_for("doctor_dashboard"))
            occupied = conn.execute("""SELECT 1 FROM appointments WHERE doctor_id=? AND appointment_date=?
                AND appointment_time=? AND id<>? AND status NOT IN ('Declined','Cancelled') LIMIT 1""",
                (session["doctor_database_id"], new_date, new_time, appointment_id)).fetchone()
            if occupied:
                flash("That appointment time is already booked. Choose another available time.", "danger")
                return redirect(url_for("doctor_dashboard"))
            conn.execute("INSERT INTO appointment_reschedule_requests (appointment_id,requested_by,requested_date,requested_time,reason,status) VALUES (?,?,?,?,?,'Accepted')", (appointment_id,"Doctor",new_date,new_time,request.form.get("reason", "").strip()))
            message = request.form.get("doctor_message", request.form.get("reason", "")).strip()
            conn.execute("UPDATE appointments SET original_date=COALESCE(original_date,appointment_date),original_time=COALESCE(original_time,appointment_time),proposed_date=?,proposed_time=?,status='Reschedule Requested',doctor_message=?,doctor_notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (new_date,new_time,message,message,appointment_id))
        else: flash("Invalid appointment action.", "danger"); return redirect(url_for("doctor_dashboard"))
    flash("Appointment updated.", "success"); return redirect(url_for("doctor_dashboard"))

@app.route("/patient/appointment/<int:appointment_id>/accept-reschedule", methods=["POST"])
@login_required
def accept_reschedule(appointment_id):
    if not valid_csrf():
        return "Invalid CSRF token", 400
    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        item = conn.execute("SELECT id,doctor_id,proposed_date,proposed_time FROM appointments WHERE id=? AND patient_id=? AND status='Reschedule Requested'", (appointment_id, session["patient_database_id"])).fetchone()
        if not item:
            flash("That reschedule proposal is not available.", "danger")
        else:
            occupied = conn.execute("""SELECT 1 FROM appointments WHERE doctor_id=? AND appointment_date=?
                AND appointment_time=? AND id<>? AND status NOT IN ('Declined','Cancelled') LIMIT 1""",
                (item["doctor_id"], item["proposed_date"], item["proposed_time"], appointment_id)).fetchone()
            if occupied:
                flash("That proposed time is no longer available. Ask the doctor to suggest another time.", "warning")
            else:
                conn.execute("""UPDATE appointments SET appointment_date=proposed_date, appointment_time=proposed_time,
                             status='Accepted',updated_at=CURRENT_TIMESTAMP WHERE id=?""", (appointment_id,))
                conn.execute("UPDATE appointment_reschedule_requests SET status='Accepted' WHERE appointment_id=? AND requested_by='Doctor'", (appointment_id,))
                flash("You accepted the proposed appointment time.", "success")
    return redirect(url_for("appointments"))

@app.route("/patient/appointment/<int:appointment_id>/reject-reschedule", methods=["POST"])
@login_required
def reject_reschedule(appointment_id):
    if not valid_csrf():
        return "Invalid CSRF token", 400
    with get_db() as conn:
        item = conn.execute("SELECT id FROM appointments WHERE id=? AND patient_id=? AND status='Reschedule Requested'", (appointment_id, session["patient_database_id"])).fetchone()
        if not item:
            flash("That reschedule proposal is not available.", "danger")
        else:
            conn.execute("UPDATE appointments SET status='Reschedule Declined',updated_at=CURRENT_TIMESTAMP WHERE id=?", (appointment_id,))
            conn.execute("UPDATE appointment_reschedule_requests SET status='Rejected' WHERE appointment_id=? AND requested_by='Doctor'", (appointment_id,))
            flash("The proposed time was declined. The original appointment remains visible.", "success")
    return redirect(url_for("appointments"))

@app.route("/services")
def services(): return render_template("services.html")
@app.route("/about")
def about(): return render_template("about.html")
@app.route("/contact")
def contact(): return render_template("contact.html")

init_db()
if __name__ == "__main__":
    debug = not IS_PRODUCTION and os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(debug=debug)
