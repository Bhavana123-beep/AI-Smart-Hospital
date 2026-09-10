from functools import wraps
import hmac
import os
import re
import sqlite3
from datetime import date, datetime
import joblib
import pandas as pd
from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "ai-smart-hospital-secret-key")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "database.db")

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

def clear_patient_session():
    for key in ("patient_id", "patient_database_id", "patient_name", "patient_email", "last_prediction"):
        session.pop(key, None)

def clear_doctor_session():
    for key in ("doctor_id", "doctor_database_id", "doctor_name", "doctor_email", "doctor_department"):
        session.pop(key, None)

def init_db():
    with get_db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS patients (id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT NOT NULL, age INTEGER NOT NULL, gender TEXT, blood_group TEXT, address TEXT, password TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS prediction_history (id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, symptoms TEXT NOT NULL, disease TEXT NOT NULL, confidence REAL, department TEXT NOT NULL, doctor TEXT NOT NULL, FOREIGN KEY(patient_id) REFERENCES patients(id))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS doctors (id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT NOT NULL, password TEXT NOT NULL, department TEXT NOT NULL, specialization TEXT NOT NULL, experience INTEGER NOT NULL, qualification TEXT NOT NULL, availability TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Active')""")
        conn.execute("""CREATE TABLE IF NOT EXISTS appointments (id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER NOT NULL, doctor_id INTEGER NOT NULL, disease TEXT NOT NULL, department TEXT NOT NULL, symptoms TEXT NOT NULL, appointment_date TEXT NOT NULL, appointment_time TEXT NOT NULL, reason TEXT NOT NULL, patient_notes TEXT, doctor_notes TEXT, status TEXT NOT NULL DEFAULT 'Pending', original_date TEXT, original_time TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(patient_id) REFERENCES patients(id), FOREIGN KEY(doctor_id) REFERENCES doctors(id))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS appointment_reschedule_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, appointment_id INTEGER NOT NULL, requested_by TEXT NOT NULL, requested_date TEXT NOT NULL, requested_time TEXT NOT NULL, reason TEXT, status TEXT NOT NULL DEFAULT 'Pending', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(appointment_id) REFERENCES appointments(id))""")
        patient_columns = {row[1] for row in conn.execute("PRAGMA table_info(patients)")}
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
        # Earlier versions seeded project demo accounts.  Keep their records intact,
        # but exclude them from recommendations unless an administrator explicitly
        # activates them as real accounts.
        conn.execute("UPDATE doctors SET status='Inactive' WHERE email LIKE '%@demo-hospital.local'")
        conn.execute("PRAGMA journal_mode=WAL")
        for row in conn.execute("SELECT id FROM doctors WHERE doctor_id IS NULL OR doctor_id='' ").fetchall():
            conn.execute("UPDATE doctors SET doctor_id=? WHERE id=?", (public_identifier(conn, "doctors", "doctor_id", "DOC", row["id"]), row["id"]))

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "patient_id" not in session:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def doctor_login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "doctor_id" not in session:
            flash("Please log in as a doctor to access that page.", "warning")
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
    model = joblib.load(os.path.join(BASE_DIR, "model", "disease_model.pkl"))
    MODEL_FEATURES = [feature for feature in model.feature_names_in_ if not feature.lower().startswith("unnamed:")]
    print(f"Disease model loaded successfully. Type: {type(model).__name__}; features: {len(MODEL_FEATURES)}; classes: {len(getattr(model, 'classes_', []))}.")
except Exception as error:
    model, MODEL_FEATURES = None, []
    print(f"ERROR: Could not load disease model: {error}")
if model is not None and not MODEL_FEATURES:
    try:
        MODEL_FEATURES = list(pd.read_csv(os.path.join(BASE_DIR, "dataset", "Training.csv")).drop(columns=["prognosis"], errors="ignore").columns)
    except Exception as error:
        print(f"ERROR: Could not load model features: {error}")

ALIASES = {"motions":"diarrhoea", "loose motions":"diarrhoea", "loose motion":"diarrhoea", "diarrhea":"diarrhoea", "high temperature":"high fever", "throwing up":"vomiting", "vomit":"vomiting", "stomach upset":"stomach pain", "heart pain":"chest pain", "breathing difficulty":"breathlessness", "burning urination":"burning micturition", "high blood sugar":"irregular sugar level", "yellow skin":"yellowish skin", "yellow eyes":"yellowing of eyes"}
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
LOW_CONFIDENCE_THRESHOLD = 0.50
GENERAL_EVALUATION_SYMPTOMS = {"headache", "stomach pain", "fever", "vomiting"}

def normalized_disease_label(label):
    """Normalize formatting only; disease classification always remains the model's job."""
    return re.sub(r"\s+", " ", str(label).strip().lower())

def department_for_disease(disease):
    """Resolve the model's disease label to its centralized department mapping."""
    return DEPARTMENTS.get(normalized_disease_label(disease), "General Medicine")

def registered_doctors(conn, department, disease=""):
    """Return only active, database-backed doctors in the recommended department."""
    specialization_hint = f"%{disease.strip().lower()}%"
    return conn.execute("""SELECT id, full_name, department, specialization, experience, qualification, availability
        FROM doctors
        WHERE LOWER(TRIM(department))=LOWER(TRIM(?)) AND LOWER(TRIM(status))='active'
        ORDER BY CASE WHEN LOWER(specialization) LIKE ? THEN 0 ELSE 1 END,
                 CASE WHEN TRIM(COALESCE(availability, '')) <> '' THEN 0 ELSE 1 END,
                 experience DESC, id ASC""", (department, specialization_hint)).fetchall()

def normalized_symptom(text):
    """Normalize free-text symptom wording before matching real model features."""
    return re.sub(r"\s+", " ", text.strip().lower().replace("_", " ").replace("-", " "))

def match_symptoms(raw_symptoms):
    """Match aliases only when their canonical target is an actual model feature."""
    lookup = {normalized_symptom(feature): feature for feature in MODEL_FEATURES}
    entered = [normalized_symptom(item) for item in re.split(r"[,;]", raw_symptoms) if item.strip()]
    matched, unmatched = [], []
    for symptom in entered:
        candidate = ALIASES.get(symptom, symptom)
        feature = lookup.get(candidate)
        if feature:
            matched.append(feature)
        else:
            unmatched.append(symptom)
    return entered, list(dict.fromkeys(matched)), unmatched

@app.route("/")
def home(): return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = {key: request.form.get(key, "").strip() for key in ("full_name", "email", "phone", "age", "gender", "blood_group", "address")}
        data["email"] = data["email"].lower(); password = request.form.get("password", ""); confirm = request.form.get("confirm_password", "")
        if not all(data.values()) or not password or not confirm: return render_template("register.html", error="Please fill all required fields.", form=data)
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
        public_id, password = request.form.get("patient_id", "").strip().upper(), request.form.get("password", "")
        if not public_id or not password: return render_template("login.html", error="Please enter both Patient ID and password.")
        with get_db() as conn: patient = conn.execute("SELECT id,patient_id,full_name,email,password FROM patients WHERE patient_id=?", (public_id,)).fetchone()
        if patient is None or not password_matches(patient["password"], password): return render_template("login.html", error="Invalid Patient ID or Password.")
        # Upgrade a legacy plaintext password only after the correct password is supplied.
        if not patient["password"].startswith(("pbkdf2:", "scrypt:")):
            with get_db() as conn:
                conn.execute("UPDATE patients SET password=? WHERE id=?", (generate_password_hash(password), patient["id"]))
        clear_patient_session(); session.update(patient_id=patient["patient_id"], patient_database_id=patient["id"], patient_name=patient["full_name"], patient_email=patient["email"]); return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/logout")
def logout(): clear_patient_session(); flash("You have been logged out.", "success"); return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    with get_db() as conn:
        appointments = conn.execute("""SELECT a.*, d.full_name doctor_name, d.specialization FROM appointments a JOIN doctors d ON d.id=a.doctor_id WHERE a.patient_id=? ORDER BY a.appointment_date DESC,a.appointment_time DESC""", (session["patient_database_id"],)).fetchall()
    return render_template("patient_dashboard.html", patient_name=session.get("patient_name", "Patient"), public_patient_id=session.get("patient_id"), appointments=appointments)

@app.route("/prediction", methods=["GET", "POST"])
@login_required
def prediction():
    if request.method == "GET": return render_template("prediction.html")
    raw = request.form.get("symptoms", "").strip()
    if not raw: return render_template("prediction.html", error="Please enter at least one symptom.")
    if model is None or not MODEL_FEATURES: return render_template("prediction.html", error="Disease model is unavailable. Please try again later.")
    entered, matched, unknown = match_symptoms(raw)
    print(f"Entered symptoms: {entered}; matched symptoms: {matched}; unmatched symptoms: {unknown}; matched count: {len(matched)}")
    if not matched: return render_template("prediction.html", error="No matching symptoms found. Check the spelling and try again.", unknown_symptoms=unknown)
    input_df = pd.DataFrame(0, index=[0], columns=MODEL_FEATURES); input_df.loc[0, list(dict.fromkeys(matched))] = 1
    try:
        disease = str(model.predict(input_df)[0])
        top_predictions = []
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(input_df)[0]
            top_indices = probabilities.argsort()[-3:][::-1]
            top_predictions = [{"disease": str(model.classes_[index]), "confidence": round(float(probabilities[index]) * 100, 2)} for index in top_indices]
            confidence = top_predictions[0]["confidence"]
        else:
            confidence = None
    except Exception as error:
        print(f"PREDICTION ERROR: {error}"); return render_template("prediction.html", error="Prediction failed. Please try again.")
    confidence_ratio = confidence / 100 if confidence is not None else 0
    normalized_symptoms = {item.replace("_", " ").lower() for item in matched}
    low_confidence = confidence is None or confidence_ratio < LOW_CONFIDENCE_THRESHOLD
    general_symptoms = bool(normalized_symptoms) and normalized_symptoms.issubset(GENERAL_EVALUATION_SYMPTOMS)
    # Confidence changes the warning, never a valid disease-specific department.
    department = department_for_disease(disease)
    with get_db() as conn:
        recommended = registered_doctors(conn, department, disease)
    doctor = recommended[0]["full_name"] if recommended else None
    doctor_id = recommended[0]["id"] if recommended else None
    doctor_specialization = recommended[0]["specialization"] if recommended else None
    doctor_experience = recommended[0]["experience"] if recommended else None
    doctor_availability = recommended[0]["availability"] if recommended else None
    symptoms = ", ".join(x.replace("_", " ") for x in dict.fromkeys(matched))
    with get_db() as conn: conn.execute("INSERT INTO prediction_history (patient_id,symptoms,disease,confidence,department,doctor) VALUES (?,?,?,?,?,?)", (session["patient_database_id"], symptoms, disease, confidence, department, doctor or "No registered doctor available"))
    chest_pain_entered = "chest_pain" in matched
    session["last_prediction"] = {"disease":disease, "confidence":confidence, "department":department, "doctor":doctor, "doctor_id":doctor_id, "doctor_specialization":doctor_specialization, "doctor_experience":doctor_experience, "doctor_availability":doctor_availability, "matched_symptoms":symptoms, "unknown_symptoms":unknown, "low_confidence":low_confidence, "general_evaluation":general_symptoms, "top_predictions":top_predictions, "chest_pain_entered":chest_pain_entered}
    return redirect(url_for("result"))

@app.route("/result")
@login_required
def result():
    data = session.get("last_prediction")
    if not data: flash("Make a prediction to see its result.", "warning"); return redirect(url_for("prediction"))
    with get_db() as conn:
        doctors = registered_doctors(conn, data["department"], data["disease"])
    return render_template("result.html", doctors=doctors, **data)

@app.route("/history")
@login_required
def history():
    with get_db() as conn: predictions = conn.execute("SELECT created_at,symptoms,disease,confidence,department,doctor FROM prediction_history WHERE patient_id=? ORDER BY datetime(created_at) DESC,id DESC", (session["patient_database_id"],)).fetchall()
    return render_template("history.html", predictions=predictions)

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    patient_id = session["patient_database_id"]
    if request.method == "POST":
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
        items = conn.execute("""SELECT a.*,d.full_name doctor_name,d.specialization FROM appointments a JOIN doctors d ON d.id=a.doctor_id WHERE a.patient_id=? ORDER BY a.appointment_date DESC,a.appointment_time DESC""", (session["patient_database_id"],)).fetchall()
    return render_template("appointments.html", appointments=items)

@app.route("/book-appointment", methods=["GET", "POST"])
@app.route("/confirm-appointment", methods=["POST"])
@login_required
def book_appointment():
    prediction = session.get("last_prediction")
    if not prediction:
        flash("Please make a disease prediction before booking an appointment.", "warning")
        return redirect(url_for("prediction"))
    with get_db() as conn:
        doctors = registered_doctors(conn, prediction["department"], prediction["disease"])
        selected_doctor_id = request.values.get("doctor_id", type=int)
        selected_doctor = next((doctor for doctor in doctors if doctor["id"] == selected_doctor_id), None)
        if selected_doctor_id and selected_doctor is None:
            return render_template("book_appointment.html", prediction=prediction, doctor=None,
                                   error="The selected doctor is no longer available in this department.", today=date.today().isoformat())
        if request.method == "POST":
            doctor_id = request.form.get("doctor_id", type=int); appointment_date = request.form.get("appointment_date", ""); appointment_time = request.form.get("appointment_time", ""); reason = request.form.get("reason", "").strip(); notes = request.form.get("patient_notes", "").strip()
            doctor = conn.execute("""SELECT id,full_name,department,specialization,availability FROM doctors WHERE id=? AND LOWER(TRIM(department))=LOWER(TRIM(?))
                                  AND LOWER(TRIM(status))='active'""", (doctor_id, prediction["department"])).fetchone()
            if not doctor:
                return render_template("book_appointment.html", prediction=prediction, doctor=None, error="The selected doctor is no longer available.", today=date.today().isoformat())
            slot_valid, slot_error = doctor_availability_is_valid(doctor["availability"], appointment_date, appointment_time)
            if not slot_valid:
                return render_template("book_appointment.html", prediction=prediction, doctor=doctor, error=slot_error, today=date.today().isoformat())
            occupied = conn.execute("SELECT id FROM appointments WHERE doctor_id=? AND appointment_date=? AND appointment_time=? AND status NOT IN ('Declined','Cancelled')", (doctor_id, appointment_date, appointment_time)).fetchone()
            if occupied:
                return render_template("book_appointment.html", prediction=prediction, doctor=doctor, error="That time slot is already booked. Please choose another time.", today=date.today().isoformat())
            cursor = conn.execute("""INSERT INTO appointments (patient_id,doctor_id,disease,department,symptoms,appointment_date,appointment_time,reason,patient_notes) VALUES (?,?,?,?,?,?,?,?,?)""", (session["patient_database_id"],doctor_id,prediction["disease"],prediction["department"],prediction["matched_symptoms"],appointment_date,appointment_time,reason,notes))
            return render_template("appointment_confirmation.html", appointment_id=cursor.lastrowid, doctor=doctor,
                                   prediction=prediction, appointment_date=appointment_date, appointment_time=appointment_time)
    if selected_doctor is None:
        return render_template("book_appointment.html", prediction=prediction, doctor=None,
                               error="Choose a registered doctor from the prediction result page.", today=date.today().isoformat())
    return render_template("book_appointment.html", prediction=prediction, doctor=selected_doctor, today=date.today().isoformat())

@app.route("/appointment/<int:appointment_id>/reschedule", methods=["GET", "POST"])
@login_required
def patient_reschedule(appointment_id):
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
        data = {key: request.form.get(key, "").strip() for key in ("email", "phone", "department", "specialization", "qualification", "experience")}
        data["full_name"] = request.form.get("name", "").strip()
        data["email"] = data["email"].lower()
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
                cursor = conn.execute("""INSERT INTO doctors (full_name,email,phone,password,department,specialization,experience,qualification,availability,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,'Active',CURRENT_TIMESTAMP)""", (data["full_name"], data["email"], data["phone"], generate_password_hash(password), data["department"], data["specialization"], experience, data["qualification"], "Monday - Friday, 09:00 - 17:00"))
                public_id = public_identifier(conn, "doctors", "doctor_id", "DOC", cursor.lastrowid)
                conn.execute("UPDATE doctors SET doctor_id=? WHERE id=?", (public_id, cursor.lastrowid))
        except sqlite3.IntegrityError:
            return render_template("doctor_register.html", error="A doctor with this email already exists.", form=data)
        except sqlite3.Error as error:
            print(f"DOCTOR REGISTRATION ERROR: {error}")
            return render_template("doctor_register.html", error="Unable to register doctor. Please try again.", form=data)
        flash("Doctor registration successful. Please login.", "success")
        return redirect(url_for("doctor_login"))
    return render_template("doctor_register.html", form={})

@app.route("/doctor-login", methods=["GET", "POST"])
@app.route("/doctor/login", methods=["GET", "POST"])
def doctor_login():
    if request.method == "POST":
        email, password = request.form.get("email", "").strip().lower(), request.form.get("password", "")
        with get_db() as conn: doctor = conn.execute("SELECT * FROM doctors WHERE email=? AND status='Active'", (email,)).fetchone()
        if not email or not password or doctor is None or not password_matches(doctor["password"], password): return render_template("doctor_login.html", error="Invalid email or password.")
        if not doctor["password"].startswith(("pbkdf2:", "scrypt:")):
            with get_db() as conn:
                conn.execute("UPDATE doctors SET password=? WHERE id=?", (generate_password_hash(password), doctor["id"]))
        clear_doctor_session(); session.update(doctor_id=doctor["doctor_id"], doctor_database_id=doctor["id"], doctor_name=doctor["full_name"], doctor_email=doctor["email"], doctor_department=doctor["department"]); return redirect(url_for("doctor_dashboard"))
    return render_template("doctor_login.html")

@app.route("/doctor-logout")
@app.route("/doctor/logout")
def doctor_logout():
    clear_doctor_session()
    flash("Doctor session ended.", "success"); return redirect(url_for("doctor_login"))

def doctor_appointments():
    with get_db() as conn:
        return conn.execute("""SELECT a.*,p.patient_id public_patient_id,p.full_name patient_name,p.email patient_email,p.phone patient_phone,p.age patient_age,p.gender patient_gender FROM appointments a JOIN patients p ON p.id=a.patient_id WHERE a.doctor_id=? ORDER BY a.appointment_date,a.appointment_time""", (session["doctor_database_id"],)).fetchall()

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
        patient = conn.execute("SELECT patient_id,full_name,email,phone,age,gender,blood_group,address FROM patients WHERE patient_id=?", (public_id,)).fetchone()
        if not patient:
            flash("Patient not found.", "danger")
            return redirect(url_for("doctor_dashboard"))
        database_id = conn.execute("SELECT id FROM patients WHERE patient_id=?", (public_id,)).fetchone()["id"]
        predictions = conn.execute("SELECT created_at,symptoms,disease,confidence,department,doctor FROM prediction_history WHERE patient_id=? ORDER BY created_at DESC", (database_id,)).fetchall()
        appointments = conn.execute("""SELECT a.*,d.full_name doctor_name FROM appointments a JOIN doctors d ON d.id=a.doctor_id WHERE a.patient_id=? ORDER BY a.appointment_date DESC,a.appointment_time DESC""", (database_id,)).fetchall()
    return render_template("doctor_patient_history.html", patient=patient, predictions=predictions, appointments=appointments)

@app.route("/doctor/appointment/<int:appointment_id>/<action>", methods=["POST"])
@doctor_login_required
def update_appointment(appointment_id, action):
    statuses = {"accept":"Accepted", "decline":"Declined", "complete":"Completed"}
    with get_db() as conn:
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
            conn.execute("INSERT INTO appointment_reschedule_requests (appointment_id,requested_by,requested_date,requested_time,reason,status) VALUES (?,?,?,?,?,'Accepted')", (appointment_id,"Doctor",new_date,new_time,request.form.get("reason", "").strip()))
            message = request.form.get("doctor_message", request.form.get("reason", "")).strip()
            conn.execute("UPDATE appointments SET original_date=COALESCE(original_date,appointment_date),original_time=COALESCE(original_time,appointment_time),proposed_date=?,proposed_time=?,status='Reschedule Requested',doctor_message=?,doctor_notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (new_date,new_time,message,message,appointment_id))
        else: flash("Invalid appointment action.", "danger"); return redirect(url_for("doctor_dashboard"))
    flash("Appointment updated.", "success"); return redirect(url_for("doctor_dashboard"))

@app.route("/patient/appointment/<int:appointment_id>/accept-reschedule", methods=["POST"])
@login_required
def accept_reschedule(appointment_id):
    with get_db() as conn:
        item = conn.execute("SELECT id FROM appointments WHERE id=? AND patient_id=? AND status='Reschedule Requested'", (appointment_id, session["patient_database_id"])).fetchone()
        if not item:
            flash("That reschedule proposal is not available.", "danger")
        else:
            conn.execute("""UPDATE appointments SET appointment_date=proposed_date, appointment_time=proposed_time,
                         status='Accepted',updated_at=CURRENT_TIMESTAMP WHERE id=?""", (appointment_id,))
            conn.execute("UPDATE appointment_reschedule_requests SET status='Accepted' WHERE appointment_id=? AND requested_by='Doctor'", (appointment_id,))
            flash("You accepted the proposed appointment time.", "success")
    return redirect(url_for("appointments"))

@app.route("/patient/appointment/<int:appointment_id>/reject-reschedule", methods=["POST"])
@login_required
def reject_reschedule(appointment_id):
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
if __name__ == "__main__": app.run(debug=True)
