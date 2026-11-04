
import os
import sqlite3
import uuid

from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    send_from_directory,
    abort
)

from flask_wtf.csrf import CSRFProtect
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)
from werkzeug.utils import secure_filename


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "development-only-change-this-key"
)

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB

app.config["SESSION_PERMANENT"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

csrf = CSRFProtect(app)


# --------------------------------------------------
# FILE AND DATABASE LOCATIONS
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

DATABASE = BASE_DIR / "scanning_system.db"

UPLOAD_FOLDER = Path(app.instance_path) / "document_uploads"

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}

DOCUMENT_TYPES = [
    "Invoice",
    "Credit Note",
    "Debit Note",
    "Sales Report"
]


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

@contextmanager
def get_db_connection():

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    try:
        yield connection
        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


# --------------------------------------------------
# DATABASE INITIALIZATION
# --------------------------------------------------

def initialize_database():

    UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

    with get_db_connection() as connection:

        # Users table
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Documents table
        connection.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                document_type TEXT NOT NULL,
                reference_number TEXT,
                document_date TEXT,
                customer_name TEXT,

                report_start_date TEXT,
                report_end_date TEXT,

                original_filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL UNIQUE,

                uploaded_by INTEGER NOT NULL,

                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                notes TEXT,

                FOREIGN KEY (uploaded_by)
                    REFERENCES users(id)
            )
        """)


# --------------------------------------------------
# FILE VALIDATION
# --------------------------------------------------

def allowed_file(filename):

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def home():

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# --------------------------------------------------
# REGISTRATION
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        full_name = request.form.get(
            "full_name", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get("password", "")

        confirm_password = request.form.get(
            "confirm_password", ""
        )

        # Validate full name
        if len(full_name) < 2:
            flash("Please enter your full name.", "error")
            return redirect(url_for("register"))

        # Basic email validation
        if not email or "@" not in email:
            flash("Please enter a valid email address.", "error")
            return redirect(url_for("register"))

        # Password validation
        if len(password) < 8 or len(password) > 128:
            flash(
                "Password must be between 8 and 128 characters.",
                "error"
            )
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Your passwords do not match.", "error")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        try:

            with get_db_connection() as connection:

                connection.execute("""
                    INSERT INTO users (
                        full_name,
                        email,
                        password_hash
                    )
                    VALUES (?, ?, ?)
                """, (
                    full_name,
                    email,
                    password_hash
                ))

        except sqlite3.IntegrityError:

            flash(
                "An account with that email already exists.",
                "error"
            )

            return redirect(url_for("register"))

        flash(
            "Registration successful. You can now log in.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template("register.html")


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get("password", "")

        with get_db_connection() as connection:

            user = connection.execute("""
                SELECT *
                FROM users
                WHERE email = ?
            """, (email,)).fetchone()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            session.clear()

            session["user_id"] = user["id"]
            session["full_name"] = user["full_name"]

            # Remember Me option
            remember = request.form.get("remember_me") == "on"

            session.permanent = remember

            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "error")

        return redirect(url_for("login"))

    return render_template("login.html")


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    with get_db_connection() as connection:

        total_documents = connection.execute("""
            SELECT COUNT(*) AS total
            FROM documents
        """).fetchone()["total"]

        total_invoices = connection.execute("""
            SELECT COUNT(*) AS total
            FROM documents
            WHERE document_type = 'Invoice'
        """).fetchone()["total"]

        total_reports = connection.execute("""
            SELECT COUNT(*) AS total
            FROM documents
            WHERE document_type = 'Sales Report'
        """).fetchone()["total"]

        recent_documents = connection.execute("""
            SELECT *
            FROM documents
            ORDER BY uploaded_at DESC
            LIMIT 5
        """).fetchall()

    return render_template(
        "dashboard.html",
        full_name=session["full_name"],
        total_documents=total_documents,
        total_invoices=total_invoices,
        total_reports=total_reports,
        recent_documents=recent_documents
    )


# --------------------------------------------------
# ADD / UPLOAD DOCUMENT
# --------------------------------------------------

@app.route("/documents/add", methods=["GET", "POST"])
def add_document():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        document_type = request.form.get(
            "document_type", ""
        ).strip()

        reference_number = request.form.get(
            "reference_number", ""
        ).strip()

        document_date = request.form.get(
            "document_date", ""
        ).strip()

        customer_name = request.form.get(
            "customer_name", ""
        ).strip()

        report_start_date = request.form.get(
            "report_start_date", ""
        ).strip()

        report_end_date = request.form.get(
            "report_end_date", ""
        ).strip()

        notes = request.form.get(
            "notes", ""
        ).strip()

        uploaded_file = request.files.get("document_file")

        # Check document type
        if document_type not in DOCUMENT_TYPES:

            flash("Please select a valid document type.", "error")

            return redirect(url_for("add_document"))

        # Check file
        if not uploaded_file or uploaded_file.filename == "":

            flash("Please select a document to upload.", "error")

            return redirect(url_for("add_document"))

        if not allowed_file(uploaded_file.filename):

            flash(
                "Only PDF, JPG, JPEG and PNG files are allowed.",
                "error"
            )

            return redirect(url_for("add_document"))

        # Clean original filename for display
        original_filename = secure_filename(
            uploaded_file.filename
        )

        if not original_filename:

            flash("The selected filename is invalid.", "error")

            return redirect(url_for("add_document"))

        extension = original_filename.rsplit(".", 1)[1].lower()

        # Generate a unique stored filename
        stored_filename = f"{uuid.uuid4().hex}.{extension}"

        file_path = UPLOAD_FOLDER / stored_filename

        # Save uploaded file
        uploaded_file.save(file_path)

        try:

            with get_db_connection() as connection:

                connection.execute("""
                    INSERT INTO documents (
                        document_type,
                        reference_number,
                        document_date,
                        customer_name,
                        report_start_date,
                        report_end_date,
                        original_filename,
                        stored_filename,
                        uploaded_by,
                        notes
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    document_type,
                    reference_number or None,
                    document_date or None,
                    customer_name or None,
                    report_start_date or None,
                    report_end_date or None,
                    original_filename,
                    stored_filename,
                    session["user_id"],
                    notes or None
                ))

        except Exception:

            # Remove file if database saving fails
            file_path.unlink(missing_ok=True)

            raise

        flash("Document uploaded successfully!", "success")

        return redirect(url_for("documents"))

    return render_template(
        "upload_document.html",
        document_types=DOCUMENT_TYPES
    )


# --------------------------------------------------
# VIEW ALL DOCUMENTS
# --------------------------------------------------

@app.route("/documents")
def documents():

    if "user_id" not in session:
        return redirect(url_for("login"))

    with get_db_connection() as connection:

        all_documents = connection.execute("""
            SELECT
                documents.*,
                users.full_name

            FROM documents

            JOIN users
                ON documents.uploaded_by = users.id

            ORDER BY documents.uploaded_at DESC
        """).fetchall()

    return render_template(
        "documents.html",
        documents=all_documents
    )


# --------------------------------------------------
# DOWNLOAD DOCUMENT
# --------------------------------------------------

@app.route("/documents/download/<int:document_id>")
def download_document(document_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    with get_db_connection() as connection:

        document = connection.execute("""
            SELECT
                stored_filename,
                original_filename

            FROM documents

            WHERE id = ?
        """, (document_id,)).fetchone()

    if document is None:
        abort(404)

    return send_from_directory(
        UPLOAD_FOLDER,
        document["stored_filename"],
        as_attachment=True,
        download_name=document["original_filename"]
    )


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout", methods=["POST"])
def logout():

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("login"))


# --------------------------------------------------
# FILE SIZE ERROR
# --------------------------------------------------

@app.errorhandler(413)
def file_too_large(error):

    flash(
        "The file is too large. Maximum file size is 10 MB.",
        "error"
    )

    return redirect(url_for("add_document"))


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    initialize_database()

    app.run(debug=True)
