import csv
import os
import re
import secrets
import smtplib
import ssl
import string
import hashlib
from html import unescape
from io import StringIO
from html.parser import HTMLParser
from datetime import date, datetime, time, timedelta
from functools import wraps
from email.message import EmailMessage
from typing import Any, TypedDict, cast
from urllib.parse import urlparse

from flask import Flask, Response, flash, redirect, render_template, request, send_from_directory, session, url_for
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from markupsafe import Markup, escape
from sqlalchemy import inspect, or_
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
try:
    from PIL import Image, ImageOps
except ImportError:  # pragma: no cover
    Image = None
    ImageOps = None

from config import Config
from models import AuditLog, Job, JobApplication, SavedJob, User, db

app = Flask(__name__)
app.config.from_object(Config)
app.config["PROFILE_UPLOAD_FOLDER"] = os.path.join("uploads", "profile")

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = cast(Any, "login")

ALLOWED_CV_EXTENSIONS = {"pdf", "doc", "docx"}
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
UNDER_REVIEW_STATUSES = {"pending", "under_review"}


class InvitationDetails(TypedDict):
    invitation_type: str
    interview_date: date
    interview_time: time
    venue: str


class VacancyFormData(TypedDict):
    title: str
    department: str
    location: str
    employment_type: str
    min_experience: int
    salary_min: int | None
    salary_max: int | None
    deadline: date | None
    description: str


class RichTextSanitizer(HTMLParser):
    ALLOWED_TAGS = {
        "p",
        "br",
        "strong",
        "em",
        "u",
        "del",
        "ul",
        "ol",
        "li",
        "a",
        "b",
        "i",
        "s",
        "strike",
        "div",
        "span",
        "font",
    }

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.open_anchors = 0

    @staticmethod
    def _sanitize_color(value):
        color = (value or "").strip().lower()
        if re.fullmatch(r"#[0-9a-f]{3}([0-9a-f]{3})?", color):
            return color
        if re.fullmatch(r"[a-z]{3,20}", color):
            return color
        if re.fullmatch(
            r"rgba?\(\s*(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\s*,\s*(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\s*,\s*(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])(\s*,\s*(0|1|0?\.\d+))?\s*\)",
            color,
        ):
            return color
        return ""

    @staticmethod
    def _sanitize_font_family(value):
        family = (value or "").strip()
        if not family:
            return ""
        if not re.fullmatch(r"[a-zA-Z0-9 ,\"'-]{1,80}", family):
            return ""
        return family

    @staticmethod
    def _sanitize_font_size(value):
        size = (value or "").strip()
        if re.fullmatch(r"[1-7]", size):
            return size
        if re.fullmatch(r"(8|9|1\d|2\d|3\d|4\d|5\d|6\d|7[0-2])(px)?", size):
            return f"{size}px" if size.isdigit() else size
        return ""

    @staticmethod
    def _sanitize_style(style_raw, allow_text_align=False):
        if not style_raw:
            return ""

        safe = []
        chunks = [item.strip() for item in style_raw.split(";") if ":" in item]
        for chunk in chunks:
            key, value = chunk.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            if key == "color":
                color = RichTextSanitizer._sanitize_color(value)
                if color:
                    safe.append(f"color:{color}")
            elif key == "background-color":
                color = RichTextSanitizer._sanitize_color(value)
                if color:
                    safe.append(f"background-color:{color}")
            elif key == "font-family":
                family = RichTextSanitizer._sanitize_font_family(value)
                if family:
                    safe.append(f"font-family:{family}")
            elif key == "font-size":
                size = RichTextSanitizer._sanitize_font_size(value)
                if size:
                    safe.append(f"font-size:{size}")
            elif key == "text-align" and allow_text_align and value in {
                "left",
                "center",
                "right",
                "justify",
            }:
                safe.append(f"text-align:{value}")
        return ";".join(safe)

    def handle_starttag(self, tag, attrs):
        if tag not in self.ALLOWED_TAGS:
            return
        if tag == "a":
            href = ""
            for key, value in attrs:
                if key == "href" and value:
                    href = value.strip()
                    break
            parsed = urlparse(href)
            if parsed.scheme not in {"http", "https"}:
                return
            safe_href = escape(href)
            self.parts.append(
                f'<a href="{safe_href}" target="_blank" rel="noopener noreferrer">'
            )
            self.open_anchors += 1
            return
        if tag == "br":
            self.parts.append("<br>")
            return

        attrs_map = {key.lower(): (value or "") for key, value in attrs}
        if tag in {"p", "div"}:
            style = self._sanitize_style(
                attrs_map.get("style", ""),
                allow_text_align=True,
            )
            self.parts.append(f'<{tag} style="{escape(style)}">' if style else f"<{tag}>")
            return

        if tag == "span":
            style = self._sanitize_style(attrs_map.get("style", ""))
            self.parts.append(f'<span style="{escape(style)}">' if style else "<span>")
            return

        if tag == "font":
            color = self._sanitize_color(attrs_map.get("color", ""))
            face = self._sanitize_font_family(attrs_map.get("face", ""))
            size = self._sanitize_font_size(attrs_map.get("size", ""))
            attr_parts = []
            if color:
                attr_parts.append(f'color="{escape(color)}"')
            if face:
                attr_parts.append(f'face="{escape(face)}"')
            if size:
                attr_parts.append(f'size="{escape(size)}"')
            joined = " ".join(attr_parts)
            self.parts.append(f"<font {joined}>".replace("  ", " ").replace(" >", ">") if joined else "<font>")
            return

        self.parts.append(f"<{tag}>")

    def handle_endtag(self, tag):
        if tag not in self.ALLOWED_TAGS or tag == "br":
            return
        if tag == "a":
            if self.open_anchors <= 0:
                return
            self.parts.append("</a>")
            self.open_anchors -= 1
            return
        self.parts.append(f"</{tag}>")

    def handle_data(self, data):
        self.parts.append(str(escape(data)))

    def get_html(self):
        return "".join(self.parts)


def sanitize_rich_html(value):
    sanitizer = RichTextSanitizer()
    sanitizer.feed(value or "")
    sanitizer.close()
    cleaned = sanitizer.get_html().strip()
    return Markup(cleaned)


def format_rich_text(value):
    if not value:
        return Markup("")

    if re.search(r"</?[a-zA-Z][^>]*>", str(value)):
        return sanitize_rich_html(str(value))

    def render_inline_markup(text):
        text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
        text = re.sub(r"~~(.+?)~~", r"<del>\1</del>", text)
        text = re.sub(r"\+\+(.+?)\+\+", r"<u>\1</u>", text)
        text = re.sub(r"\[(.+?)\]\((https?://[^\s)]+)\)", r'<a href="\2" target="_blank" rel="noopener noreferrer">\1</a>', text)
        text = re.sub(r"(?<!\*)\*(?!\s)(.+?)(?<!\s)\*(?!\*)", r"<em>\1</em>", text)
        text = re.sub(r"(?<!\w)_(.+?)_(?!\w)", r"<em>\1</em>", text)
        return text

    text = escape(value)
    blocks = re.split(r"\n\s*\n", str(text))
    rendered_blocks = []
    for block in blocks:
        block_text = block.strip()
        if not block_text:
            continue

        lines = [line.strip() for line in block_text.split("\n") if line.strip()]
        is_unordered = bool(lines) and all(re.match(r"^[-*]\s+", line) for line in lines)
        is_ordered = bool(lines) and all(re.match(r"^\d+\.\s+", line) for line in lines)

        if is_unordered:
            items = []
            for line in lines:
                line = re.sub(r"^[-*]\s+", "", line, count=1)
                items.append(f"<li>{render_inline_markup(line)}</li>")
            rendered_blocks.append(f"<ul>{''.join(items)}</ul>")
            continue

        if is_ordered:
            items = []
            for line in lines:
                line = re.sub(r"^\d+\.\s+", "", line, count=1)
                items.append(f"<li>{render_inline_markup(line)}</li>")
            rendered_blocks.append(f"<ol>{''.join(items)}</ol>")
            continue

        block_text = render_inline_markup(block_text).replace("\n", "<br>")
        rendered_blocks.append(f"<p>{block_text}</p>")
    return Markup("".join(rendered_blocks))


def rich_text_to_plain_text(value):
    if not value:
        return ""

    raw = str(value)
    if re.search(r"</?[a-zA-Z][^>]*>", raw):
        raw = str(sanitize_rich_html(raw))

    text = re.sub(r"(?i)<br\s*/?>", "\n", raw)
    text = re.sub(r"(?i)</(p|div|li|ul|ol|h[1-6])>", "\n", text)
    text = re.sub(r"(?i)<li>", "- ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = unescape(text)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r" *\n *", "\n", text)
    return text.strip()


def build_plain_excerpt(value, limit=140):
    text = rich_text_to_plain_text(value)
    if len(text) <= limit:
        return text

    shortened = text[:limit].rsplit(" ", 1)[0].strip()
    if not shortened:
        shortened = text[:limit].strip()
    return f"{shortened}..."


def generate_temp_password(length=10):
    # Avoid ambiguous characters like O/0, I/l/1 for easier manual typing.
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def avatar_theme(value):
    if not value:
        return "avatar-theme-1"
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    index = int(digest[:2], 16) % 6 + 1
    return f"avatar-theme-{index}"


def queue_generated_credentials(email, password, role, action):
    session["generated_credentials"] = {
        "email": email,
        "password": password,
        "role": role,
        "action": action,
        "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


def send_account_notification_placeholder(email, password, role, action):
    role_label = "HR" if role == "staff" else "Interview Panel"
    action_label = "Account Created" if action == "created" else "Password Reset"
    email_subject = f"{role_label} Access {action_label} - Staff Selection System"
    email_body = (
        f"Hello,\n\n"
        f"Your {role_label} access details have been {action_label.lower()}.\n"
        f"Login Email: {email}\n"
        f"Temporary Password: {password}\n\n"
        f"Please sign in and change your password immediately.\n\n"
        f"Regards,\n"
        f"System Administrator"
    )

    if not app.config.get("MAIL_ENABLED", False):
        app.logger.info(
            "MAIL_DISABLED role=%s action=%s recipient=%s temp_password=%s",
            role_label,
            action,
            email,
            password,
        )
        return False

    return send_system_email(email_subject, email_body, email)


def send_system_email(subject, body, recipient):
    required = ["MAIL_HOST", "MAIL_PORT", "MAIL_USER", "MAIL_PASS", "MAIL_FROM"]
    missing = [key for key in required if not app.config.get(key)]
    if missing:
        app.logger.warning(
            "MAIL_CONFIG_INCOMPLETE missing=%s recipient=%s",
            ",".join(missing),
            recipient,
        )
        return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = app.config["MAIL_FROM"]
    message["To"] = recipient
    message.set_content(body)

    try:
        if app.config.get("MAIL_USE_SSL", False):
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(
                app.config["MAIL_HOST"],
                app.config["MAIL_PORT"],
                context=context,
            ) as server:
                server.login(app.config["MAIL_USER"], app.config["MAIL_PASS"])
                server.send_message(message)
        else:
            with smtplib.SMTP(app.config["MAIL_HOST"], app.config["MAIL_PORT"]) as server:
                if app.config.get("MAIL_USE_TLS", True):
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                server.login(app.config["MAIL_USER"], app.config["MAIL_PASS"])
                server.send_message(message)
        return True
    except Exception as exc:
        app.logger.exception("MAIL_SEND_FAILED recipient=%s error=%s", recipient, exc)
        return False


def send_invitation_letter(application, invitation_type, interview_date, interview_time, venue):
    candidate_name = application.user.fullname
    candidate_email = application.user.email
    vacancy_title = application.job.title
    subject = f"{invitation_type} Invitation - {vacancy_title}"
    body = (
        f"Dear {candidate_name},\n\n"
        f"You are invited for a {invitation_type.lower()} for the role: {vacancy_title}.\n\n"
        f"Candidate Name: {candidate_name}\n"
        f"Candidate Email: {candidate_email}\n"
        f"Interview Date: {interview_date}\n"
        f"Interview Time: {interview_time}\n"
        f"Venue: {venue}\n\n"
        "Please arrive at least 15 minutes before the scheduled time.\n\n"
        "Regards,\n"
        "Interview Panel\n"
        "Staff Selection Management Platform"
    )
    return send_system_email(subject, body, candidate_email)


def parse_invitation_details(
    invitation_type_raw,
    interview_date_raw,
    interview_time_raw,
    venue_raw,
) -> tuple[InvitationDetails | None, str | None]:
    invitation_type = (invitation_type_raw or "Interview").strip()
    if invitation_type not in {"Interview", "Physical Assessment"}:
        invitation_type = "Interview"

    try:
        interview_date = datetime.strptime((interview_date_raw or "").strip(), "%Y-%m-%d").date()
    except ValueError:
        return None, "Enter a valid interview date."
    try:
        interview_time = datetime.strptime((interview_time_raw or "").strip(), "%H:%M").time()
    except ValueError:
        return None, "Enter a valid interview time."

    venue = (venue_raw or "").strip() or "UBA HQ, Interview Hall"
    return (
        {
            "invitation_type": invitation_type,
            "interview_date": interview_date,
            "interview_time": interview_time,
            "venue": venue,
        },
        None,
    )


def log_activity(action, entity_type=None, entity_id=None, details=None, user_id=None):
    actor_id = user_id
    if actor_id is None and current_user.is_authenticated:
        actor_id = current_user.id
    entry = AuditLog(
        user_id=actor_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details,
        ip_address=request.remote_addr if request else None,
    )
    db.session.add(entry)


@app.template_filter("richtext")
def richtext_filter(value):
    return format_rich_text(value)


@app.template_filter("plain_excerpt")
def plain_excerpt_filter(value, limit=140):
    return build_plain_excerpt(value, limit)


@app.template_filter("avatar_theme")
def avatar_theme_filter(value):
    return avatar_theme(value)


def process_and_save_profile_image(file_storage, save_path):
    if Image is None or ImageOps is None:
        file_storage.save(save_path)
        return
    assert Image is not None
    assert ImageOps is not None

    file_storage.stream.seek(0)
    image = Image.open(file_storage.stream)
    normalized_image = ImageOps.exif_transpose(image)
    assert normalized_image is not None
    image = normalized_image.convert("RGB")

    # Crop to centered square before resizing for consistent avatar display.
    width, height = image.size
    side = min(width, height)
    left = (width - side) // 2
    top = (height - side) // 2
    image = image.crop((left, top, left + side, top + side))

    target_size = 512
    image = image.resize((target_size, target_size), Image.Resampling.LANCZOS)
    image.save(save_path, format="JPEG", quality=82, optimize=True)


def role_required(*roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in roles:
                flash("You are not authorized to access this page.", "error")
                return redirect(url_for("dashboard"))
            return view_func(*args, **kwargs)

        return wrapper

    return decorator


def compute_score_breakdown(qualification, experience, job=None, applicant=None):
    # Weighted scoring to reduce harsh cutoffs and avoid discarding promising profiles.
    qualification_weights = {
        "OND/HND": 24,
        "BSc": 32,
        "MSc": 40,
        "PhD": 48,
    }
    qualification_points = qualification_weights.get(qualification, 24)

    safe_experience = max(experience or 0, 0)
    experience_points = min(safe_experience, 10) * 3
    experience_points += min(max(safe_experience - 10, 0), 10) * 1.5
    role_fit_points = 0

    if job:
        min_required = max(job.min_experience or 0, 0)
        delta = safe_experience - min_required
        if delta >= 2:
            role_fit_points = 12
        elif delta >= 0:
            role_fit_points = 8
        elif delta == -1:
            role_fit_points = 4
        else:
            role_fit_points = -2

    profile_bonus = 0
    if applicant:
        if applicant.cv_filename:
            profile_bonus += 3
        if applicant.education_level:
            profile_bonus += 2
        if applicant.location:
            profile_bonus += 1
        if applicant.phone:
            profile_bonus += 1
        if applicant.bio:
            profile_bonus += 1

    total = qualification_points + experience_points + role_fit_points + profile_bonus
    total = max(0, min(100, int(round(total))))
    return {
        "qualification_points": int(qualification_points),
        "experience_points": int(round(experience_points)),
        "role_fit_points": int(role_fit_points),
        "profile_bonus": int(profile_bonus),
        "total": total,
    }


def compute_score(qualification, experience, job=None, applicant=None):
    breakdown = compute_score_breakdown(
        qualification=qualification,
        experience=experience,
        job=job,
        applicant=applicant,
    )
    return breakdown["total"]


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_CV_EXTENSIONS
    )


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def create_default_users():
    admin = User.query.filter_by(email="admin@uba.local").first()
    if not admin:
        admin = User(
            fullname="System Admin",
            email="admin@uba.local",
            password_hash=generate_password_hash("admin123"),
            role="admin",
        )
        db.session.add(admin)

    staff = User.query.filter_by(email="staff@uba.local").first()
    if not staff:
        staff = User(
            fullname="HR Staff Reviewer",
            email="staff@uba.local",
            password_hash=generate_password_hash("staff123"),
            role="staff",
        )
        db.session.add(staff)

    panel = User.query.filter_by(email="panel@uba.local").first()
    if not panel:
        panel = User(
            fullname="Interview Panel",
            email="panel@uba.local",
            password_hash=generate_password_hash("panel123"),
            role="panel",
        )
        db.session.add(panel)
    db.session.commit()


def ensure_schema_columns():
    table_changes = {
        "user": [
            ("phone", "VARCHAR(30)"),
            ("location", "VARCHAR(120)"),
            ("education_level", "VARCHAR(50)"),
            ("years_experience", "INTEGER DEFAULT 0"),
            ("bio", "TEXT"),
            ("profile_image", "VARCHAR(255)"),
        ],
        "job": [
            ("location", "VARCHAR(120) DEFAULT 'Lagos, Nigeria'"),
            ("employment_type", "VARCHAR(40) DEFAULT 'Full-time'"),
            ("salary_min", "INTEGER"),
            ("salary_max", "INTEGER"),
            ("min_experience", "INTEGER DEFAULT 0"),
            ("deadline", "DATE"),
        ],
        "job_application": [
            ("assessment_score", "INTEGER"),
            ("assessment_remark", "TEXT"),
            ("shortlisted_at", "DATETIME"),
            ("assessed_at", "DATETIME"),
            ("assessed_by_id", "INTEGER"),
            ("reviewed_at", "DATETIME"),
        ],
    }
    inspector = inspect(db.engine)
    for table_name, columns in table_changes.items():
        existing = {column["name"] for column in inspector.get_columns(table_name)}
        for column_name, definition in columns:
            if column_name not in existing:
                db.session.execute(
                    db.text(
                        f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"  # noqa: S608
                    )
                )
    db.session.commit()


def seed_sample_jobs():
    if Job.query.count() > 0:
        return
    sample_jobs = [
        Job(
            title="Graduate Trainee - Banking Operations",
            department="Operations",
            location="Lagos, Nigeria",
            employment_type="Graduate Program",
            min_experience=0,
            salary_min=1500000,
            salary_max=2200000,
            description="Entry-level role for graduates interested in banking operations and customer service.",
        ),
        Job(
            title="Relationship Manager - Corporate Banking",
            department="Corporate Banking",
            location="Abuja, Nigeria",
            employment_type="Full-time",
            min_experience=4,
            salary_min=5400000,
            salary_max=7800000,
            description="Manage and grow corporate banking portfolios, strengthen client relationships, and hit revenue targets.",
        ),
        Job(
            title="IT Support Analyst",
            department="Information Technology",
            location="Lagos, Nigeria",
            employment_type="Full-time",
            min_experience=2,
            salary_min=3400000,
            salary_max=4600000,
            description="Provide IT support, troubleshoot hardware/software issues, and maintain uptime for business systems.",
        ),
    ]
    db.session.add_all(sample_jobs)
    db.session.commit()


with app.app_context():
    db.create_all()
    ensure_schema_columns()
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["PROFILE_UPLOAD_FOLDER"], exist_ok=True)
    create_default_users()
    seed_sample_jobs()


@app.route("/")
def home():
    active_jobs = Job.query.filter_by(is_active=True).order_by(Job.created_at.desc()).all()
    return render_template("index.html", jobs=active_jobs)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        fullname = request.form.get("fullname", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not fullname or not email or len(password) < 6:
            flash("Provide full name, email, and password of at least 6 characters.", "error")
            return redirect(url_for("register"))
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered. Please login.", "error")
            return redirect(url_for("login"))
        user = User(
            fullname=fullname,
            email=email,
            password_hash=generate_password_hash(password),
            role="user",
        )
        db.session.add(user)
        log_activity(
            action="user.registered",
            entity_type="user",
            details=f"New applicant account: {email}",
            user_id=None,
        )
        db.session.commit()
        flash("Registration successful. Please login.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid email or password.", "error")
            return redirect(url_for("login"))
        login_user(user)
        log_activity(
            action="user.login",
            entity_type="user",
            entity_id=user.id,
            details=f"User logged in: {user.email}",
            user_id=user.id,
        )
        db.session.commit()
        flash("Login successful.", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    user_id = current_user.id
    logout_user()
    log_activity(
        action="user.logout",
        entity_type="user",
        entity_id=user_id,
        details="User logged out",
        user_id=user_id,
    )
    db.session.commit()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


def allowed_image_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS
    )


@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == "admin":
        return redirect(url_for("admin_dashboard"))
    if current_user.role == "staff":
        return redirect(url_for("staff_dashboard"))
    if current_user.role == "panel":
        return redirect(url_for("panel_dashboard"))
    applications = (
        JobApplication.query.filter_by(user_id=current_user.id)
        .order_by(JobApplication.created_at.desc())
        .all()
    )
    total_applications = len(applications)
    pending_count = sum(1 for item in applications if item.review_status in UNDER_REVIEW_STATUSES)
    shortlisted_count = sum(1 for item in applications if item.review_status == "shortlisted")
    assessed_count = sum(1 for item in applications if item.review_status == "assessed")
    selected_count = sum(1 for item in applications if item.review_status == "accepted")
    profile_complete = all(
        [
            current_user.cv_filename,
            current_user.phone,
            current_user.location,
            current_user.education_level,
        ]
    )
    saved_jobs_count = SavedJob.query.filter_by(user_id=current_user.id).count()
    return render_template(
        "dashboard_user.html",
        applications=applications,
        total_applications=total_applications,
        pending_count=pending_count,
        shortlisted_count=shortlisted_count,
        assessed_count=assessed_count,
        selected_count=selected_count,
        profile_complete=profile_complete,
        saved_jobs_count=saved_jobs_count,
    )


@app.route("/account/delete", methods=["POST"])
@login_required
def delete_account():
    user = db.session.get(User, current_user.id)
    if user is None:
        flash("Account not found.", "error")
        return redirect(url_for("home"))
    deleted_user_id = user.id
    deleted_user_email = user.email
    logout_user()
    if user.cv_filename:
        cv_path = os.path.join(app.config["UPLOAD_FOLDER"], user.cv_filename)
        if os.path.exists(cv_path):
            os.remove(cv_path)
    if user.profile_image:
        image_path = os.path.join(app.config["PROFILE_UPLOAD_FOLDER"], user.profile_image)
        if os.path.exists(image_path):
            os.remove(image_path)
    db.session.delete(user)
    log_activity(
        action="user.deleted",
        entity_type="user",
        entity_id=deleted_user_id,
        details=f"Account deleted: {deleted_user_email}",
        user_id=deleted_user_id,
    )
    db.session.commit()
    flash("Account deleted successfully.", "success")
    return redirect(url_for("home"))


@app.route("/upload-cv", methods=["POST"])
@login_required
def upload_cv():
    cv_file = request.files.get("cv_file")
    if not cv_file or cv_file.filename == "":
        flash("Choose a CV file to upload.", "error")
        return redirect(url_for("dashboard"))
    if not allowed_file(cv_file.filename):
        flash("Only PDF, DOC, and DOCX files are allowed.", "error")
        return redirect(url_for("dashboard"))

    filename = cv_file.filename
    if not filename:
        flash("Choose a CV file to upload.", "error")
        return redirect(url_for("dashboard"))

    safe_name = secure_filename(filename)
    stored_name = f"user_{current_user.id}_{safe_name}"
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
    cv_file.save(save_path)

    user = db.session.get(User, current_user.id)
    if user is None:
        flash("User account not found.", "error")
        return redirect(url_for("dashboard"))
    user.cv_filename = stored_name
    log_activity(
        action="cv.uploaded",
        entity_type="user",
        entity_id=user.id,
        details=f"CV uploaded: {stored_name}",
    )
    db.session.commit()
    flash("CV uploaded successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/my-cv")
@login_required
def my_cv():
    if not current_user.cv_filename:
        flash("No CV uploaded yet.", "error")
        return redirect(url_for("dashboard"))
    return send_from_directory(app.config["UPLOAD_FOLDER"], current_user.cv_filename)


@app.route("/profile-image")
@login_required
def profile_image():
    if not current_user.profile_image:
        flash("No profile picture uploaded.", "error")
        return redirect(url_for("dashboard"))
    return send_from_directory(app.config["PROFILE_UPLOAD_FOLDER"], current_user.profile_image)


@app.route("/profile/upload-image", methods=["POST"])
@login_required
def upload_profile_image():
    if current_user.role != "user":
        flash("Only applicants can upload profile pictures.", "error")
        return redirect(url_for("dashboard"))
    image_file = request.files.get("profile_image")
    if not image_file or image_file.filename == "":
        flash("Choose an image to upload.", "error")
        return redirect(url_for("dashboard"))
    if not allowed_image_file(image_file.filename):
        flash("Only PNG, JPG, JPEG, and WEBP files are allowed.", "error")
        return redirect(url_for("dashboard"))

    filename = image_file.filename
    if not filename:
        flash("Choose an image to upload.", "error")
        return redirect(url_for("dashboard"))

    safe_name = secure_filename(filename)
    base_name = os.path.splitext(safe_name)[0]
    stored_name = f"user_{current_user.id}_{base_name}.jpg"
    save_path = os.path.join(app.config["PROFILE_UPLOAD_FOLDER"], stored_name)
    process_and_save_profile_image(image_file, save_path)

    user = db.session.get(User, current_user.id)
    if user is None:
        flash("User account not found.", "error")
        return redirect(url_for("dashboard"))
    if user.profile_image:
        old_path = os.path.join(app.config["PROFILE_UPLOAD_FOLDER"], user.profile_image)
        if os.path.exists(old_path):
            os.remove(old_path)
    user.profile_image = stored_name
    log_activity(
        action="profile_image.uploaded",
        entity_type="user",
        entity_id=user.id,
        details=f"Profile image uploaded: {stored_name}",
    )
    db.session.commit()
    flash("Profile picture uploaded successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/profile/delete-image", methods=["POST"])
@login_required
def delete_profile_image():
    if current_user.role != "user":
        flash("Only applicants can delete profile pictures.", "error")
        return redirect(url_for("dashboard"))
    user = db.session.get(User, current_user.id)
    if user is None:
        flash("User account not found.", "error")
        return redirect(url_for("dashboard"))
    if not user.profile_image:
        flash("No profile picture to delete.", "error")
        return redirect(url_for("dashboard"))

    image_path = os.path.join(app.config["PROFILE_UPLOAD_FOLDER"], user.profile_image)
    if os.path.exists(image_path):
        os.remove(image_path)
    user.profile_image = None
    log_activity(
        action="profile_image.deleted",
        entity_type="user",
        entity_id=user.id,
        details="Profile image removed",
    )
    db.session.commit()
    flash("Profile picture removed.", "success")
    return redirect(url_for("dashboard"))


@app.route("/applications/<int:application_id>/cv")
@login_required
@role_required("admin", "staff", "panel")
def application_cv(application_id):
    application = db.session.get(JobApplication, application_id)
    if not application:
        flash("Application not found.", "error")
        return redirect(url_for("dashboard"))
    if not application.user.cv_filename:
        flash("This applicant has not uploaded a CV yet.", "error")
        if current_user.role == "panel":
            return redirect(url_for("panel_dashboard"))
        return redirect(url_for("staff_dashboard"))

    log_activity(
        action="cv.reviewed",
        entity_type="application",
        entity_id=application.id,
        details=f"Reviewer opened CV for {application.user.email}",
    )
    db.session.commit()
    return send_from_directory(app.config["UPLOAD_FOLDER"], application.user.cv_filename)


@app.route("/jobs")
def jobs():
    keyword = request.args.get("q", "").strip()
    department = request.args.get("department", "").strip()
    location = request.args.get("location", "").strip()
    employment_type = request.args.get("type", "").strip()

    query = Job.query.filter_by(is_active=True)
    if keyword:
        query = query.filter(
            or_(
                Job.title.ilike(f"%{keyword}%"),
                Job.description.ilike(f"%{keyword}%"),
            )
        )
    if department:
        query = query.filter(Job.department == department)
    if location:
        query = query.filter(Job.location == location)
    if employment_type:
        query = query.filter(Job.employment_type == employment_type)

    all_jobs = query.order_by(Job.created_at.desc()).all()
    departments = [
        row[0]
        for row in db.session.query(Job.department).distinct().order_by(Job.department).all()
    ]
    locations = [
        row[0]
        for row in db.session.query(Job.location).distinct().order_by(Job.location).all()
    ]
    types = [
        row[0]
        for row in db.session.query(Job.employment_type).distinct().order_by(Job.employment_type).all()
    ]

    saved_job_ids = set()
    if current_user.is_authenticated and current_user.role == "user":
        saved_job_ids = {
            row[0]
            for row in db.session.query(SavedJob.job_id).filter_by(user_id=current_user.id).all()
        }

    return render_template(
        "jobs.html",
        jobs=all_jobs,
        departments=departments,
        locations=locations,
        types=types,
        selected_department=department,
        selected_location=location,
        selected_type=employment_type,
        keyword=keyword,
        saved_job_ids=saved_job_ids,
    )


@app.route("/apply")
def apply():
    return redirect(url_for("jobs"))


@app.route("/jobs/<int:job_id>/apply", methods=["GET", "POST"])
@login_required
def apply_for_job(job_id):
    if current_user.role != "user":
        flash("Only applicants can apply for vacancies.", "error")
        return redirect(url_for("dashboard"))

    job = db.session.get(Job, job_id)
    if not job or not job.is_active:
        flash("Job not found.", "error")
        return redirect(url_for("jobs"))

    already_applied = JobApplication.query.filter_by(
        user_id=current_user.id, job_id=job.id
    ).first()
    if already_applied:
        flash("You already applied for this job.", "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        qualification = request.form.get("qualification", "OND/HND")
        experience = int(request.form.get("experience", "0"))
        score = compute_score(
            qualification=qualification,
            experience=experience,
            job=job,
            applicant=current_user,
        )
        if score >= 75:
            auto_status = "strong"
        elif score >= 55:
            auto_status = "consider"
        else:
            auto_status = "review"

        application = JobApplication(
            user_id=current_user.id,
            job_id=job.id,
            qualification=qualification,
            experience=experience,
            score=score,
            auto_status=auto_status,
            review_status="under_review",
        )
        db.session.add(application)
        log_activity(
            action="application.submitted",
            entity_type="application",
            details=f"Applied for vacancy: {job.title}",
        )
        db.session.commit()
        flash("Application submitted successfully.", "success")
        return redirect(url_for("application_confirmation", application_id=application.id))

    return render_template("job_apply.html", job=job)


@app.route("/applications/<int:application_id>/confirmation")
@login_required
def application_confirmation(application_id):
    application = db.session.get(JobApplication, application_id)
    if not application:
        flash("Application not found.", "error")
        return redirect(url_for("dashboard"))
    if current_user.role != "admin" and application.user_id != current_user.id:
        flash("You are not authorized to view this application.", "error")
        return redirect(url_for("dashboard"))
    return render_template("application_confirmation.html", application=application)


@app.route("/profile/update", methods=["POST"])
@login_required
def update_profile():
    if current_user.role != "user":
        flash("Only applicants can update this profile.", "error")
        return redirect(url_for("dashboard"))

    user = db.session.get(User, current_user.id)
    if user is None:
        flash("User account not found.", "error")
        return redirect(url_for("dashboard"))
    user.phone = request.form.get("phone", "").strip() or None
    user.location = request.form.get("location", "").strip() or None
    user.education_level = request.form.get("education_level", "").strip() or None
    user.bio = request.form.get("bio", "").strip() or None
    years = request.form.get("years_experience", "0").strip()
    try:
        user.years_experience = max(0, int(years))
    except ValueError:
        flash("Years of experience must be a number.", "error")
        return redirect(url_for("dashboard"))
    log_activity(
        action="profile.updated",
        entity_type="user",
        entity_id=user.id,
        details="Applicant profile updated",
    )
    db.session.commit()
    flash("Profile updated successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/jobs/<int:job_id>/save", methods=["POST"])
@login_required
def save_job(job_id):
    if current_user.role != "user":
        flash("Only applicants can save vacancies.", "error")
        return redirect(url_for("jobs"))
    if not db.session.get(Job, job_id):
        flash("Job not found.", "error")
        return redirect(url_for("jobs"))
    existing = SavedJob.query.filter_by(user_id=current_user.id, job_id=job_id).first()
    if not existing:
        db.session.add(SavedJob(user_id=current_user.id, job_id=job_id))
        log_activity(
            action="vacancy.saved",
            entity_type="vacancy",
            entity_id=job_id,
            details="Vacancy saved by applicant",
        )
        db.session.commit()
    flash("Vacancy saved.", "success")
    query_args = {key: value for key, value in request.args.items() if not key.startswith("_")}
    return redirect(url_for("jobs", **cast(dict[str, Any], query_args)))


@app.route("/jobs/<int:job_id>/unsave", methods=["POST"])
@login_required
def unsave_job(job_id):
    saved = SavedJob.query.filter_by(user_id=current_user.id, job_id=job_id).first()
    if saved:
        db.session.delete(saved)
        log_activity(
            action="vacancy.unsaved",
            entity_type="vacancy",
            entity_id=job_id,
            details="Vacancy removed from saved list",
        )
        db.session.commit()
    flash("Vacancy removed from saved list.", "success")
    query_args = {key: value for key, value in request.args.items() if not key.startswith("_")}
    return redirect(url_for("jobs", **cast(dict[str, Any], query_args)))


def parse_vacancy_form_data() -> tuple[VacancyFormData | None, str | None]:
    title = request.form.get("title", "").strip()
    department = request.form.get("department", "").strip()
    location = request.form.get("location", "").strip() or "Lagos, Nigeria"
    employment_type = request.form.get("employment_type", "").strip() or "Full-time"
    min_experience_raw = request.form.get("min_experience", "0")
    salary_min = request.form.get("salary_min", "").strip()
    salary_max = request.form.get("salary_max", "").strip()
    deadline_raw = request.form.get("deadline", "").strip()
    description = request.form.get("description", "").strip()
    if re.search(r"</?[a-zA-Z][^>]*>", description):
        description = str(sanitize_rich_html(description))

    if not title or not department or not description:
        return None, "Title, department, and description are required."
    try:
        min_experience = max(0, int(min_experience_raw))
    except ValueError:
        return None, "Minimum experience must be a number."
    try:
        salary_min_value = int(salary_min) if salary_min else None
        salary_max_value = int(salary_max) if salary_max else None
    except ValueError:
        return None, "Salary range must be numeric."

    deadline = None
    if deadline_raw:
        try:
            deadline = datetime.strptime(deadline_raw, "%Y-%m-%d").date()
        except ValueError:
            return None, "Deadline must be in YYYY-MM-DD format."

    data: VacancyFormData = {
        "title": title,
        "department": department,
        "location": location,
        "employment_type": employment_type,
        "min_experience": min_experience,
        "salary_min": salary_min_value,
        "salary_max": salary_max_value,
        "deadline": deadline,
        "description": description,
    }
    return data, None


@app.route("/jobs/create", methods=["GET", "POST"])
@login_required
@role_required("admin", "staff")
def create_job():
    if request.method == "POST":
        data, error = parse_vacancy_form_data()
        if error:
            flash(error, "error")
            return redirect(url_for("create_job"))
        assert data is not None
        job = Job(
            **data,
        )
        db.session.add(job)
        db.session.flush()
        log_activity(
            action="vacancy.created",
            entity_type="vacancy",
            entity_id=job.id,
            details=f"Vacancy created: {data['title']} ({data['department']})",
        )
        db.session.commit()
        flash("Vacancy posted successfully.", "success")
        return redirect(url_for("staff_dashboard"))
    return render_template("job_form.html", job=None, edit_mode=False)


@app.route("/jobs/<int:job_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("admin", "staff")
def edit_job(job_id):
    job = db.session.get(Job, job_id)
    if not job:
        flash("Vacancy not found.", "error")
        return redirect(url_for("staff_dashboard"))

    if request.method == "POST":
        data, error = parse_vacancy_form_data()
        if error:
            flash(error, "error")
            return redirect(url_for("edit_job", job_id=job.id))
        assert data is not None
        for field, value in data.items():
            setattr(job, field, value)
        log_activity(
            action="vacancy.updated",
            entity_type="vacancy",
            entity_id=job.id,
            details=f"Vacancy updated: {job.title} ({job.department})",
        )
        db.session.commit()
        flash("Vacancy updated successfully.", "success")
        return redirect(url_for("staff_dashboard"))

    return render_template("job_form.html", job=job, edit_mode=True)


@app.route("/jobs/<int:job_id>/toggle-status", methods=["POST"])
@login_required
@role_required("admin", "staff")
def toggle_job_status(job_id):
    job = db.session.get(Job, job_id)
    if not job:
        flash("Vacancy not found.", "error")
        return redirect(url_for("staff_dashboard"))
    job.is_active = not job.is_active
    action_word = "reopened" if job.is_active else "closed"
    log_activity(
        action=f"vacancy.{action_word}",
        entity_type="vacancy",
        entity_id=job.id,
        details=f"Vacancy {action_word}: {job.title}",
    )
    db.session.commit()
    flash(f"Vacancy {action_word}.", "success")
    return redirect(url_for("staff_dashboard"))


@app.route("/staff/dashboard")
@login_required
@role_required("admin", "staff")
def staff_dashboard():
    jobs_list = Job.query.order_by(Job.created_at.desc()).all()
    status = request.args.get("status", "under_review").strip().lower()
    department = request.args.get("department", "").strip()
    cv_status = request.args.get("cv_status", "all").strip().lower()
    vacancy_id_raw = request.args.get("vacancy_id", "").strip()
    try:
        selected_vacancy_id = int(vacancy_id_raw) if vacancy_id_raw else None
    except ValueError:
        selected_vacancy_id = None
    valid_statuses = {"under_review", "pending", "shortlisted", "assessed", "accepted", "rejected"}
    valid_cv_statuses = {"all", "uploaded", "missing"}
    if status not in valid_statuses:
        status = "under_review"
    if cv_status not in valid_cv_statuses:
        cv_status = "all"

    if status in UNDER_REVIEW_STATUSES:
        query = JobApplication.query.filter(JobApplication.review_status.in_(UNDER_REVIEW_STATUSES))
    else:
        query = JobApplication.query.filter_by(review_status=status)
    if selected_vacancy_id:
        query = query.filter(JobApplication.job_id == selected_vacancy_id)
    if department:
        query = query.filter(JobApplication.job.has(Job.department == department))
    if cv_status == "uploaded":
        query = query.filter(JobApplication.user.has(User.cv_filename.isnot(None)))
    elif cv_status == "missing":
        query = query.filter(JobApplication.user.has(User.cv_filename.is_(None)))

    filtered_applications = query.order_by(JobApplication.created_at.desc()).all()
    score_breakdowns = {
        item.id: summarize_score_breakdown(item) for item in filtered_applications
    }
    vacancy_applications = []
    if selected_vacancy_id:
        vacancy_applications = (
            JobApplication.query.filter_by(job_id=selected_vacancy_id)
            .order_by(JobApplication.created_at.desc())
            .all()
        )
    for item in vacancy_applications:
        score_breakdowns[item.id] = summarize_score_breakdown(item)
    pipeline_counts = {
        "under_review": JobApplication.query.filter(JobApplication.review_status.in_(UNDER_REVIEW_STATUSES)).count(),
        "shortlisted": JobApplication.query.filter_by(review_status="shortlisted").count(),
        "assessed": JobApplication.query.filter_by(review_status="assessed").count(),
        "accepted": JobApplication.query.filter_by(review_status="accepted").count(),
        "rejected": JobApplication.query.filter_by(review_status="rejected").count(),
    }
    departments = [row[0] for row in db.session.query(Job.department).distinct().order_by(Job.department).all()]
    return render_template(
        "staff_dashboard.html",
        jobs=jobs_list,
        applications=filtered_applications,
        active_status=status,
        selected_department=department,
        selected_cv_status=cv_status,
        selected_vacancy_id=selected_vacancy_id,
        vacancy_options=jobs_list,
        vacancy_applications=vacancy_applications,
        score_breakdowns=score_breakdowns,
        departments=departments,
        pipeline_counts=pipeline_counts,
        can_shortlist=True,
        can_assess=True,
        can_decide=True,
        can_invite=False,
        can_bulk=True,
        dashboard_route="staff_dashboard",
        dashboard_title="Selection Review Dashboard",
        dashboard_subtitle="Manage vacancies and run shortlisting, assessment, and final selection decisions.",
    )


@app.route("/panel/dashboard")
@login_required
@role_required("panel")
def panel_dashboard():
    status = request.args.get("status", "shortlisted").strip().lower()
    department = request.args.get("department", "").strip()
    cv_status = request.args.get("cv_status", "all").strip().lower()
    vacancy_id_raw = request.args.get("vacancy_id", "").strip()
    try:
        selected_vacancy_id = int(vacancy_id_raw) if vacancy_id_raw else None
    except ValueError:
        selected_vacancy_id = None
    valid_statuses = {"shortlisted", "assessed", "accepted", "rejected"}
    valid_cv_statuses = {"all", "uploaded", "missing"}
    if status not in valid_statuses:
        status = "shortlisted"
    if cv_status not in valid_cv_statuses:
        cv_status = "all"

    query = JobApplication.query.filter(JobApplication.review_status.in_(valid_statuses)).filter_by(review_status=status)
    if selected_vacancy_id:
        query = query.filter(JobApplication.job_id == selected_vacancy_id)
    if department:
        query = query.filter(JobApplication.job.has(Job.department == department))
    if cv_status == "uploaded":
        query = query.filter(JobApplication.user.has(User.cv_filename.isnot(None)))
    elif cv_status == "missing":
        query = query.filter(JobApplication.user.has(User.cv_filename.is_(None)))

    filtered_applications = query.order_by(JobApplication.created_at.desc()).all()
    score_breakdowns = {
        item.id: summarize_score_breakdown(item) for item in filtered_applications
    }
    vacancy_applications = []
    if selected_vacancy_id:
        vacancy_applications = (
            JobApplication.query.filter_by(job_id=selected_vacancy_id)
            .order_by(JobApplication.created_at.desc())
            .all()
        )
    for item in vacancy_applications:
        score_breakdowns[item.id] = summarize_score_breakdown(item)
    vacancy_options = Job.query.order_by(Job.created_at.desc()).all()
    pipeline_counts = {
        "shortlisted": JobApplication.query.filter_by(review_status="shortlisted").count(),
        "assessed": JobApplication.query.filter_by(review_status="assessed").count(),
        "accepted": JobApplication.query.filter_by(review_status="accepted").count(),
        "rejected": JobApplication.query.filter_by(review_status="rejected").count(),
    }
    departments = [row[0] for row in db.session.query(Job.department).distinct().order_by(Job.department).all()]
    return render_template(
        "staff_dashboard.html",
        jobs=[],
        applications=filtered_applications,
        active_status=status,
        selected_department=department,
        selected_cv_status=cv_status,
        selected_vacancy_id=selected_vacancy_id,
        vacancy_options=vacancy_options,
        vacancy_applications=vacancy_applications,
        score_breakdowns=score_breakdowns,
        departments=departments,
        pipeline_counts=pipeline_counts,
        can_shortlist=False,
        can_assess=True,
        can_decide=False,
        can_invite=True,
        can_bulk=False,
        dashboard_route="panel_dashboard",
        dashboard_title="Interview Panel Dashboard",
        dashboard_subtitle="Review shortlisted candidates and record structured assessment outcomes.",
    )


def summarize_score_breakdown(application):
    breakdown = compute_score_breakdown(
        qualification=application.qualification,
        experience=application.experience,
        job=application.job,
        applicant=application.user,
    )
    return (
        f"Q:{breakdown['qualification_points']} "
        f"+ Exp:{breakdown['experience_points']} "
        f"+ Fit:{breakdown['role_fit_points']} "
        f"+ Profile:{breakdown['profile_bonus']} "
        f"= {breakdown['total']}"
    )


@app.route("/applications/bulk-update", methods=["POST"])
@login_required
@role_required("admin", "staff")
def bulk_update_applications():
    action = request.form.get("bulk_action", "").strip().lower()
    selected_ids_raw = request.form.getlist("application_ids")
    if action not in {"shortlist", "reject"}:
        flash("Invalid bulk action.", "error")
        return redirect(url_for("staff_dashboard"))
    if not selected_ids_raw:
        flash("Select at least one application for bulk action.", "error")
        return redirect(url_for("staff_dashboard"))

    valid_ids = []
    for value in selected_ids_raw:
        try:
            valid_ids.append(int(value))
        except ValueError:
            continue

    applications = JobApplication.query.filter(JobApplication.id.in_(valid_ids)).all()
    updated = 0
    skipped = 0
    for application in applications:
        if action == "shortlist":
            if application.review_status not in UNDER_REVIEW_STATUSES:
                skipped += 1
                continue
            application.review_status = "shortlisted"
            application.shortlisted_at = datetime.utcnow()
            application.reviewed_by_id = current_user.id
            application.reviewed_at = datetime.utcnow()
            updated += 1
            log_activity(
                action="application.shortlisted",
                entity_type="application",
                entity_id=application.id,
                details=f"Bulk shortlisted for vacancy: {application.job.title}",
            )
        elif action == "reject":
            if application.review_status not in UNDER_REVIEW_STATUSES.union({"shortlisted", "assessed"}):
                skipped += 1
                continue
            application.review_status = "rejected"
            application.reviewed_by_id = current_user.id
            application.reviewed_at = datetime.utcnow()
            updated += 1
            log_activity(
                action="application.rejected",
                entity_type="application",
                entity_id=application.id,
                details=f"Bulk rejected for vacancy: {application.job.title}",
            )

    db.session.commit()
    flash(f"Bulk action complete. Updated: {updated}, Skipped: {skipped}.", "success")
    status = request.form.get("status", "under_review").strip().lower()
    department = request.form.get("department", "").strip()
    cv_status = request.form.get("cv_status", "all").strip().lower()
    vacancy_id = request.form.get("vacancy_id", "").strip()
    return redirect(
        url_for(
            "staff_dashboard",
            status=status,
            department=department,
            cv_status=cv_status,
            vacancy_id=vacancy_id,
        )
    )


@app.route("/admin/dashboard")
@login_required
@role_required("admin")
def admin_dashboard():
    users_count = User.query.count()
    jobs_count = Job.query.count()
    applications_count = JobApplication.query.count()
    pending_count = JobApplication.query.filter(JobApplication.review_status.in_(UNDER_REVIEW_STATUSES)).count()
    shortlisted_count = JobApplication.query.filter_by(review_status="shortlisted").count()
    assessed_count = JobApplication.query.filter_by(review_status="assessed").count()
    accepted_count = JobApplication.query.filter_by(review_status="accepted").count()
    rejected_count = JobApplication.query.filter_by(review_status="rejected").count()
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    managed_accounts = (
        User.query.filter(User.role.in_(["staff", "panel"]))
        .order_by(User.created_at.desc())
        .all()
    )
    generated_credentials = session.pop("generated_credentials", None)
    return render_template(
        "admin_dashboard.html",
        users_count=users_count,
        jobs_count=jobs_count,
        applications_count=applications_count,
        pending_count=pending_count,
        shortlisted_count=shortlisted_count,
        assessed_count=assessed_count,
        accepted_count=accepted_count,
        rejected_count=rejected_count,
        recent_users=recent_users,
        managed_accounts=managed_accounts,
        generated_credentials=generated_credentials,
    )


@app.route("/admin/accounts/create", methods=["POST"])
@login_required
@role_required("admin")
def create_managed_account():
    fullname = request.form.get("fullname", "").strip()
    email = request.form.get("email", "").strip().lower()
    role = request.form.get("role", "").strip().lower()
    manual_password = request.form.get("password", "").strip()
    if role not in {"staff", "panel"}:
        flash("Role must be HR (staff) or Panel.", "error")
        return redirect(url_for("admin_dashboard"))
    if not fullname or not email:
        flash("Full name and email are required.", "error")
        return redirect(url_for("admin_dashboard"))
    existing = User.query.filter_by(email=email).first()
    if existing:
        flash("Email already exists.", "error")
        return redirect(url_for("admin_dashboard"))

    if manual_password and len(manual_password) < 6:
        flash("Password must be at least 6 characters.", "error")
        return redirect(url_for("admin_dashboard"))
    password = manual_password or generate_temp_password()
    user = User(
        fullname=fullname,
        email=email,
        password_hash=generate_password_hash(password),
        role=role,
    )
    db.session.add(user)
    db.session.flush()
    log_activity(
        action="admin.account_created",
        entity_type="user",
        entity_id=user.id,
        details=f"Admin created {role} account: {email}",
    )
    queue_generated_credentials(email=email, password=password, role=role, action="created")
    sent = send_account_notification_placeholder(email=email, password=password, role=role, action="created")
    db.session.commit()
    role_label = "HR" if role == "staff" else "Panel"
    flash(f"{role_label} account created. Credentials are shown below once.", "success")
    if sent:
        flash(f"Notification email sent to {email}.", "success")
    else:
        flash("Email notification not sent. Check mail settings or logs.", "error")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/accounts/<int:user_id>/reset-password", methods=["POST"])
@login_required
@role_required("admin")
def reset_managed_account_password(user_id):
    user = db.session.get(User, user_id)
    if not user or user.role not in {"staff", "panel"}:
        flash("Managed account not found.", "error")
        return redirect(url_for("admin_dashboard"))
    manual_password = request.form.get("new_password", "").strip()
    if manual_password and len(manual_password) < 6:
        flash("New password must be at least 6 characters.", "error")
        return redirect(url_for("admin_dashboard"))
    password = manual_password or generate_temp_password()
    user.password_hash = generate_password_hash(password)
    log_activity(
        action="admin.password_reset",
        entity_type="user",
        entity_id=user.id,
        details=f"Admin reset password for {user.email}",
    )
    queue_generated_credentials(email=user.email, password=password, role=user.role, action="reset")
    sent = send_account_notification_placeholder(email=user.email, password=password, role=user.role, action="reset")
    db.session.commit()
    role_label = "HR" if user.role == "staff" else "Panel"
    flash(f"{role_label} password reset. New credentials are shown below once.", "success")
    if sent:
        flash(f"Notification email sent to {user.email}.", "success")
    else:
        flash("Email notification not sent. Check mail settings or logs.", "error")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/accounts/<int:user_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def delete_managed_account(user_id):
    user = db.session.get(User, user_id)
    if not user or user.role not in {"staff", "panel"}:
        flash("Managed account not found.", "error")
        return redirect(url_for("admin_dashboard"))
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("admin_dashboard"))

    deleted_email = user.email
    deleted_role = user.role

    JobApplication.query.filter_by(reviewed_by_id=user.id).update({"reviewed_by_id": None})
    JobApplication.query.filter_by(assessed_by_id=user.id).update({"assessed_by_id": None})
    db.session.delete(user)
    log_activity(
        action="admin.account_deleted",
        entity_type="user",
        entity_id=user.id,
        details=f"Admin deleted {deleted_role} account: {deleted_email}",
    )
    db.session.commit()
    flash("Managed account deleted successfully.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/mail/test", methods=["POST"])
@login_required
@role_required("admin")
def test_mail_settings():
    recipient = request.form.get("test_email", "").strip() or current_user.email
    if "@" not in recipient:
        flash("Enter a valid test email address.", "error")
        return redirect(url_for("admin_dashboard"))
    if not app.config.get("MAIL_ENABLED", False):
        flash("Mail is disabled. Set MAIL_ENABLED=true before testing.", "error")
        return redirect(url_for("admin_dashboard"))

    subject = "Mail Settings Test - Staff Selection System"
    body = (
        "This is a test email from the Staff Selection Management Platform.\n\n"
        "If you received this, SMTP settings are configured correctly."
    )
    sent = send_system_email(subject, body, recipient)
    if sent:
        flash(f"Test email sent successfully to {recipient}.", "success")
    else:
        flash("Test email failed. Check SMTP settings and server logs.", "error")
    return redirect(url_for("admin_dashboard"))


@app.route("/hr/review")
@login_required
@role_required("admin", "staff")
def hr_review():
    vacancy_id_raw = request.args.get("vacancy_id", "").strip()
    try:
        selected_vacancy_id = int(vacancy_id_raw) if vacancy_id_raw else None
    except ValueError:
        selected_vacancy_id = None

    query = JobApplication.query.filter(JobApplication.review_status.in_(UNDER_REVIEW_STATUSES))
    if selected_vacancy_id:
        query = query.filter(JobApplication.job_id == selected_vacancy_id)
    applications = query.order_by(JobApplication.created_at.desc()).all()
    vacancy_options = Job.query.filter_by(is_active=True).order_by(Job.created_at.desc()).all()
    return render_template(
        "hr_review.html",
        applications=applications,
        vacancy_options=vacancy_options,
        selected_vacancy_id=selected_vacancy_id,
    )


@app.route("/applications/<int:application_id>/shortlist", methods=["POST"])
@login_required
@role_required("admin", "staff")
def shortlist_application(application_id):
    application = db.session.get(JobApplication, application_id)
    if not application:
        flash("Application not found.", "error")
        return redirect(url_for("staff_dashboard"))
    if application.review_status not in UNDER_REVIEW_STATUSES:
        flash("Only under-review applications can be shortlisted.", "error")
        return redirect(url_for("staff_dashboard", status=application.review_status))

    application.review_status = "shortlisted"
    application.shortlisted_at = datetime.utcnow()
    application.reviewed_by_id = current_user.id
    application.reviewed_at = datetime.utcnow()
    log_activity(
        action="application.shortlisted",
        entity_type="application",
        entity_id=application.id,
        details=f"Shortlisted for vacancy: {application.job.title}",
    )
    db.session.commit()
    flash("Success: candidate moved from UNDER_REVIEW to SHORTLISTED.", "success")
    return redirect(url_for("staff_dashboard", status="shortlisted"))


@app.route("/applications/<int:application_id>/reject", methods=["POST"])
@login_required
@role_required("admin", "staff")
def reject_application(application_id):
    application = db.session.get(JobApplication, application_id)
    if not application:
        flash("Application not found.", "error")
        return redirect(url_for("hr_review"))
    if application.review_status not in UNDER_REVIEW_STATUSES:
        flash("Only under-review applications can be rejected from HR screening.", "error")
        return redirect(url_for("hr_review"))

    application.review_status = "rejected"
    application.reviewed_by_id = current_user.id
    application.reviewed_at = datetime.utcnow()
    log_activity(
        action="application.rejected",
        entity_type="application",
        entity_id=application.id,
        details=f"Rejected during HR screening for vacancy: {application.job.title}",
    )
    db.session.commit()
    flash("Success: candidate moved from UNDER_REVIEW to REJECTED.", "success")
    return redirect(url_for("hr_review"))


@app.route("/applications/<int:application_id>/assess", methods=["POST"])
@login_required
@role_required("admin", "staff", "panel")
def assess_application(application_id):
    dashboard_endpoint = "panel_dashboard" if current_user.role == "panel" else "staff_dashboard"
    application = db.session.get(JobApplication, application_id)
    if not application:
        flash("Application not found.", "error")
        return redirect(url_for(dashboard_endpoint))
    if application.review_status not in {"shortlisted", "assessed"}:
        flash("Only shortlisted applications can be assessed.", "error")
        return redirect(url_for(dashboard_endpoint, status=application.review_status))

    score_raw = request.form.get("assessment_score", "").strip()
    remark = request.form.get("assessment_remark", "").strip()
    try:
        assessment_score = int(score_raw)
    except ValueError:
        flash("Assessment score must be a number between 0 and 100.", "error")
        return redirect(url_for(dashboard_endpoint, status="shortlisted"))
    if assessment_score < 0 or assessment_score > 100:
        flash("Assessment score must be between 0 and 100.", "error")
        return redirect(url_for(dashboard_endpoint, status="shortlisted"))

    application.assessment_score = assessment_score
    application.assessment_remark = remark or None
    application.assessed_at = datetime.utcnow()
    application.assessed_by_id = current_user.id
    application.review_status = "assessed"
    log_activity(
        action="application.assessed",
        entity_type="application",
        entity_id=application.id,
        details=f"Assessment score: {assessment_score}",
    )
    db.session.commit()
    flash("Assessment recorded successfully.", "success")
    return redirect(url_for(dashboard_endpoint, status="assessed"))


@app.route("/panel/invitations", methods=["GET", "POST"])
@login_required
@role_required("panel")
def panel_invitations():
    vacancy_id_raw = request.values.get("vacancy_id", "").strip()
    application_id_raw = request.values.get("application_id", "").strip()
    try:
        selected_vacancy_id = int(vacancy_id_raw) if vacancy_id_raw else None
    except ValueError:
        selected_vacancy_id = None
    try:
        selected_application_id = int(application_id_raw) if application_id_raw else None
    except ValueError:
        selected_application_id = None

    vacancy_options = (
        Job.query.join(JobApplication, Job.id == JobApplication.job_id)
        .filter(JobApplication.review_status == "shortlisted")
        .distinct()
        .order_by(Job.created_at.desc())
        .all()
    )

    shortlisted_query = JobApplication.query.filter_by(review_status="shortlisted")
    if selected_vacancy_id:
        shortlisted_query = shortlisted_query.filter(JobApplication.job_id == selected_vacancy_id)
    shortlisted_applications = shortlisted_query.order_by(JobApplication.created_at.desc()).all()

    if request.method == "POST":
        details, error = parse_invitation_details(
            invitation_type_raw=request.form.get("invitation_type"),
            interview_date_raw=request.form.get("interview_date"),
            interview_time_raw=request.form.get("interview_time"),
            venue_raw=request.form.get("venue"),
        )
        if error:
            flash(error, "error")
            return redirect(
                url_for(
                    "panel_invitations",
                    vacancy_id=selected_vacancy_id,
                    application_id=selected_application_id,
                )
            )
        assert details is not None

        selected_ids_raw = request.form.getlist("application_ids")
        selected_ids = []
        for value in selected_ids_raw:
            try:
                selected_ids.append(int(value))
            except ValueError:
                continue
        if not selected_ids and selected_application_id:
            selected_ids.append(selected_application_id)
        if not selected_ids:
            flash("Select at least one shortlisted candidate.", "error")
            return redirect(
                url_for(
                    "panel_invitations",
                    vacancy_id=selected_vacancy_id,
                    application_id=selected_application_id,
                )
            )

        target_query = JobApplication.query.filter(
            JobApplication.id.in_(selected_ids),
            JobApplication.review_status == "shortlisted",
        )
        if selected_vacancy_id:
            target_query = target_query.filter(JobApplication.job_id == selected_vacancy_id)
        targets = target_query.all()
        if not targets:
            flash("No eligible shortlisted candidates found for this vacancy.", "error")
            return redirect(url_for("panel_invitations", vacancy_id=selected_vacancy_id))

        sent_count = 0
        failed_count = 0
        for application in targets:
            sent = send_invitation_letter(
                application=application,
                invitation_type=details["invitation_type"],
                interview_date=details["interview_date"].strftime("%Y-%m-%d"),
                interview_time=details["interview_time"].strftime("%H:%M"),
                venue=details["venue"],
            )
            if sent:
                sent_count += 1
            else:
                failed_count += 1
            log_activity(
                action="application.invitation_sent",
                entity_type="application",
                entity_id=application.id,
                details=(
                    f"{details['invitation_type']} letter sent to {application.user.email}; "
                    f"schedule={details['interview_date'].strftime('%Y-%m-%d')} "
                    f"{details['interview_time'].strftime('%H:%M')}; venue={details['venue']}; "
                    f"mail_status={'sent' if sent else 'failed'}"
                ),
            )
        db.session.commit()
        if failed_count == 0:
            flash(f"Invitation sent successfully to {sent_count} shortlisted candidate(s).", "success")
        else:
            flash(
                f"Invitation processing complete. Sent: {sent_count}, Failed: {failed_count}.",
                "error",
            )
        keep_application_id = selected_application_id or (targets[0].id if targets else None)
        return redirect(
            url_for(
                "panel_invitations",
                vacancy_id=selected_vacancy_id,
                application_id=keep_application_id,
            )
        )

    selected_application = None
    if shortlisted_applications:
        if selected_application_id:
            selected_application = next(
                (item for item in shortlisted_applications if item.id == selected_application_id),
                None,
            )
        if not selected_application:
            selected_application = shortlisted_applications[0]
            selected_application_id = selected_application.id

    return render_template(
        "panel_invitations.html",
        vacancy_options=vacancy_options,
        selected_vacancy_id=selected_vacancy_id,
        shortlisted_applications=shortlisted_applications,
        selected_application=selected_application,
        selected_application_id=selected_application_id,
    )


@app.route("/applications/<int:application_id>/send-invitation", methods=["POST"])
@login_required
@role_required("panel", "admin", "staff")
def send_application_invitation(application_id):
    dashboard_endpoint = "panel_dashboard" if current_user.role == "panel" else "staff_dashboard"
    application = db.session.get(JobApplication, application_id)
    if not application:
        flash("Application not found.", "error")
        return redirect(url_for(dashboard_endpoint))
    if application.review_status != "shortlisted":
        flash("Invitations can only be sent for shortlisted candidates.", "error")
        return redirect(url_for(dashboard_endpoint, status=application.review_status))

    details, error = parse_invitation_details(
        invitation_type_raw=request.form.get("invitation_type"),
        interview_date_raw=request.form.get("interview_date"),
        interview_time_raw=request.form.get("interview_time"),
        venue_raw=request.form.get("venue"),
    )
    if error:
        flash(error, "error")
        return redirect(url_for(dashboard_endpoint, status="shortlisted"))
    assert details is not None

    scheduled_label = (
        f"{details['interview_date'].strftime('%Y-%m-%d')} "
        f"{details['interview_time'].strftime('%H:%M')}"
    )
    sent = send_invitation_letter(
        application=application,
        invitation_type=details["invitation_type"],
        interview_date=details["interview_date"].strftime("%Y-%m-%d"),
        interview_time=details["interview_time"].strftime("%H:%M"),
        venue=details["venue"],
    )
    log_activity(
        action="application.invitation_sent",
        entity_type="application",
        entity_id=application.id,
        details=(
            f"{details['invitation_type']} letter sent to {application.user.email}; "
            f"schedule={scheduled_label}; venue={details['venue']}"
        ),
    )
    db.session.commit()

    if sent:
        flash(
            f"{details['invitation_type']} letter sent to {application.user.fullname} "
            f"({application.user.email}) for {scheduled_label}.",
            "success",
        )
    else:
        flash(
            "Invitation generated, but email was not sent. Check mail settings/logs.",
            "error",
        )
    return redirect(url_for(dashboard_endpoint, status="shortlisted"))


@app.route("/applications/<int:application_id>/invitation-letter", methods=["GET"])
@login_required
@role_required("panel", "admin", "staff")
def invitation_letter(application_id):
    dashboard_endpoint = "panel_dashboard" if current_user.role == "panel" else "staff_dashboard"
    application = db.session.get(JobApplication, application_id)
    if not application:
        flash("Application not found.", "error")
        return redirect(url_for(dashboard_endpoint))
    if application.review_status != "shortlisted":
        flash("Letter can only be prepared for shortlisted candidates.", "error")
        return redirect(url_for(dashboard_endpoint, status=application.review_status))

    details, error = parse_invitation_details(
        invitation_type_raw=request.args.get("invitation_type"),
        interview_date_raw=request.args.get("interview_date"),
        interview_time_raw=request.args.get("interview_time"),
        venue_raw=request.args.get("venue"),
    )
    if error:
        flash(f"{error} before previewing letter.", "error")
        return redirect(url_for(dashboard_endpoint, status="shortlisted"))
    assert details is not None

    return render_template(
        "invitation_letter.html",
        application=application,
        invitation_type=details["invitation_type"],
        interview_date=details["interview_date"].strftime("%A, %d %B %Y"),
        interview_time=details["interview_time"].strftime("%H:%M"),
        venue=details["venue"],
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    )


@app.route("/applications/<int:application_id>/review", methods=["POST"])
@login_required
@role_required("admin", "staff")
def review_application(application_id):
    decision = request.form.get("decision", "").strip().lower()
    if decision not in {"accepted", "rejected"}:
        flash("Invalid review decision.", "error")
        return redirect(url_for("staff_dashboard"))

    application = db.session.get(JobApplication, application_id)
    if not application:
        flash("Application not found.", "error")
        return redirect(url_for("staff_dashboard"))
    if application.review_status not in {"shortlisted", "assessed"}:
        flash("Application must be shortlisted or assessed before final decision.", "error")
        return redirect(url_for("staff_dashboard", status=application.review_status))

    application.review_status = decision
    application.reviewed_by_id = current_user.id
    application.reviewed_at = datetime.utcnow()
    log_activity(
        action=f"application.{decision}",
        entity_type="application",
        entity_id=application.id,
        details=f"Final decision set to {decision}",
    )
    db.session.commit()
    flash(f"Application marked as {decision}.", "success")
    return redirect(url_for("staff_dashboard", status=decision))


@app.route("/shortlisted")
@login_required
@role_required("admin", "staff", "panel")
def shortlisted():
    shortlisted_applications = (
        JobApplication.query.filter_by(review_status="shortlisted")
        .order_by(JobApplication.shortlisted_at.desc(), JobApplication.created_at.desc())
        .all()
    )
    return render_template("shortlisted.html", applications=shortlisted_applications)


@app.route("/selected")
@login_required
@role_required("admin", "staff", "panel")
def selected():
    accepted_applications = (
        JobApplication.query.filter_by(review_status="accepted")
        .order_by(JobApplication.assessment_score.desc(), JobApplication.score.desc())
        .limit(50)
        .all()
    )
    return render_template("selected.html", applications=accepted_applications)


@app.route("/reports/shortlisted.csv")
@login_required
@role_required("admin", "staff", "panel")
def shortlisted_csv():
    records = (
        JobApplication.query.filter_by(review_status="shortlisted")
        .order_by(JobApplication.shortlisted_at.desc(), JobApplication.created_at.desc())
        .all()
    )
    out = StringIO()
    writer = csv.writer(out)
    writer.writerow(["Application ID", "Applicant", "Email", "Vacancy", "Department", "Auto Score", "Shortlisted At"])
    for item in records:
        writer.writerow(
            [
                item.id,
                item.user.fullname,
                item.user.email,
                item.job.title,
                item.job.department,
                item.score,
                item.shortlisted_at.strftime("%Y-%m-%d %H:%M:%S") if item.shortlisted_at else "",
            ]
        )
    return Response(
        out.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=shortlisted_candidates.csv"},
    )


@app.route("/reports/selected.csv")
@login_required
@role_required("admin", "staff", "panel")
def selected_csv():
    records = (
        JobApplication.query.filter_by(review_status="accepted")
        .order_by(JobApplication.assessment_score.desc(), JobApplication.score.desc())
        .all()
    )
    out = StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "Application ID",
            "Applicant",
            "Email",
            "Vacancy",
            "Department",
            "Auto Score",
            "Assessment Score",
            "Assessment Remark",
        ]
    )
    for item in records:
        writer.writerow(
            [
                item.id,
                item.user.fullname,
                item.user.email,
                item.job.title,
                item.job.department,
                item.score,
                item.assessment_score if item.assessment_score is not None else "",
                item.assessment_remark or "",
            ]
        )
    return Response(
        out.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=selected_candidates.csv"},
    )


@app.route("/audit-logs")
@login_required
@role_required("admin", "staff")
def audit_logs():
    selected_action = request.args.get("action", "").strip()
    start_date_raw = request.args.get("start_date", "").strip()
    end_date_raw = request.args.get("end_date", "").strip()

    query = AuditLog.query

    if selected_action:
        query = query.filter(AuditLog.action == selected_action)

    if start_date_raw:
        try:
            start_date = datetime.strptime(start_date_raw, "%Y-%m-%d")
            query = query.filter(AuditLog.created_at >= start_date)
        except ValueError:
            flash("Invalid start date format. Use YYYY-MM-DD.", "error")
            return redirect(url_for("audit_logs"))

    if end_date_raw:
        try:
            end_date = datetime.strptime(end_date_raw, "%Y-%m-%d") + timedelta(days=1)
            query = query.filter(AuditLog.created_at < end_date)
        except ValueError:
            flash("Invalid end date format. Use YYYY-MM-DD.", "error")
            return redirect(url_for("audit_logs"))

    logs = query.order_by(AuditLog.created_at.desc()).limit(300).all()
    actions = [row[0] for row in db.session.query(AuditLog.action).distinct().order_by(AuditLog.action).all()]

    return render_template(
        "audit_logs.html",
        logs=logs,
        actions=actions,
        selected_action=selected_action,
        start_date=start_date_raw,
        end_date=end_date_raw,
    )


if __name__ == "__main__":
    app.run(debug=True)

