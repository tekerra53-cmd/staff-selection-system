from datetime import date, datetime
from typing import TYPE_CHECKING

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    cv_filename = db.Column(db.String(255), nullable=True)
    profile_image = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(30), nullable=True)
    location = db.Column(db.String(120), nullable=True)
    education_level = db.Column(db.String(50), nullable=True)
    years_experience = db.Column(db.Integer, nullable=True, default=0)
    bio = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    applications = db.relationship(
        "JobApplication",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="JobApplication.user_id",
    )
    audit_logs = db.relationship(
        "AuditLog",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="AuditLog.user_id",
    )

    if TYPE_CHECKING:
        def __init__(
            self,
            *,
            fullname: str,
            email: str,
            password_hash: str,
            role: str = "user",
            cv_filename: str | None = None,
            profile_image: str | None = None,
            phone: str | None = None,
            location: str | None = None,
            education_level: str | None = None,
            years_experience: int | None = 0,
            bio: str | None = None,
        ) -> None: ...


class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(120), nullable=False, default="Lagos, Nigeria")
    employment_type = db.Column(db.String(40), nullable=False, default="Full-time")
    salary_min = db.Column(db.Integer, nullable=True)
    salary_max = db.Column(db.Integer, nullable=True)
    min_experience = db.Column(db.Integer, nullable=False, default=0)
    deadline = db.Column(db.Date, nullable=True)
    description = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    applications = db.relationship(
        "JobApplication", back_populates="job", cascade="all, delete-orphan"
    )

    if TYPE_CHECKING:
        def __init__(
            self,
            *,
            title: str,
            department: str,
            location: str = "Lagos, Nigeria",
            employment_type: str = "Full-time",
            salary_min: int | None = None,
            salary_max: int | None = None,
            min_experience: int = 0,
            deadline: date | None = None,
            description: str,
            is_active: bool = True,
        ) -> None: ...


class JobApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    job_id = db.Column(db.Integer, db.ForeignKey("job.id"), nullable=False)
    qualification = db.Column(db.String(50), nullable=False)
    experience = db.Column(db.Integer, nullable=False)
    score = db.Column(db.Integer, nullable=False)
    assessment_score = db.Column(db.Integer, nullable=True)
    assessment_remark = db.Column(db.Text, nullable=True)
    auto_status = db.Column(db.String(20), nullable=False, default="rejected")
    review_status = db.Column(db.String(20), nullable=False, default="pending")
    shortlisted_at = db.Column(db.DateTime, nullable=True)
    assessed_at = db.Column(db.DateTime, nullable=True)
    assessed_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship("User", foreign_keys=[user_id], back_populates="applications")
    job = db.relationship("Job", back_populates="applications")
    assessed_by = db.relationship("User", foreign_keys=[assessed_by_id])
    reviewed_by = db.relationship("User", foreign_keys=[reviewed_by_id])

    __table_args__ = (
        db.UniqueConstraint("user_id", "job_id", name="uq_user_job_application"),
    )

    if TYPE_CHECKING:
        def __init__(
            self,
            *,
            user_id: int,
            job_id: int,
            qualification: str,
            experience: int,
            score: int,
            assessment_score: int | None = None,
            assessment_remark: str | None = None,
            auto_status: str = "rejected",
            review_status: str = "pending",
            shortlisted_at: datetime | None = None,
            assessed_at: datetime | None = None,
            assessed_by_id: int | None = None,
            reviewed_by_id: int | None = None,
            reviewed_at: datetime | None = None,
        ) -> None: ...


class SavedJob(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    job_id = db.Column(db.Integer, db.ForeignKey("job.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint("user_id", "job_id", name="uq_saved_user_job"),)

    if TYPE_CHECKING:
        def __init__(self, *, user_id: int, job_id: int) -> None: ...


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(120), nullable=False)
    entity_type = db.Column(db.String(60), nullable=True)
    entity_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship("User", back_populates="audit_logs")

    if TYPE_CHECKING:
        def __init__(
            self,
            *,
            user_id: int | None = None,
            action: str,
            entity_type: str | None = None,
            entity_id: int | None = None,
            details: str | None = None,
            ip_address: str | None = None,
        ) -> None: ...
