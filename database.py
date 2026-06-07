from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class Company(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    industry = db.Column(db.String(50))
    employees = db.Column(db.String(20))
    domain = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    assessments = db.relationship('Assessment', backref='company', lazy=True)

class Assessment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    score = db.Column(db.Integer)
    risk_level = db.Column(db.String(20))
    antivirus = db.Column(db.String(5))
    mfa = db.Column(db.String(5))
    backups = db.Column(db.String(5))
    training = db.Column(db.String(5))
    passwords = db.Column(db.String(5))
    encryption = db.Column(db.String(5))
    ssl_status = db.Column(db.String(20))
    spf_status = db.Column(db.String(20))
    dmarc_status = db.Column(db.String(20))
    breach_found = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)