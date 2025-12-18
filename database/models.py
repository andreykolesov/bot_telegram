import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, Text, BigInteger
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database.db import Base

class UserRole(Base):
    __tablename__ = 'user_roles'
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True)
    description = Column(String(255))
    users = relationship("User", back_populates="role")

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    telegram_id = Column(BigInteger, unique=True, index=True)
    login = Column(String(100), unique=True)
    password_hash = Column(String(255))
    reg_date = Column(DateTime(timezone=True), server_default=func.now())
    is_blocked = Column(Boolean, default=False)
    role_id = Column(Integer, ForeignKey('user_roles.id'))
    role = relationship("UserRole", back_populates="users")
    scans = relationship("Scan", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")
    exports = relationship("DataExport", back_populates="user")
    tickets = relationship("SupportTicket", foreign_keys="SupportTicket.user_id", back_populates="user")

class FileArtifact(Base):
    __tablename__ = 'file_artifacts'
    id = Column(Integer, primary_key=True)
    sha256_hash = Column(String(64), unique=True, index=True)
    md5_hash = Column(String(32))
    size_bytes = Column(BigInteger)
    mime_type = Column(String(100))
    extension = Column(String(20))
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    scans = relationship("Scan", back_populates="file")

class ScannerTool(Base):
    __tablename__ = 'scanner_tools'
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True)
    version = Column(String(50))
    is_active = Column(Boolean, default=True)

class Scan(Base):
    __tablename__ = 'scans'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    file_id = Column(Integer, ForeignKey('file_artifacts.id'))
    filename_at_upload = Column(String(255))
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    finished_at = Column(DateTime(timezone=True))
    status = Column(String(50), default="processing")
    overall_verdict = Column(String(20), default="clean")
    user = relationship("User", back_populates="scans")
    file = relationship("FileArtifact", back_populates="scans")
    results = relationship("ScanResult", back_populates="scan")

class ScanResult(Base):
    __tablename__ = 'scan_results'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    scanner_tool_id = Column(Integer, ForeignKey('scanner_tools.id'))
    verdict = Column(String(50))
    raw_output = Column(Text)
    scan = relationship("Scan", back_populates="results")
    threats = relationship("Threat", back_populates="result")

class Threat(Base):
    __tablename__ = 'threats'
    id = Column(Integer, primary_key=True)
    scan_result_id = Column(Integer, ForeignKey('scan_results.id'))
    threat_type = Column(String(100))
    threat_name = Column(String(255))
    danger_level = Column(String(50))
    result = relationship("ScanResult", back_populates="threats")

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    action_type = Column(String(50))
    details = Column(Text)
    ip_address = Column(String(45), nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    user = relationship("User", back_populates="audit_logs")

class DataExport(Base):
    __tablename__ = 'data_exports'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    export_format = Column(String(10))
    status = Column(String(20))
    file_path = Column(String(500))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    user = relationship("User", back_populates="exports")

class Backup(Base):
    __tablename__ = 'backups'
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String(20))
    backup_size_bytes = Column(BigInteger)
    remote_url = Column(String(1000))

class SupportTicket(Base):
    __tablename__ = 'support_tickets'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    question = Column(Text, nullable=False)
    answer = Column(Text, nullable=True)
    status = Column(String(20), default='open')
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    answered_at = Column(DateTime(timezone=True), nullable=True)
    answered_by_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    user = relationship("User", foreign_keys=[user_id], back_populates="tickets")
    admin = relationship("User", foreign_keys=[answered_by_id])