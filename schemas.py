"""
Database Schemas for AV TOURNAMENT Admin Panel

Each Pydantic model corresponds to a MongoDB collection (collection name = class name lowercased).
These schemas define validation and shape for documents the admin panel will manage.
"""
from __future__ import annotations
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Dict, Any
from datetime import datetime

# Core platform entities

class AdminUser(BaseModel):
    email: EmailStr
    password_hash: str
    name: str
    role: str = Field(..., description="super_admin, tournament_manager, financial_admin, support_moderator, content_manager, analytics_viewer")
    is_active: bool = True
    last_login_at: Optional[datetime] = None
    two_factor_enabled: bool = False
    allowed_ips: Optional[List[str]] = None

class AdminSession(BaseModel):
    admin_id: str
    token: str
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

class User(BaseModel):
    uid: str
    username: str
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    status: str = Field("active", description="active, suspended, deleted")
    verified: bool = False
    balances: Dict[str, float] = Field(default_factory=lambda: {"deposited": 0.0, "winnings": 0.0, "gifted": 0.0})
    referrals: Dict[str, Any] = Field(default_factory=dict)
    last_login_ip: Optional[str] = None
    devices: Optional[List[Dict[str, Any]]] = None

class Tournament(BaseModel):
    name: str
    type: str = Field(..., description="Clash Squad, Battle Royale, Lone Wolf, Free Match, Premium")
    entry_fee: Dict[str, Any] = Field(..., description="{mode: free|fixed|variable, amount: number}")
    team_size: int
    capacity: int
    schedule: Dict[str, Any] = Field(..., description="{start, end, registration_deadline}")
    prize_pool: Dict[str, Any] = Field(..., description="{total, distribution: [{place, percent}]}")
    map: Optional[str] = None
    settings: Dict[str, Any] = Field(default_factory=dict)
    rules: Optional[str] = None
    status: str = Field("draft", description="draft, scheduled, live, completed, cancelled")

class Match(BaseModel):
    tournament_id: str
    room: Optional[Dict[str, Any]] = None
    participants: List[Dict[str, Any]]
    scores: Optional[List[Dict[str, Any]]] = None
    status: str = Field("pending", description="pending, live, completed, disqualified")

class Transaction(BaseModel):
    user_id: str
    kind: str = Field(..., description="deposit, withdrawal, entry_fee, prize, refund, fee")
    amount: float
    currency: str = "BDT"
    gateway: Optional[str] = None
    status: str = Field("pending", description="pending, approved, rejected, failed, completed")
    meta: Dict[str, Any] = Field(default_factory=dict)

class Withdrawal(BaseModel):
    user_id: str
    amount: float
    status: str = Field("queued", description="queued, approved, rejected, paid")
    fees: float = 0.0
    method: Optional[str] = None
    meta: Dict[str, Any] = Field(default_factory=dict)

class Notification(BaseModel):
    title: str
    body: str
    audience: Dict[str, Any] = Field(default_factory=dict)
    channels: List[str] = Field(default_factory=lambda: ["push"])  # push, email, sms
    scheduled_at: Optional[datetime] = None
    sent_at: Optional[datetime] = None

class Ticket(BaseModel):
    user_id: str
    subject: str
    message: str
    priority: str = Field("normal", description="low, normal, high, urgent")
    status: str = Field("open", description="open, in_progress, resolved, closed")
    assignee_id: Optional[str] = None

class AuditLog(BaseModel):
    admin_id: str
    action: str
    entity: str
    entity_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    ip: Optional[str] = None

class Setting(BaseModel):
    key: str
    value: Any
    category: str = "general"
    description: Optional[str] = None

# The schema examples file documents additional patterns for reference.
