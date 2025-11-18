import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import jwt, JWTError
from passlib.context import CryptContext

from database import db, create_document, get_documents

SECRET_KEY = os.getenv("ADMIN_JWT_SECRET", "dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="AV Tournament Admin API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Utility functions

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: str
    password: str
    otp: Optional[str] = None


async def get_current_admin(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise ValueError("Invalid auth scheme")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        admin_id: str = payload.get("sub")
        role: str = payload.get("role")
        if admin_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"_id": admin_id, "role": role}
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalid or expired")


@app.get("/")
def root():
    return {"status": "ok", "service": "admin"}


@app.get("/test")
def test_database():
    info = {
        "backend": "running",
        "database": "disconnected",
        "collections": [],
    }
    try:
        if db is not None:
            info["database"] = "connected"
            info["collections"] = db.list_collection_names()
    except Exception as e:
        info["database"] = f"error: {str(e)[:80]}"
    return info


# Auth endpoints (minimal to get started)

@app.post("/auth/login", response_model=Token)
async def admin_login(body: LoginRequest):
    # Minimal bootstrap: find admin user by email
    admin = db["adminuser"].find_one({"email": body.email}) if db else None
    if not admin:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(body.password, admin.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not admin.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account disabled")

    token = create_access_token({"sub": str(admin.get("_id")), "role": admin.get("role", "super_admin")})
    return Token(access_token=token)


# Example aggregate metrics for dashboard

@app.get("/analytics/overview")
async def analytics_overview(_: dict = Depends(get_current_admin)):
    def count(col: str) -> int:
        try:
            return db[col].count_documents({}) if db else 0
        except Exception:
            return 0
    # Simple sums as placeholders; real logic can be expanded
    total_users = count("user")
    total_tournaments = count("tournament")
    total_transactions = count("transaction")
    revenue = 0.0
    try:
        pipeline = [
            {"$match": {"kind": {"$in": ["deposit", "entry_fee", "fee", "prize", "refund"]}, "status": {"$in": ["approved", "completed"]}}},
            {"$group": {"_id": None, "sum": {"$sum": "$amount"}}}
        ]
        res = list(db["transaction"].aggregate(pipeline)) if db else []
        revenue = float(res[0]["sum"]) if res else 0.0
    except Exception:
        revenue = 0.0

    recent_activity = []
    try:
        users = db["user"].find().sort("created_at", -1).limit(5) if db else []
        txs = db["transaction"].find().sort("created_at", -1).limit(5) if db else []
        for u in users:
            recent_activity.append({"type": "user", "username": u.get("username"), "ts": u.get("created_at")})
        for t in txs:
            recent_activity.append({"type": "transaction", "amount": t.get("amount"), "ts": t.get("created_at")})
        recent_activity = sorted(recent_activity, key=lambda x: x.get("ts") or datetime.now(timezone.utc), reverse=True)[:10]
    except Exception:
        recent_activity = []

    return {
        "metrics": {
            "users": total_users,
            "tournaments": total_tournaments,
            "transactions": total_transactions,
            "revenue": revenue,
        },
        "recent_activity": recent_activity,
        "system_health": {"server": "ok", "db": "ok" if db else "down"},
    }


# Minimal CRUD style endpoints for Users and Tournaments to power UI

class Pagination(BaseModel):
    page: int = 1
    per_page: int = 20


@app.get("/users")
async def list_users(q: Optional[str] = None, status: Optional[str] = None, page: int = 1, per_page: int = 20, _: dict = Depends(get_current_admin)):
    if not db:
        return {"items": [], "total": 0}
    filt: Dict[str, Any] = {}
    if status:
        filt["status"] = status
    if q:
        filt["$or"] = [
            {"username": {"$regex": q, "$options": "i"}},
            {"email": {"$regex": q, "$options": "i"}},
            {"uid": {"$regex": q, "$options": "i"}},
        ]
    total = db["user"].count_documents(filt)
    cursor = db["user"].find(filt).sort("created_at", -1).skip((page-1)*per_page).limit(per_page)
    return {"items": list(cursor), "total": total}


@app.patch("/users/{uid}/balance")
async def adjust_balance(uid: str, payload: Dict[str, float], _: dict = Depends(get_current_admin)):
    if not db:
        raise HTTPException(status_code=500, detail="Database unavailable")
    inc = {f"balances.{k}": v for k, v in payload.items()}
    res = db["user"].update_one({"uid": uid}, {"$inc": inc, "$set": {"updated_at": datetime.now(timezone.utc)}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"ok": True}


@app.post("/tournaments")
async def create_tournament(body: Dict[str, Any], admin: dict = Depends(get_current_admin)):
    if not db:
        raise HTTPException(status_code=500, detail="Database unavailable")
    body["status"] = body.get("status", "draft")
    body["created_by"] = admin["_id"]
    tid = create_document("tournament", body)
    return {"id": tid}


@app.get("/tournaments")
async def list_tournaments(status: Optional[str] = None, page: int = 1, per_page: int = 20, _: dict = Depends(get_current_admin)):
    if not db:
        return {"items": [], "total": 0}
    filt = {"status": status} if status else {}
    total = db["tournament"].count_documents(filt)
    cursor = db["tournament"].find(filt).sort("created_at", -1).skip((page-1)*per_page).limit(per_page)
    return {"items": list(cursor), "total": total}


# Schema exposure (helpful for DB viewer tools)
@app.get("/schema")
async def get_schema():
    try:
        from schemas import (
            AdminUser, AdminSession, User, Tournament, Match, Transaction,
            Withdrawal, Notification, Ticket, AuditLog, Setting
        )
        def model_to_dict(model):
            return {k: str(v.annotation) for k, v in model.model_fields.items()}
        return {
            "adminuser": model_to_dict(AdminUser),
            "adminsession": model_to_dict(AdminSession),
            "user": model_to_dict(User),
            "tournament": model_to_dict(Tournament),
            "match": model_to_dict(Match),
            "transaction": model_to_dict(Transaction),
            "withdrawal": model_to_dict(Withdrawal),
            "notification": model_to_dict(Notification),
            "ticket": model_to_dict(Ticket),
            "auditlog": model_to_dict(AuditLog),
            "setting": model_to_dict(Setting),
        }
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
