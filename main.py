"""
ESP32 GPS Tracker - FastAPI Backend (Single File)
==================================================
Features:
- Receives GPS data from ESP32 devices at POST /gps
- Stores data in SQLite database
- Admin authentication with Argon2 password hashing
- Admin account auto-created on startup
- Protected API endpoints with JWT tokens
- Dashboard data endpoints for external frontend

Run: uvicorn main:app --host 0.0.0.0 --port 8000
"""

import os
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, desc, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from jose import JWTError, jwt
from passlib.hash import argon2

# =============================================================================
# CONFIGURATION
# =============================================================================

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./gps_tracker.db")
SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret-key-in-production-esp32-gps-tracker")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

DEFAULT_ADMIN_USER = os.getenv("DEFAULT_ADMIN_USER", "admin")
DEFAULT_ADMIN_PASS = os.getenv("DEFAULT_ADMIN_PASS", "admin123")

# =============================================================================
# DATABASE SETUP
# =============================================================================

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class GPSData(Base):
    __tablename__ = "gps_data"
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, index=True, nullable=False)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    speed = Column(Float, default=0.0)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


class Admin(Base):
    __tablename__ = "admins"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)


class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# =============================================================================
# PYDANTIC SCHEMAS
# =============================================================================

class GPSDataCreate(BaseModel):
    device_id: str = Field(..., min_length=1, max_length=100)
    latitude: float = Field(..., ge=-90, le=90)
    longitude: float = Field(..., ge=-180, le=180)
    speed: Optional[float] = Field(default=0.0, ge=0)


class GPSDataResponse(BaseModel):
    id: int
    device_id: str
    latitude: float
    longitude: float
    speed: float
    timestamp: datetime

    class Config:
        from_attributes = True


class DeviceResponse(BaseModel):
    id: int
    device_id: str
    name: Optional[str]
    created_at: datetime
    last_seen: Optional[datetime]
    is_active: bool

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AdminCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)


class AdminResponse(BaseModel):
    id: int
    username: str
    created_at: datetime
    is_active: bool

    class Config:
        from_attributes = True


class DashboardStats(BaseModel):
    total_devices: int
    total_records: int
    active_devices: int
    latest_records: List[GPSDataResponse]


class DeviceHistoryResponse(BaseModel):
    device_id: str
    device_name: Optional[str]
    record_count: int
    records: List[GPSDataResponse]

    class Config:
        from_attributes = True


# =============================================================================
# AUTHENTICATION UTILITIES
# =============================================================================

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(password: str) -> str:
    """Hash password using Argon2id with strong parameters."""
    return argon2.using(memory_cost=65536, time_cost=3, parallelism=4, type="id").hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against Argon2 hash."""
    try:
        return argon2.verify(plain_password, hashed_password)
    except Exception:
        return False


def authenticate_admin(db: Session, username: str, password: str) -> Optional[Admin]:
    """Authenticate admin by username and password."""
    admin = db.query(Admin).filter(Admin.username == username).first()
    if not admin:
        # Dummy verify to prevent timing attacks
        hash_password("dummy")
        return None
    if not verify_password(password, admin.password_hash):
        return None
    if not admin.is_active:
        return None
    return admin


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_admin(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> Admin:
    """Get current authenticated admin from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    admin = db.query(Admin).filter(Admin.username == username).first()
    if admin is None or not admin.is_active:
        raise credentials_exception
    return admin


async def get_current_active_admin(current_admin: Admin = Depends(get_current_admin)) -> Admin:
    """Verify admin is active."""
    if not current_admin.is_active:
        raise HTTPException(status_code=400, detail="Inactive admin account")
    return current_admin


# =============================================================================
# STARTUP / LIFESPAN
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database and create default admin on startup."""
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        admin_count = db.query(Admin).count()
        if admin_count == 0:
            new_admin = Admin(
                username=DEFAULT_ADMIN_USER,
                password_hash=hash_password(DEFAULT_ADMIN_PASS)
            )
            db.add(new_admin)
            db.commit()
            print(f"=" * 60)
            print(f"  DEFAULT ADMIN CREATED")
            print(f"  Username: {DEFAULT_ADMIN_USER}")
            print(f"  Password: {DEFAULT_ADMIN_PASS}")
            print(f"=" * 60)
            print(f"  WARNING: Change default credentials immediately!")
            print(f"=" * 60)
    finally:
        db.close()

    yield

    # Shutdown
    engine.dispose()


# =============================================================================
# FASTAPI APP
# =============================================================================

app = FastAPI(
    title="ESP32 GPS Tracker API",
    description="Backend API for receiving GPS data from ESP32 devices with admin dashboard",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# ESP32 GPS ENDPOINTS (No auth required - device sends data)
# =============================================================================

@app.post("/gps", status_code=status.HTTP_201_CREATED, response_model=GPSDataResponse)
async def receive_gps_data(data: GPSDataCreate, db: Session = Depends(get_db)):
    """
    Receive GPS data from ESP32 device.
    Your ESP32 sends POST to this endpoint with JSON body.
    """
    gps_record = GPSData(
        device_id=data.device_id,
        latitude=data.latitude,
        longitude=data.longitude,
        speed=data.speed
    )
    db.add(gps_record)

    # Update or create device record
    device = db.query(Device).filter(Device.device_id == data.device_id).first()
    if device:
        device.last_seen = datetime.utcnow()
    else:
        device = Device(
            device_id=data.device_id,
            name=f"Device {data.device_id}",
            last_seen=datetime.utcnow()
        )
        db.add(device)

    db.commit()
    db.refresh(gps_record)
    return gps_record


# =============================================================================
# AUTHENTICATION ENDPOINTS
# =============================================================================

@app.post("/api/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Admin login - returns JWT token for dashboard access."""
    admin = authenticate_admin(db, form_data.username, form_data.password)
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": admin.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/api/auth/admin", response_model=AdminResponse, status_code=status.HTTP_201_CREATED)
async def create_admin(
    admin_data: AdminCreate,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_active_admin)
):
    """Create new admin account (requires existing admin auth)."""
    existing = db.query(Admin).filter(Admin.username == admin_data.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    new_admin = Admin(
        username=admin_data.username,
        password_hash=hash_password(admin_data.password)
    )
    db.add(new_admin)
    db.commit()
    db.refresh(new_admin)
    return new_admin


@app.get("/api/auth/me", response_model=AdminResponse)
async def get_current_admin_info(current_admin: Admin = Depends(get_current_active_admin)):
    """Get current authenticated admin info."""
    return current_admin


# =============================================================================
# DASHBOARD DATA ENDPOINTS (Admin only)
# =============================================================================

@app.get("/api/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_active_admin)
):
    """Get dashboard statistics."""
    total_devices = db.query(Device).count()
    total_records = db.query(GPSData).count()
    active_devices = db.query(Device).filter(Device.is_active == True).count()
    latest_records = db.query(GPSData).order_by(desc(GPSData.timestamp)).limit(10).all()

    return DashboardStats(
        total_devices=total_devices,
        total_records=total_records,
        active_devices=active_devices,
        latest_records=latest_records
    )


@app.get("/api/gps/latest", response_model=List[GPSDataResponse])
async def get_latest_gps(
    device_id: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_active_admin)
):
    """Get latest GPS records (optionally filtered by device)."""
    query = db.query(GPSData)
    if device_id:
        query = query.filter(GPSData.device_id == device_id)
    records = query.order_by(desc(GPSData.timestamp)).limit(limit).all()
    return records


@app.get("/api/gps/device/{device_id}", response_model=DeviceHistoryResponse)
async def get_device_gps_history(
    device_id: str,
    hours: int = 24,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_active_admin)
):
    """Get GPS history for a specific device."""
    since = datetime.utcnow() - timedelta(hours=hours)
    records = db.query(GPSData).filter(
        GPSData.device_id == device_id,
        GPSData.timestamp >= since
    ).order_by(GPSData.timestamp).all()

    device = db.query(Device).filter(Device.device_id == device_id).first()

    return DeviceHistoryResponse(
        device_id=device_id,
        device_name=device.name if device else None,
        record_count=len(records),
        records=records
    )


# =============================================================================
# DEVICE MANAGEMENT ENDPOINTS (Admin only)
# =============================================================================

@app.get("/api/devices", response_model=List[DeviceResponse])
async def get_devices(
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_active_admin)
):
    """Get all registered devices."""
    devices = db.query(Device).order_by(Device.last_seen.desc()).all()
    return devices


@app.get("/api/devices/{device_id}", response_model=DeviceResponse)
async def get_device(
    device_id: str,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_active_admin)
):
    """Get single device details."""
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@app.patch("/api/devices/{device_id}")
async def update_device(
    device_id: str,
    name: Optional[str] = None,
    is_active: Optional[bool] = None,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_active_admin)
):
    """Update device name or active status."""
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    if name is not None:
        device.name = name
    if is_active is not None:
        device.is_active = is_active

    db.commit()
    db.refresh(device)
    return device


@app.delete("/api/devices/{device_id}")
async def delete_device(
    device_id: str,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_active_admin)
):
    """Delete a device and all its GPS records."""
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Delete GPS records for this device
    db.query(GPSData).filter(GPSData.device_id == device_id).delete()
    db.delete(device)
    db.commit()
    return {"message": f"Device {device_id} deleted successfully"}


# =============================================================================
# HEALTH CHECK
# =============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
