from fastapi import FastAPI, Request, Query, HTTPException, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, Text, Float
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime, timedelta
import math
import json
import pam  # Ubuntu sistem istifadəçilərini yoxlamaq üçün
import jwt

# --- VERİLƏNLƏR BAZASI AYARLARI ---
DATABASE_URL = "sqlite:///./edr.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
Base = declarative_base()

# --- JWT VƏ SESSİYA AYARLARI ---
SECRET_KEY = "SUPER_SECRET_NEXGUARD_KEY_CHANGE_THIS"  # İstehsalatda bunu mütləq gizli saxla
ALGORITHM = "HS256"
COOKIE_NAME = "access_token"

# --- SQLALCHEMY MODELLƏRİ ---
class Agent(Base):
    __tablename__ = "agents"
    id            = Column(Integer, primary_key=True)
    hostname      = Column(String, unique=True, index=True)
    ip            = Column(String, default="")
    status        = Column(String, default="offline")
    last_seen     = Column(String, default="")
    cpu_percent   = Column(Float, default=0.0)
    ram_percent   = Column(Float, default=0.0)
    ram_used_gb   = Column(Float, default=0.0)
    ram_total_gb  = Column(Float, default=0.0)
    disk_percent  = Column(Float, default=0.0)
    disk_used_gb  = Column(Float, default=0.0)
    disk_total_gb = Column(Float, default=0.0)
    uptime        = Column(String, default="")
    boot_time     = Column(String, default="")
    active_user   = Column(String, default="")
    login_time    = Column(String, default="")
    os_info       = Column(String, default="")
    architecture  = Column(String, default="")
    processes     = Column(Text, default="[]")

class Log(Base):
    __tablename__ = "logs"
    id        = Column(Integer, primary_key=True)
    hostname  = Column(String, index=True)
    category  = Column(String, index=True)          
    severity  = Column(String, default="info", index=True)  
    content   = Column(Text)                  
    fields    = Column(Text, default="{}")     
    timestamp = Column(String)

Base.metadata.create_all(bind=engine)

# --- FASTAPI APPLIKASIYASI VƏ ŞABLONLAR ---
app = FastAPI(title="NexGuard EDR SIEM Backend")
templates = Jinja2Templates(directory="templates")

def decode_json(value):
    try: 
        return json.loads(value)
    except: 
        return {}

templates.env.filters["decode_json"] = decode_json

# --- AUTENTIFIKASIYA YARDIMÇI FUNKSIYALARI ---
def verify_linux_user(username: str, password: str) -> bool:
    """ Ubuntu sistemindəki (PAM) istifadəçi məlumatlarını yoxlayır """
    p = pam.pam()
    return p.authenticate(username, password)

def get_current_user_from_cookie(request: Request):
    """ Cookie daxilindən JWT-ni oxuyub cari sessiya istifadəçisini qaytarır """
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return username
    except jwt.PyJWTError:
        return None

# DB Sessiyası Dependency
def get_db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- AUTH ENDPOINT-LƏR ---

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = Query(None)):
    return templates.TemplateResponse(request, "login.html", {"error": error})

@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    # Birbaşa Ubuntu /etc/shadow və PAM üzərindən yoxlanış gedir
    if not verify_linux_user(username, password):
        return RedirectResponse(url="/login?error=Istifadeci+adi+ve+ya+sifre+yalnisdir", status_code=status.HTTP_303_SEE_OTHER)
    
    # Token yaradılması (Məsələn: 12 saatlıq sessiya)
    expire = datetime.utcnow() + timedelta(hours=12)
    token_data = {"sub": username, "exp": expire}
    encoded_jwt = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
    
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(key=COOKIE_NAME, value=encoded_jwt, httponly=True, samesite="lax")
    return response

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(COOKIE_NAME)
    return response

# --- API ENDPOINT-LƏR (AGENT TELEMETRY - AUTH TƏLƏB OLUNMUR) ---

@app.post("/heartbeat")
async def heartbeat(data: dict):
    db = SessionLocal()
    try:
        h = data.get("hostname", "unknown")
        ip = data.get("ip", "")
        sinfo = data.get("system_info", {})
        
        agent = db.query(Agent).filter(Agent.hostname == h).first()
        if not agent:
            agent = Agent(hostname=h)
            db.add(agent)

        # Dinamik Online/Offline status yoxlaması üçün 'last_seen' datetime formatında saxlanılır
        agent.ip = ip
        agent.last_seen = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")
        
        if sinfo:
            agent.cpu_percent   = sinfo.get("cpu_percent", 0)
            agent.ram_percent   = sinfo.get("ram_percent", 0)
            agent.ram_used_gb   = sinfo.get("ram_used_gb", 0)
            agent.ram_total_gb  = sinfo.get("ram_total_gb", 0)
            agent.disk_percent  = sinfo.get("disk_percent", 0)
            agent.disk_used_gb  = sinfo.get("disk_used_gb", 0)
            agent.disk_total_gb = sinfo.get("disk_total_gb", 0)
            agent.uptime        = sinfo.get("uptime", "")
            agent.boot_time     = sinfo.get("boot_time", "")
            agent.active_user   = sinfo.get("active_user", "")
            agent.login_time    = sinfo.get("login_time", "")
            agent.os_info       = sinfo.get("os", "")
            agent.architecture  = sinfo.get("architecture", "")

        db.commit()
        return {"status": "ok"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.post("/processes")
async def receive_processes(data: dict):
    db = SessionLocal()
    try:
        h = data.get("hostname", "")
        agent = db.query(Agent).filter(Agent.hostname == h).first()
        if agent:
            agent.processes = json.dumps(data.get("processes", []))
            db.commit()
            return {"status": "ok"}
        return {"status": "agent_not_found"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.post("/logs")
async def receive_logs(data: dict):
    db = SessionLocal()
    try:
        h = data.get("hostname", "unknown")
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")

        raw_logs = data.get("logs", [])
        for log in raw_logs:
            db.add(Log(
                hostname  = h,
                category  = log.get("category", "system"),
                severity  = log.get("severity", "info"),
                content   = log.get("content", ""),
                fields    = json.dumps(log.get("fields", {})), 
                timestamp = now,
            ))
        db.commit()
        return {"status": "received", "count": len(raw_logs)}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

# --- UI ENDPOINT-LƏR (SESSİYA YOXLANILIŞI İLƏ) ---

@app.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request, 
    page: int = Query(1, ge=1), 
    hostname: str = Query(None), 
    category: str = Query(None), 
    severity: str = Query(None)
):
    current_user = get_current_user_from_cookie(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    db = SessionLocal()
    try:
        limit = 25
        offset = (page - 1) * limit

        query = db.query(Log)
        if hostname: 
            query = query.filter(Log.hostname == hostname)
        if category: 
            query = query.filter(Log.category == category)
        if severity: 
            query = query.filter(Log.severity == severity)

        total = query.count()
        logs = query.order_by(Log.id.desc()).offset(offset).limit(limit).all()
        raw_agents = db.query(Agent).all()

        total_pages = max(1, math.ceil(total / limit))
        
        # Dinamik Heartbeat yoxlanışı (Son 2 dəqiqə ərzində siqnal gəlməyibsə offline et)
        agents = []
        online_count = 0
        heartbeat_timeout = timedelta(minutes=2)
        now = datetime.utcnow()

        for a in raw_agents:
            if a.last_seen:
                try:
                    last_seen_dt = datetime.strptime(a.last_seen, "%Y-%m-%d %H:%M:%S.%f")
                    if (now - last_seen_dt) < heartbeat_timeout:
                        a.status = "online"
                        online_count += 1
                    else:
                        a.status = "offline"
                except:
                    a.status = "offline"
            else:
                a.status = "offline"
            agents.append(a)

        crit_count = db.query(Log).filter(Log.severity == "critical").count()
        warn_count = db.query(Log).filter(Log.severity == "warning").count()

        return templates.TemplateResponse(request, "dashboard.html", {
            "agents": agents, 
            "logs": logs, 
            "page": page, 
            "total_pages": total_pages, 
            "total_logs": total,
            "hostname": hostname or "", 
            "category": category or "", 
            "severity": severity or "",
            "critical_count": crit_count, 
            "warning_count": warn_count, 
            "online_count": online_count, 
            "total_agents": len(agents),
            "current_user": current_user  # Üst barda istifadəçi adını göstərmək üçün
        })
    finally:
        db.close()

@app.get("/agent/{hostname_param}", response_class=HTMLResponse)
async def agent_detail(
    request: Request, 
    hostname_param: str, 
    category: str = Query(None), 
    severity: str = Query(None)
):
    current_user = get_current_user_from_cookie(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    db = SessionLocal()
    try:
        agent = db.query(Agent).filter(Agent.hostname == hostname_param).first()
        if not agent:
            return HTMLResponse(
                "<html><body><h1 style='color:#ef4444; font-family:sans-serif; text-align:center; margin-top:10%;'>404 — Agent tapılmadı</h1></body></html>", 
                status_code=404
            )
        
        # Cari agentin statusunu dinamik yoxla
        heartbeat_timeout = timedelta(minutes=2)
        if agent.last_seen:
            try:
                last_seen_dt = datetime.strptime(agent.last_seen, "%Y-%m-%d %H:%M:%S.%f")
                if (datetime.utcnow() - last_seen_dt) < heartbeat_timeout:
                    agent.status = "online"
                else:
                    agent.status = "offline"
            except:
                agent.status = "offline"
        else:
            agent.status = "offline"

        q = db.query(Log).filter(Log.hostname == hostname_param)
        if category: 
            q = q.filter(Log.category == category)
        if severity: 
            q = q.filter(Log.severity == severity)
        
        logs = q.order_by(Log.id.desc()).limit(200).all()

        try: 
            processes = json.loads(agent.processes or "[]")
        except: 
            processes = []

        crit_count = sum(1 for l in logs if l.severity == "critical")
        warn_count = sum(1 for l in logs if l.severity == "warning")

        return templates.TemplateResponse(request, "agent_detail.html", {
            "agent": agent, 
            "logs": logs, 
            "processes": processes,
            "crit_count": crit_count,
            "warn_count": warn_count, 
            "category": category or "", 
            "severity": severity or "",
            "current_user": current_user
        })
    finally:
        db.close()