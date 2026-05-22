from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, Text
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime, timedelta
import math

# ---------------- DB SETUP ----------------
DATABASE_URL = "sqlite:///./edr.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# expire_on_commit=False əlavə edildi ki, sessiya bağlananda 
# HTML tərəf datanı oxuyarkən DetachedInstanceError xətası verməsin
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
Base = declarative_base()

# ---------------- MODELS ----------------
class Agent(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True)
    hostname = Column(String)
    ip = Column(String)
    status = Column(String)
    last_seen = Column(String)


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True)
    hostname = Column(String)
    category = Column(String)
    content = Column(Text)
    timestamp = Column(String)


Base.metadata.create_all(bind=engine)

# ---------------- APP ----------------
app = FastAPI()
templates = Jinja2Templates(directory="templates")


# ---------------- HEARTBEAT ----------------
@app.post("/heartbeat")
async def heartbeat(data: dict):
    db = SessionLocal()

    hostname = data.get("hostname")
    ip = data.get("ip")

    agent = db.query(Agent).filter(Agent.hostname == hostname).first()

    # Bazaya vaxtı hamar və standart formatda yazırıq
    current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    if not agent:
        agent = Agent(
            hostname=hostname,
            ip=ip,
            status="online",
            last_seen=current_time_str
        )
        db.add(agent)
    else:
        agent.status = "online"
        agent.ip = ip
        agent.last_seen = current_time_str

    db.commit()
    db.close()

    return {"status": "ok"}


# ---------------- LOGS ----------------
@app.post("/logs")
async def receive_logs(data: dict):
    db = SessionLocal()

    hostname = data.get("hostname")
    logs = data.get("logs", [])
    current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    for log in logs:
        entry = Log(
            hostname=hostname,
            category=log.get("category", "unknown"),
            content=log.get("content", ""),
            timestamp=current_time_str
        )
        db.add(entry)

    db.commit()
    db.close()

    return {"status": "received"}


# ---------------- DASHBOARD ----------------
@app.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    page: int = Query(1, ge=1),
    hostname: str = Query(None),
    category: str = Query(None)
):
    db = SessionLocal()

    limit = 20
    offset = (page - 1) * limit

    query = db.query(Log)

    # Filtrləmə
    if hostname:
        query = query.filter(Log.hostname == hostname)

    if category:
        query = query.filter(Log.category == category)

    total = query.count()

    logs = (
        query.order_by(Log.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    # --- AGENT STATUS HANDLE (REAL VAXTDA YOXLANILMASI) ---
    agents = db.query(Agent).all()
    now = datetime.now()
    
    for agent in agents:
        if agent.last_seen:
            try:
                # String formatında olan vaxtı geri çevirib müqayisə edirik
                last_seen_time = datetime.strptime(agent.last_seen, "%Y-%m-%d %H:%M:%S.%f")
                
                # Əgər son heartbeat-dən 30 saniyədən çox keçibsə -> offline
                if now - last_seen_time > timedelta(seconds=30):
                    agent.status = "offline"
                else:
                    agent.status = "online"
            except Exception:
                agent.status = "offline"
        else:
            agent.status = "offline"
            
        db.add(agent)
    
    db.commit()
    # -----------------------------------------------------

    total_pages = (total // limit) + (1 if total % limit else 0)
    if total_pages == 0:
        total_pages = 1

    # Starlette/FastAPI-ın ən son standartına uyğun TemplateResponse ötürülməsi
    response = templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "agents": agents,
            "logs": logs,
            "page": page,
            "total_pages": total_pages,
            "hostname": hostname if hostname else "",
            "category": category if category else ""
        }
    )
    
    # Bazanı render tamamlandıqdan sonra tam təhlükəsiz şəkildə bağlayırıq
    db.close()
    return response


# ---------------- HEALTH CHECK ----------------
@app.get("/health")
def health():
    return {"status": "running"}