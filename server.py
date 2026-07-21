from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import re
import logging
import uuid
import jwt
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
from datetime import datetime, timezone, timedelta


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT config
JWT_SECRET = os.environ.get('JWT_SECRET', 'terreiro-dev-secret-change-me')
JWT_ALGO = 'HS256'
JWT_EXP_HOURS = 24 * 30  # 30 days

# Admin default CPF (only digits)
ADMIN_CPF = os.environ.get('ADMIN_CPF', '13480937497')

app = FastAPI(title="Casa de Jurema API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

# ------------------------ Helpers ------------------------

def clean_cpf(cpf: str) -> str:
    return re.sub(r'\D', '', cpf or '')


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_token(member_id: str, cpf: str, is_admin: bool) -> str:
    payload = {
        'sub': member_id,
        'cpf': cpf,
        'is_admin': is_admin,
        'exp': datetime.now(timezone.utc) + timedelta(hours=JWT_EXP_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")
    member = await db.members.find_one({"id": payload['sub']}, {"_id": 0})
    if not member:
        raise HTTPException(status_code=401, detail="Membro não encontrado")
    return member


async def require_admin(user=Depends(get_current_user)):
    if not user.get('is_admin'):
        raise HTTPException(status_code=403, detail="Acesso restrito ao administrador")
    return user


# ------------------------ Models ------------------------

class LoginIn(BaseModel):
    cpf: str


class MemberIn(BaseModel):
    name: str
    cpf: str
    phone: Optional[str] = ""
    is_admin: bool = False
    photo: Optional[str] = None


class MemberUpdate(BaseModel):
    name: Optional[str] = None
    cpf: Optional[str] = None
    phone: Optional[str] = None
    is_admin: Optional[bool] = None
    photo: Optional[str] = None


class SettingsIn(BaseModel):
    house_name: Optional[str] = None
    house_short: Optional[str] = None
    founded_year: Optional[int] = None
    monthly_amount: Optional[float] = None
    pix_code: Optional[str] = None
    pix_key: Optional[str] = None
    pix_bank: Optional[str] = None
    pix_holder_name: Optional[str] = None
    pix_qr_image: Optional[str] = None
    boleto_info: Optional[str] = None
    welcome_message: Optional[str] = None


class PaymentIn(BaseModel):
    member_id: str
    month: int
    year: int
    amount: float
    status: str = "paid"  # paid | pending | overdue
    method: str = "pix"   # pix | boleto | dinheiro | outro
    notes: Optional[str] = ""


class PaymentUpdate(BaseModel):
    status: Optional[str] = None
    amount: Optional[float] = None
    method: Optional[str] = None
    notes: Optional[str] = None


class EventIn(BaseModel):
    title: str
    description: Optional[str] = ""
    category: str  # reuniao | gira | estudo | festividade | mutirao
    date: str  # YYYY-MM-DD
    time: Optional[str] = ""


class NoticeIn(BaseModel):
    title: str
    body: str
    priority: str = "info"  # info | important | urgent


# ------------------------ Seed ------------------------

DEFAULT_WELCOME = (
    "Salve! É com o coração cheio de fé que damos as boas-vindas a você. "
    "A nossa casa é um lar de união, respeito e espiritualidade — um espaço "
    "onde caminhamos juntos, sustentados pela força dos guias e pela mão de "
    "cada irmão de fé. Sua contribuição mantém acesa a luz do nosso terreiro "
    "e possibilita que sigamos servindo com amor. Axé!"
)


async def seed_defaults():
    # Settings
    if not await db.settings.find_one({"key": "app"}):
        await db.settings.insert_one({
            "key": "app",
            "house_name": "Casa de Jurema Caboclo Samambaia",
            "house_short": "C.D.J.C.S",
            "founded_year": 2022,
            "monthly_amount": 50.0,
            "pix_code": "",
            "pix_key": "",
            "pix_bank": "",
            "pix_holder_name": "",
            "pix_qr_image": "",
            "boleto_info": "",
            "welcome_message": DEFAULT_WELCOME,
        })
    # Admin
    admin = await db.members.find_one({"cpf": ADMIN_CPF})
    if not admin:
        await db.members.insert_one({
            "id": str(uuid.uuid4()),
            "cpf": ADMIN_CPF,
            "name": "Administrador",
            "phone": "",
            "is_admin": True,
            "created_at": now_iso(),
        })


@app.on_event("startup")
async def on_startup():
    await seed_defaults()


# ------------------------ Auth ------------------------

@api_router.post("/auth/login")
async def login(data: LoginIn):
    cpf = clean_cpf(data.cpf)
    if len(cpf) != 11:
        raise HTTPException(status_code=400, detail="CPF inválido. Informe 11 dígitos.")
    member = await db.members.find_one({"cpf": cpf}, {"_id": 0})
    if not member:
        raise HTTPException(status_code=404, detail="CPF não cadastrado. Fale com o administrador.")
    token = make_token(member['id'], member['cpf'], member.get('is_admin', False))
    return {"token": token, "user": member}


@api_router.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return user


# ------------------------ Settings ------------------------

@api_router.get("/settings")
async def get_settings():
    s = await db.settings.find_one({"key": "app"}, {"_id": 0})
    return s


@api_router.put("/settings")
async def update_settings(data: SettingsIn, admin=Depends(require_admin)):
    patch = {k: v for k, v in data.model_dump().items() if v is not None}
    await db.settings.update_one({"key": "app"}, {"$set": patch})
    return await db.settings.find_one({"key": "app"}, {"_id": 0})


# ------------------------ Members ------------------------

@api_router.get("/members")
async def list_members(admin=Depends(require_admin)):
    members = await db.members.find({}, {"_id": 0}).sort("name", 1).to_list(1000)
    return members


@api_router.post("/members")
async def create_member(data: MemberIn, admin=Depends(require_admin)):
    cpf = clean_cpf(data.cpf)
    if len(cpf) != 11:
        raise HTTPException(status_code=400, detail="CPF inválido")
    if await db.members.find_one({"cpf": cpf}):
        raise HTTPException(status_code=409, detail="CPF já cadastrado")
    doc = {
        "id": str(uuid.uuid4()),
        "cpf": cpf,
        "name": data.name.strip(),
        "phone": (data.phone or "").strip(),
        "is_admin": bool(data.is_admin),
        "photo": data.photo or None,
        "created_at": now_iso(),
    }
    await db.members.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api_router.put("/members/{member_id}")
async def update_member(member_id: str, data: MemberUpdate, admin=Depends(require_admin)):
    patch = {}
    payload = data.model_dump()
    if payload.get('name') is not None:
        patch['name'] = payload['name'].strip()
    if payload.get('phone') is not None:
        patch['phone'] = payload['phone'].strip()
    if payload.get('is_admin') is not None:
        patch['is_admin'] = bool(payload['is_admin'])
    if payload.get('photo') is not None:
        patch['photo'] = payload['photo'] or None
    if payload.get('cpf') is not None:
        cpf = clean_cpf(payload['cpf'])
        if len(cpf) != 11:
            raise HTTPException(status_code=400, detail="CPF inválido")
        existing = await db.members.find_one({"cpf": cpf, "id": {"$ne": member_id}})
        if existing:
            raise HTTPException(status_code=409, detail="CPF já cadastrado")
        patch['cpf'] = cpf
    if not patch:
        raise HTTPException(status_code=400, detail="Nada para atualizar")
    result = await db.members.update_one({"id": member_id}, {"$set": patch})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Membro não encontrado")
    return await db.members.find_one({"id": member_id}, {"_id": 0})


@api_router.delete("/members/{member_id}")
async def delete_member(member_id: str, admin=Depends(require_admin)):
    member = await db.members.find_one({"id": member_id})
    if not member:
        raise HTTPException(status_code=404, detail="Membro não encontrado")
    if member.get('cpf') == ADMIN_CPF:
        raise HTTPException(status_code=400, detail="Não é possível remover o administrador principal")
    await db.members.delete_one({"id": member_id})
    await db.payments.delete_many({"member_id": member_id})
    return {"ok": True}


# ------------------------ Payments ------------------------

def _month_key(year: int, month: int) -> str:
    return f"{year:04d}-{month:02d}"


async def _last_payment_of_member(member_id: str):
    return await db.payments.find_one(
        {"member_id": member_id, "status": "paid"},
        {"_id": 0},
        sort=[("year", -1), ("month", -1)],
    )


@api_router.get("/payments/me")
async def my_payments(user=Depends(get_current_user)):
    items = await db.payments.find({"member_id": user['id']}, {"_id": 0}).sort([("year", -1), ("month", -1)]).to_list(1000)
    return items


@api_router.get("/payments/me/status")
async def my_status(user=Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    y, m = now.year, now.month
    payment = await db.payments.find_one(
        {"member_id": user['id'], "year": y, "month": m},
        {"_id": 0},
    )
    settings = await db.settings.find_one({"key": "app"}, {"_id": 0})
    amount = settings.get('monthly_amount', 0) if settings else 0
    if payment and payment.get('status') == 'paid':
        return {"status": "em_dia", "month": m, "year": y, "payment": payment, "amount": payment.get('amount', amount)}
    last_paid = await _last_payment_of_member(user['id'])
    return {
        "status": "em_atraso",
        "month": m,
        "year": y,
        "payment": payment,
        "amount": amount,
        "last_paid": last_paid,
    }


@api_router.get("/payments")
async def list_payments(admin=Depends(require_admin), year: Optional[int] = None, month: Optional[int] = None, member_id: Optional[str] = None):
    q = {}
    if year is not None:
        q['year'] = year
    if month is not None:
        q['month'] = month
    if member_id:
        q['member_id'] = member_id
    items = await db.payments.find(q, {"_id": 0}).sort([("year", -1), ("month", -1)]).to_list(2000)
    return items


@api_router.post("/payments")
async def create_payment(data: PaymentIn, admin=Depends(require_admin)):
    member = await db.members.find_one({"id": data.member_id}, {"_id": 0})
    if not member:
        raise HTTPException(status_code=404, detail="Membro não encontrado")
    existing = await db.payments.find_one({"member_id": data.member_id, "year": data.year, "month": data.month})
    if existing:
        raise HTTPException(status_code=409, detail="Já existe registro para esse mês. Edite o existente.")
    doc = {
        "id": str(uuid.uuid4()),
        "member_id": data.member_id,
        "member_name": member['name'],
        "member_cpf": member['cpf'],
        "month": data.month,
        "year": data.year,
        "amount": data.amount,
        "status": data.status,
        "method": data.method,
        "notes": data.notes or "",
        "paid_at": now_iso() if data.status == 'paid' else None,
        "created_at": now_iso(),
    }
    await db.payments.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api_router.put("/payments/{payment_id}")
async def update_payment(payment_id: str, data: PaymentUpdate, admin=Depends(require_admin)):
    patch = {k: v for k, v in data.model_dump().items() if v is not None}
    if 'status' in patch:
        patch['paid_at'] = now_iso() if patch['status'] == 'paid' else None
    if not patch:
        raise HTTPException(status_code=400, detail="Nada para atualizar")
    result = await db.payments.update_one({"id": payment_id}, {"$set": patch})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Pagamento não encontrado")
    return await db.payments.find_one({"id": payment_id}, {"_id": 0})


@api_router.delete("/payments/{payment_id}")
async def delete_payment(payment_id: str, admin=Depends(require_admin)):
    result = await db.payments.delete_one({"id": payment_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Pagamento não encontrado")
    return {"ok": True}


# ------------------------ Events ------------------------

@api_router.get("/events")
async def list_events(user=Depends(get_current_user), year: Optional[int] = None, month: Optional[int] = None):
    q = {}
    if year is not None and month is not None:
        prefix = f"{year:04d}-{month:02d}"
        q['date'] = {"$regex": f"^{prefix}"}
    items = await db.events.find(q, {"_id": 0}).sort("date", 1).to_list(2000)
    return items


@api_router.post("/events")
async def create_event(data: EventIn, admin=Depends(require_admin)):
    doc = {
        "id": str(uuid.uuid4()),
        "title": data.title.strip(),
        "description": (data.description or "").strip(),
        "category": data.category,
        "date": data.date,
        "time": data.time or "",
        "created_at": now_iso(),
    }
    await db.events.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api_router.put("/events/{event_id}")
async def update_event(event_id: str, data: EventIn, admin=Depends(require_admin)):
    patch = {
        "title": data.title.strip(),
        "description": (data.description or "").strip(),
        "category": data.category,
        "date": data.date,
        "time": data.time or "",
    }
    result = await db.events.update_one({"id": event_id}, {"$set": patch})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Evento não encontrado")
    return await db.events.find_one({"id": event_id}, {"_id": 0})


@api_router.delete("/events/{event_id}")
async def delete_event(event_id: str, admin=Depends(require_admin)):
    result = await db.events.delete_one({"id": event_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Evento não encontrado")
    return {"ok": True}


# ------------------------ Notices ------------------------

@api_router.get("/notices")
async def list_notices(user=Depends(get_current_user)):
    items = await db.notices.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    return items


@api_router.post("/notices")
async def create_notice(data: NoticeIn, admin=Depends(require_admin)):
    doc = {
        "id": str(uuid.uuid4()),
        "title": data.title.strip(),
        "body": data.body.strip(),
        "priority": data.priority,
        "created_at": now_iso(),
        "created_by": admin['id'],
        "created_by_name": admin['name'],
    }
    await db.notices.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api_router.put("/notices/{notice_id}")
async def update_notice(notice_id: str, data: NoticeIn, admin=Depends(require_admin)):
    patch = {
        "title": data.title.strip(),
        "body": data.body.strip(),
        "priority": data.priority,
    }
    result = await db.notices.update_one({"id": notice_id}, {"$set": patch})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Aviso não encontrado")
    return await db.notices.find_one({"id": notice_id}, {"_id": 0})


@api_router.delete("/notices/{notice_id}")
async def delete_notice(notice_id: str, admin=Depends(require_admin)):
    result = await db.notices.delete_one({"id": notice_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Aviso não encontrado")
    return {"ok": True}


# ------------------------ Reports ------------------------

@api_router.get("/reports/summary")
async def reports_summary(admin=Depends(require_admin), year: Optional[int] = None, month: Optional[int] = None):
    now = datetime.now(timezone.utc)
    y = year or now.year
    m = month or now.month
    members = await db.members.find({"is_admin": {"$ne": True}}, {"_id": 0}).to_list(2000)
    payments = await db.payments.find({"year": y, "month": m}, {"_id": 0}).to_list(2000)
    paid_ids = {p['member_id'] for p in payments if p.get('status') == 'paid'}
    total_paid = sum(p.get('amount', 0) for p in payments if p.get('status') == 'paid')
    settings = await db.settings.find_one({"key": "app"}, {"_id": 0})
    expected = (settings.get('monthly_amount', 0) if settings else 0) * len(members)
    return {
        "year": y,
        "month": m,
        "total_members": len(members),
        "paid_count": len(paid_ids),
        "pending_count": len(members) - len(paid_ids),
        "total_paid": total_paid,
        "expected": expected,
    }


# Include router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
