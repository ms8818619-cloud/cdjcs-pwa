from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, WebSocket, WebSocketDisconnect, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import re
import logging
import uuid
import jwt
import secrets
import string
import json
import webauthn
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    options_to_json,
    parse_registration_credential_json,
    parse_authentication_credential_json,
)
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

# WebAuthn (biometria nativa do aparelho) — v2.0.
# IMPORTANTE: WEBAUTHN_RP_ID deve ser o domínio exato onde o frontend está
# publicado (ex: "seusite.netlify.app" ou seu domínio próprio), sem
# "https://" e sem caminho. Sem isso configurado corretamente no Render, a
# biometria não funciona (mas o login por CPF continua funcionando normalmente).
WEBAUTHN_RP_ID = os.environ.get('WEBAUTHN_RP_ID', 'localhost')
WEBAUTHN_RP_NAME = "Casa de Jurema Caboclo Samambaia"
WEBAUTHN_ORIGIN = os.environ.get('WEBAUTHN_ORIGIN', f'https://{WEBAUTHN_RP_ID}')

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


async def get_user_from_ws_token(token: str):
    """Autentica uma conexão WebSocket via token JWT passado por query string
    (WebSocket nativo do navegador não permite cabeçalhos customizados)."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.PyJWTError:
        return None
    member = await db.members.find_one({"id": payload['sub']}, {"_id": 0})
    return member


class ChatConnectionManager:
    """Mantém as conexões WebSocket ativas por conversa e o canal de avisos
    para administradores (inbox de conversas privadas)."""

    def __init__(self):
        self.rooms: dict[str, set[WebSocket]] = {}
        self.admin_inbox: set[WebSocket] = set()

    async def join(self, conversation_id: str, ws: WebSocket):
        self.rooms.setdefault(conversation_id, set()).add(ws)

    def leave(self, conversation_id: str, ws: WebSocket):
        if conversation_id in self.rooms:
            self.rooms[conversation_id].discard(ws)
            if not self.rooms[conversation_id]:
                del self.rooms[conversation_id]

    async def broadcast(self, conversation_id: str, payload: dict):
        for ws in list(self.rooms.get(conversation_id, [])):
            try:
                await ws.send_json(payload)
            except Exception:
                self.leave(conversation_id, ws)

    async def join_admin_inbox(self, ws: WebSocket):
        self.admin_inbox.add(ws)

    def leave_admin_inbox(self, ws: WebSocket):
        self.admin_inbox.discard(ws)

    async def notify_admin_inbox(self, payload: dict):
        for ws in list(self.admin_inbox):
            try:
                await ws.send_json(payload)
            except Exception:
                self.leave_admin_inbox(ws)


chat_manager = ChatConnectionManager()


class PresenceManager:
    """Mantém uma conexão viva por membro logado (enquanto ele estiver em
    qualquer tela do app) para poder avisar sobre chamadas recebidas em
    tempo real — v2.0 (Chamadas)."""

    def __init__(self):
        self.connections: dict[str, set[WebSocket]] = {}

    async def join(self, member_id: str, ws: WebSocket):
        self.connections.setdefault(member_id, set()).add(ws)

    def leave(self, member_id: str, ws: WebSocket):
        if member_id in self.connections:
            self.connections[member_id].discard(ws)
            if not self.connections[member_id]:
                del self.connections[member_id]

    async def notify(self, member_id: str, payload: dict):
        for ws in list(self.connections.get(member_id, [])):
            try:
                await ws.send_json(payload)
            except Exception:
                self.leave(member_id, ws)

    def is_online(self, member_id: str) -> bool:
        return bool(self.connections.get(member_id))


presence_manager = PresenceManager()


class CallSignalManager:
    """Retransmite mensagens de sinalização WebRTC (SDP/ICE) entre os
    participantes de uma sala de chamada — v2.0. O servidor nunca vê áudio
    ou vídeo: apenas ajuda os navegadores a se encontrarem (a mídia viaja
    diretamente entre os aparelhos, peer-to-peer)."""

    def __init__(self):
        self.rooms: dict[str, dict[str, WebSocket]] = {}

    async def join(self, room_id: str, member_id: str, ws: WebSocket):
        self.rooms.setdefault(room_id, {})[member_id] = ws

    def leave(self, room_id: str, member_id: str):
        if room_id in self.rooms:
            self.rooms[room_id].pop(member_id, None)
            if not self.rooms[room_id]:
                del self.rooms[room_id]

    async def relay(self, room_id: str, from_member_id: str, payload: dict):
        for member_id, ws in list(self.rooms.get(room_id, {}).items()):
            if member_id == from_member_id:
                continue
            try:
                await ws.send_json({**payload, "from": from_member_id})
            except Exception:
                self.leave(room_id, member_id)

    def participants(self, room_id: str) -> list:
        return list(self.rooms.get(room_id, {}).keys())


call_signal_manager = CallSignalManager()


def user_role(user: dict) -> str:
    if user.get("is_admin"):
        return "admin"
    return user.get("role") or "member"


def can_access_conversation(user: dict, conversation_id: str) -> bool:
    role = user_role(user)
    if conversation_id == GROUP_CONVERSATION_ID:
        return role in ("admin", "member")  # visitantes não têm grupo
    if conversation_id.startswith("private_"):
        owner_id = conversation_id[len("private_"):]
        return role == "admin" or user["id"] == owner_id
    return False


async def is_muted(member_id: str) -> bool:
    m = await db.members.find_one({"id": member_id}, {"chat_muted_until": 1})
    if not m or not m.get("chat_muted_until"):
        return False
    try:
        until = datetime.fromisoformat(m["chat_muted_until"])
    except Exception:
        return False
    return until > datetime.now(timezone.utc)


# ------------------------ Models ------------------------

class LoginIn(BaseModel):
    cpf: str


class MemberIn(BaseModel):
    name: str
    cpf: str
    phone: Optional[str] = ""
    is_admin: bool = False
    photo: Optional[str] = None
    role: Optional[str] = "member"  # admin | member | visitor — v2.0
    spiritual_name: Optional[str] = ""  # v2.0
    cargo: Optional[str] = ""  # v2.0
    join_date: Optional[str] = ""  # v2.0 (YYYY-MM-DD)
    mother_name: Optional[str] = ""  # v2.0 — Credencial Digital
    father_name: Optional[str] = ""  # v2.0
    birth_date: Optional[str] = ""  # v2.0 (YYYY-MM-DD)
    status: Optional[str] = "ativo"  # v2.0 — ativo | afastado | desligado


class MemberUpdate(BaseModel):
    name: Optional[str] = None
    cpf: Optional[str] = None
    phone: Optional[str] = None
    is_admin: Optional[bool] = None
    photo: Optional[str] = None
    role: Optional[str] = None
    spiritual_name: Optional[str] = None
    cargo: Optional[str] = None
    join_date: Optional[str] = None
    mother_name: Optional[str] = None
    father_name: Optional[str] = None
    birth_date: Optional[str] = None
    status: Optional[str] = None


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
    # --- v2.0: identidade e conteúdo público da Casa ---
    logo_image: Optional[str] = None
    cover_image: Optional[str] = None
    history_text: Optional[str] = None
    about_text: Optional[str] = None
    address: Optional[str] = None
    maps_link: Optional[str] = None
    contact_phone: Optional[str] = None
    whatsapp: Optional[str] = None
    instagram: Optional[str] = None
    facebook: Optional[str] = None
    contact_email: Optional[str] = None
    business_hours: Optional[str] = None
    # --- v2.0: Credencial Digital — assinatura do responsável ---
    signature_image: Optional[str] = None
    signature_name: Optional[str] = None
    signature_title: Optional[str] = None


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


# Público-alvo de publicações — v2.0
# all | members | visitors | members_visitors | admins
AUDIENCE_VALUES = ("all", "members", "visitors", "members_visitors", "admins")


class EventIn(BaseModel):
    title: str
    description: Optional[str] = ""
    category: str  # reuniao | gira | estudo | festividade | mutirao
    date: str  # YYYY-MM-DD
    time: Optional[str] = ""
    image: Optional[str] = ""  # v2.0
    location: Optional[str] = ""  # v2.0
    notes: Optional[str] = ""  # v2.0
    participants: Optional[str] = ""  # v2.0
    audience: Optional[str] = "all"  # v2.0


class NoticeIn(BaseModel):
    title: str
    body: str
    priority: str = "info"  # info | important | urgent
    audience: Optional[str] = "all"  # v2.0


class NewsPostIn(BaseModel):
    """Mural de notícias — v2.0."""
    title: str
    body: str
    photos: List[str] = []
    audience: Optional[str] = "all"


class GalleryAlbumIn(BaseModel):
    """Galeria de fotos — v2.0."""
    title: str
    year: int
    event_name: Optional[str] = ""
    date: Optional[str] = ""
    photos: List[str] = []
    audience: Optional[str] = "all"


class ReceiptIn(BaseModel):
    """Comprovante de pagamento enviado pelo membro — v2.0."""
    month: int
    year: int
    amount: float
    photo: str
    notes: Optional[str] = ""


# ------------------------ Feed & Stories (v2.x) ------------------------
# "composition" guarda o resultado do Compositor de Publicações do frontend:
# posição/tamanho/rotação da mídia, textos, emojis e figurinhas — permite
# reabrir/editar a publicação exatamente como foi montada. O backend não
# interpreta esse conteúdo, apenas armazena e devolve como veio.

class CompositionElement(BaseModel):
    kind: str  # "text" | "emoji" | "sticker"
    content: str  # texto em si, o emoji, ou a URL/id da figurinha
    x: float = 50  # posição em % da largura
    y: float = 50  # posição em % da altura
    scale: float = 1.0
    rotation: float = 0
    font_size: Optional[int] = None
    color: Optional[str] = None


class FeedPostIn(BaseModel):
    media_type: str = "photo"  # photo | video | text
    media: Optional[str] = ""  # data URL da foto/vídeo (vazio se for só texto)
    media_transform: Optional[dict] = None  # {x, y, scale, rotation} aplicado à mídia no compositor
    caption: Optional[str] = ""
    elements: List[CompositionElement] = []  # textos/emojis/figurinhas posicionados
    audience: Optional[str] = "all"
    music_track: Optional[dict] = None  # reservado p/ integração futura (ver /music)


class StoryIn(BaseModel):
    media_type: str = "photo"  # photo | video
    media: str
    media_transform: Optional[dict] = None
    elements: List[CompositionElement] = []
    music_track: Optional[dict] = None


class CommentIn(BaseModel):
    body: str


class MusicConnectIn(BaseModel):
    provider: str = "spotify"  # preparado para múltiplos serviços no futuro


# ------------------------ Chat (v2.0) ------------------------
# Estrutura: 1 Grupo dos Membros (membros + admins) + conversas privadas
# individuais (qualquer membro/visitante <-> administração). Sem grupo de
# visitantes — eles só têm a conversa privada.

GROUP_CONVERSATION_ID = "group_members"


class ChatMessageIn(BaseModel):
    conversation_id: str  # "group_members" | "private_<user_id>"
    type: str = "text"  # text | image | document | audio
    content: str  # texto da mensagem, ou data URL/base64 do anexo
    file_name: Optional[str] = ""  # nome original do arquivo, se houver
    reply_to: Optional[str] = None  # id da mensagem respondida


class MuteIn(BaseModel):
    member_id: str
    minutes: int = 60


# ------------------------ Chamadas (v2.0 — WebRTC) ------------------------

class CallStartIn(BaseModel):
    call_type: str = "audio"  # audio | video
    mode: str = "direct"  # direct (1 para 1) | group (reunião)
    target_member_id: Optional[str] = None  # obrigatório se mode == "direct"
    title: Optional[str] = ""  # usado em reuniões (mode == "group")


class CallInviteIn(BaseModel):
    member_id: str


# ------------------------ Seed ------------------------

DEFAULT_WELCOME = (
    "Salve! É com o coração cheio de fé que damos as boas-vindas a você. "
    "A nossa casa é um lar de união, respeito e espiritualidade — um espaço "
    "onde caminhamos juntos, sustentados pela força dos guias e pela mão de "
    "cada irmão de fé. Sua contribuição mantém acesa a luz do nosso terreiro "
    "e possibilita que sigamos servindo com amor. Axé!"
)


def visible_to(role: str) -> list:
    """Lista de valores de 'audience' visíveis para um determinado papel — v2.0."""
    if role == "admin":
        return list(AUDIENCE_VALUES)
    if role == "visitor":
        return ["all", "visitors", "members_visitors"]
    return ["all", "members", "members_visitors"]  # member (default)


async def log_action(actor: dict, action: str, details: str = ""):
    """Registra uma ação no histórico administrativo — v2.0 (Log de Auditoria)."""
    try:
        await db.audit_logs.insert_one({
            "id": str(uuid.uuid4()),
            "actor_name": actor.get("name", "—") if actor else "—",
            "actor_cpf": actor.get("cpf", "") if actor else "",
            "action": action,
            "details": details,
            "created_at": now_iso(),
        })
    except Exception:
        logging.getLogger(__name__).exception("Falha ao gravar log de auditoria")


async def seed_defaults():
    # Política de retenção — v2.x: mensagens do Chat são apagadas automaticamente
    # pelo próprio MongoDB 72h (3 dias) após o envio, sem precisar de nenhuma
    # rotina/cron separada — o índice TTL cuida disso sozinho no servidor.
    # (idempotente: recriar o índice com os mesmos parâmetros não tem efeito colateral)
    try:
        await db.chat_messages.create_index("expires_at", expireAfterSeconds=72 * 3600)
    except Exception:
        logging.getLogger(__name__).exception("Falha ao criar índice TTL do chat")

    try:
        # Stories somem sozinhos 24h após a publicação — mesmo mecanismo do chat.
        await db.stories.create_index("expires_at", expireAfterSeconds=24 * 3600)
    except Exception:
        logging.getLogger(__name__).exception("Falha ao criar índice TTL das Stories")

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
            "signature_name": "Márcio Nascimento Santos",
            "signature_title": "Juremeiro Responsável",
            "signature_image": "",
        })
    # Admin — garante que o CPF definido em ADMIN_CPF seja sempre administrador,
    # mesmo que o registro já existisse (ex: criado antes da variável de ambiente
    # estar configurada corretamente, ou por qualquer outro motivo).
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
    elif not admin.get("is_admin"):
        await db.members.update_one({"cpf": ADMIN_CPF}, {"$set": {"is_admin": True}})
        logging.getLogger(__name__).info("Corrigido: CPF admin promovido a administrador no startup.")


@app.on_event("startup")
async def on_startup():
    await seed_defaults()


def with_role(member: dict) -> dict:
    """Calcula o campo 'role' (admin | member | visitor) sem exigir migração de
    banco: registros antigos (que só têm is_admin) continuam funcionando."""
    if member is None:
        return member
    member = dict(member)
    if member.get("is_admin"):
        member["role"] = "admin"
    else:
        member["role"] = member.get("role") or "member"
    return member


def generate_credential_code() -> str:
    """Código de identificação da Credencial Digital — aleatório, não
    sequencial, 10 caracteres (letras maiúsculas + números)."""
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(10))


async def ensure_credential_code(member: dict) -> dict:
    """Garante que o membro tenha um código de credencial, gerando e
    persistindo um na primeira vez que for necessário (registros criados
    antes da Credencial Digital existir continuam funcionando, sem migração)."""
    if member.get("credential_code"):
        return member
    for _ in range(5):
        code = generate_credential_code()
        if not await db.members.find_one({"credential_code": code}):
            await db.members.update_one({"id": member["id"]}, {"$set": {"credential_code": code}})
            member = dict(member)
            member["credential_code"] = code
            return member
    return member  # extremamente improvável esgotar tentativas


async def with_financial_status(member: dict) -> dict:
    """Calcula o status financeiro automático — v2.0.
    🟢 em_dia | 🟡 vence_neste_mes | 🔴 atrasado (visitantes/admins: sem status)"""
    member = dict(member)
    role = member.get("role") or ("admin" if member.get("is_admin") else "member")
    if role != "member":
        member["financial_status"] = None
        return member
    now = datetime.now(timezone.utc)
    payment = await db.payments.find_one({"member_id": member["id"], "month": now.month, "year": now.year}, {"_id": 0})
    if payment and payment.get("status") == "paid":
        member["financial_status"] = "em_dia"
    elif payment and payment.get("status") == "overdue":
        member["financial_status"] = "atrasado"
    else:
        member["financial_status"] = "vence_neste_mes"
    return member


# ------------------------ Auth ------------------------

@api_router.post("/auth/login")
async def login(data: LoginIn):
    cpf = clean_cpf(data.cpf)
    if len(cpf) != 11:
        raise HTTPException(status_code=400, detail="CPF inválido. Informe 11 dígitos.")
    member = await db.members.find_one({"cpf": cpf}, {"_id": 0})
    if not member:
        raise HTTPException(status_code=404, detail="CPF não cadastrado. Fale com o administrador.")
    member = await ensure_credential_code(member)
    token = make_token(member['id'], member['cpf'], member.get('is_admin', False))
    return {"token": token, "user": with_role(member)}


@api_router.get("/auth/me")
async def me(user=Depends(get_current_user)):
    user = await ensure_credential_code(user)
    return with_role(user)


# ------------------------ Settings ------------------------

@api_router.get("/settings")
async def get_settings():
    s = await db.settings.find_one({"key": "app"}, {"_id": 0})
    return s


@api_router.put("/settings")
async def update_settings(data: SettingsIn, admin=Depends(require_admin)):
    patch = {k: v for k, v in data.model_dump().items() if v is not None}
    await db.settings.update_one({"key": "app"}, {"$set": patch})
    await log_action(admin, "Alterou as configurações da Casa", ", ".join(patch.keys()))
    return await db.settings.find_one({"key": "app"}, {"_id": 0})


# ------------------------ Members ------------------------

@api_router.get("/members")
async def list_members(admin=Depends(require_admin)):
    members = await db.members.find({}, {"_id": 0}).sort("name", 1).to_list(1000)
    out = []
    for m in members:
        m = await ensure_credential_code(m)
        out.append(await with_financial_status(with_role(m)))
    return out


@api_router.post("/members")
async def create_member(data: MemberIn, admin=Depends(require_admin)):
    cpf = clean_cpf(data.cpf)
    if len(cpf) != 11:
        raise HTTPException(status_code=400, detail="CPF inválido")
    if await db.members.find_one({"cpf": cpf}):
        raise HTTPException(status_code=409, detail="CPF já cadastrado")
    # Compatibilidade: is_admin=True (checkbox antigo) sempre força role=admin.
    role = "admin" if data.is_admin else (data.role or "member")
    if role not in ("admin", "member", "visitor"):
        role = "member"
    doc = {
        "id": str(uuid.uuid4()),
        "cpf": cpf,
        "name": data.name.strip(),
        "phone": (data.phone or "").strip(),
        "is_admin": role == "admin",
        "role": role,
        "photo": data.photo or None,
        "spiritual_name": (data.spiritual_name or "").strip(),
        "cargo": (data.cargo or "").strip(),
        "join_date": data.join_date or "",
        "mother_name": (data.mother_name or "").strip(),
        "father_name": (data.father_name or "").strip(),
        "birth_date": data.birth_date or "",
        "status": data.status if data.status in ("ativo", "afastado", "desligado") else "ativo",
        "credential_code": generate_credential_code(),
        "created_at": now_iso(),
    }
    await db.members.insert_one(doc)
    doc.pop("_id", None)
    await log_action(admin, f"Cadastrou o membro '{doc['name']}'", f"CPF {cpf}, papel: {role}")
    return doc


@api_router.put("/members/{member_id}")
async def update_member(member_id: str, data: MemberUpdate, admin=Depends(require_admin)):
    patch = {}
    payload = data.model_dump()
    if payload.get('name') is not None:
        patch['name'] = payload['name'].strip()
    if payload.get('phone') is not None:
        patch['phone'] = payload['phone'].strip()
    if payload.get('photo') is not None:
        patch['photo'] = payload['photo'] or None
    if payload.get('spiritual_name') is not None:
        patch['spiritual_name'] = payload['spiritual_name'].strip()
    if payload.get('cargo') is not None:
        patch['cargo'] = payload['cargo'].strip()
    if payload.get('join_date') is not None:
        patch['join_date'] = payload['join_date']
    if payload.get('mother_name') is not None:
        patch['mother_name'] = payload['mother_name'].strip()
    if payload.get('father_name') is not None:
        patch['father_name'] = payload['father_name'].strip()
    if payload.get('birth_date') is not None:
        patch['birth_date'] = payload['birth_date']
    if payload.get('status') is not None and payload['status'] in ("ativo", "afastado", "desligado"):
        patch['status'] = payload['status']
    if payload.get('is_admin') is not None or payload.get('role') is not None:
        if payload.get('is_admin') is True:
            role = "admin"
        elif payload.get('role') in ("admin", "member", "visitor"):
            role = payload['role']
        else:
            role = "admin" if payload.get('is_admin') else "member"
        patch['role'] = role
        patch['is_admin'] = role == "admin"
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
    await log_action(admin, f"Editou o membro (id {member_id})", ", ".join(patch.keys()))
    return with_role(await db.members.find_one({"id": member_id}, {"_id": 0}))


@api_router.delete("/members/{member_id}")
async def delete_member(member_id: str, admin=Depends(require_admin)):
    member = await db.members.find_one({"id": member_id})
    if not member:
        raise HTTPException(status_code=404, detail="Membro não encontrado")
    if member.get('cpf') == ADMIN_CPF:
        raise HTTPException(status_code=400, detail="Não é possível remover o administrador principal")
    await db.members.delete_one({"id": member_id})
    await db.payments.delete_many({"member_id": member_id})
    await log_action(admin, f"Excluiu o membro '{member.get('name', '')}'", f"CPF {member.get('cpf', '')}")
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
    await log_action(admin, f"Registrou pagamento de {member['name']}", f"{data.month}/{data.year} — R$ {data.amount} ({data.status})")
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
    await log_action(admin, "Atualizou um pagamento", f"id {payment_id}: {patch}")
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
    role = "admin" if user.get("is_admin") else (user.get("role") or "member")
    if q:
        q = {"$and": [q, {"$or": [{"audience": {"$in": visible_to(role)}}, {"audience": {"$exists": False}}]}]}
    else:
        q = {"$or": [{"audience": {"$in": visible_to(role)}}, {"audience": {"$exists": False}}]}
    items = await db.events.find(q, {"_id": 0}).sort("date", 1).to_list(2000)
    return items


@api_router.post("/events")
async def create_event(data: EventIn, admin=Depends(require_admin)):
    audience = data.audience if data.audience in AUDIENCE_VALUES else "all"
    doc = {
        "id": str(uuid.uuid4()),
        "title": data.title.strip(),
        "description": (data.description or "").strip(),
        "category": data.category,
        "date": data.date,
        "time": data.time or "",
        "image": data.image or "",
        "location": (data.location or "").strip(),
        "notes": (data.notes or "").strip(),
        "participants": (data.participants or "").strip(),
        "audience": audience,
        "created_at": now_iso(),
    }
    await db.events.insert_one(doc)
    doc.pop("_id", None)
    await log_action(admin, f"Criou o evento '{doc['title']}'", f"{doc['date']} — público: {audience}")
    return doc


@api_router.put("/events/{event_id}")
async def update_event(event_id: str, data: EventIn, admin=Depends(require_admin)):
    audience = data.audience if data.audience in AUDIENCE_VALUES else "all"
    patch = {
        "title": data.title.strip(),
        "description": (data.description or "").strip(),
        "category": data.category,
        "date": data.date,
        "time": data.time or "",
        "image": data.image or "",
        "location": (data.location or "").strip(),
        "notes": (data.notes or "").strip(),
        "participants": (data.participants or "").strip(),
        "audience": audience,
    }
    result = await db.events.update_one({"id": event_id}, {"$set": patch})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Evento não encontrado")
    await log_action(admin, f"Editou o evento '{patch['title']}'", f"id {event_id}")
    return await db.events.find_one({"id": event_id}, {"_id": 0})


@api_router.delete("/events/{event_id}")
async def delete_event(event_id: str, admin=Depends(require_admin)):
    event = await db.events.find_one({"id": event_id})
    result = await db.events.delete_one({"id": event_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Evento não encontrado")
    await log_action(admin, f"Excluiu o evento '{event.get('title', '') if event else ''}'", f"id {event_id}")
    return {"ok": True}


# ------------------------ Notices ------------------------

@api_router.get("/notices")
async def list_notices(user=Depends(get_current_user)):
    role = "admin" if user.get("is_admin") else (user.get("role") or "member")
    q = {"$or": [{"audience": {"$in": visible_to(role)}}, {"audience": {"$exists": False}}]}
    items = await db.notices.find(q, {"_id": 0}).sort("created_at", -1).to_list(500)
    return items


@api_router.post("/notices")
async def create_notice(data: NoticeIn, admin=Depends(require_admin)):
    audience = data.audience if data.audience in AUDIENCE_VALUES else "all"
    doc = {
        "id": str(uuid.uuid4()),
        "title": data.title.strip(),
        "body": data.body.strip(),
        "priority": data.priority,
        "audience": audience,
        "created_at": now_iso(),
        "created_by": admin['id'],
        "created_by_name": admin['name'],
    }
    await db.notices.insert_one(doc)
    doc.pop("_id", None)
    await log_action(admin, f"Publicou o aviso '{doc['title']}'", f"prioridade: {data.priority}, público: {audience}")
    return doc


@api_router.put("/notices/{notice_id}")
async def update_notice(notice_id: str, data: NoticeIn, admin=Depends(require_admin)):
    audience = data.audience if data.audience in AUDIENCE_VALUES else "all"
    patch = {
        "title": data.title.strip(),
        "body": data.body.strip(),
        "priority": data.priority,
        "audience": audience,
    }
    result = await db.notices.update_one({"id": notice_id}, {"$set": patch})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Aviso não encontrado")
    await log_action(admin, f"Editou o aviso '{patch['title']}'", f"id {notice_id}")
    return await db.notices.find_one({"id": notice_id}, {"_id": 0})


@api_router.delete("/notices/{notice_id}")
async def delete_notice(notice_id: str, admin=Depends(require_admin)):
    notice = await db.notices.find_one({"id": notice_id})
    result = await db.notices.delete_one({"id": notice_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Aviso não encontrado")
    await log_action(admin, f"Excluiu o aviso '{notice.get('title', '') if notice else ''}'", f"id {notice_id}")
    return {"ok": True}


# ------------------------ Reports ------------------------

@api_router.get("/reports/summary")
async def reports_summary(admin=Depends(require_admin), year: Optional[int] = None, month: Optional[int] = None):
    now = datetime.now(timezone.utc)
    y = year or now.year
    m = month or now.month
    members = await db.members.find({"is_admin": {"$ne": True}, "role": {"$ne": "visitor"}}, {"_id": 0}).to_list(2000)
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


# ============================================================
#  v2.0 — Mural, Galeria, Comprovantes, Log, Dashboard, Busca, Backup
# ============================================================

# ------------------------ Mural de Notícias ------------------------

@api_router.get("/news")
async def list_news(user=Depends(get_current_user)):
    role = "admin" if user.get("is_admin") else (user.get("role") or "member")
    q = {"$or": [{"audience": {"$in": visible_to(role)}}, {"audience": {"$exists": False}}]}
    return await db.news_posts.find(q, {"_id": 0}).sort("created_at", -1).to_list(500)


@api_router.post("/news")
async def create_news(data: NewsPostIn, admin=Depends(require_admin)):
    audience = data.audience if data.audience in AUDIENCE_VALUES else "all"
    doc = {
        "id": str(uuid.uuid4()),
        "title": data.title.strip(),
        "body": data.body.strip(),
        "photos": data.photos or [],
        "audience": audience,
        "author_name": admin.get("name", "Administração"),
        "created_at": now_iso(),
    }
    await db.news_posts.insert_one(doc)
    doc.pop("_id", None)
    await log_action(admin, f"Publicou no mural: '{doc['title']}'", f"público: {audience}")
    return doc


@api_router.put("/news/{post_id}")
async def update_news(post_id: str, data: NewsPostIn, admin=Depends(require_admin)):
    audience = data.audience if data.audience in AUDIENCE_VALUES else "all"
    patch = {"title": data.title.strip(), "body": data.body.strip(), "photos": data.photos or [], "audience": audience}
    result = await db.news_posts.update_one({"id": post_id}, {"$set": patch})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Publicação não encontrada")
    await log_action(admin, f"Editou publicação do mural: '{patch['title']}'", f"id {post_id}")
    return await db.news_posts.find_one({"id": post_id}, {"_id": 0})


@api_router.delete("/news/{post_id}")
async def delete_news(post_id: str, admin=Depends(require_admin)):
    await db.news_posts.delete_one({"id": post_id})
    await log_action(admin, "Excluiu publicação do mural", f"id {post_id}")
    return {"ok": True}


# ------------------------ Galeria ------------------------

@api_router.get("/gallery")
async def list_gallery(user=Depends(get_current_user)):
    role = "admin" if user.get("is_admin") else (user.get("role") or "member")
    q = {"$or": [{"audience": {"$in": visible_to(role)}}, {"audience": {"$exists": False}}]}
    return await db.gallery_albums.find(q, {"_id": 0}).sort("date", -1).to_list(500)


@api_router.post("/gallery")
async def create_gallery_album(data: GalleryAlbumIn, admin=Depends(require_admin)):
    audience = data.audience if data.audience in AUDIENCE_VALUES else "all"
    doc = {
        "id": str(uuid.uuid4()),
        "title": data.title.strip(),
        "year": data.year,
        "event_name": (data.event_name or "").strip(),
        "date": data.date or "",
        "photos": data.photos or [],
        "audience": audience,
        "created_at": now_iso(),
    }
    await db.gallery_albums.insert_one(doc)
    doc.pop("_id", None)
    await log_action(admin, f"Criou álbum na galeria: '{doc['title']}'", f"público: {audience}")
    return doc


@api_router.put("/gallery/{album_id}")
async def update_gallery_album(album_id: str, data: GalleryAlbumIn, admin=Depends(require_admin)):
    audience = data.audience if data.audience in AUDIENCE_VALUES else "all"
    patch = {
        "title": data.title.strip(), "year": data.year,
        "event_name": (data.event_name or "").strip(), "date": data.date or "",
        "photos": data.photos or [], "audience": audience,
    }
    result = await db.gallery_albums.update_one({"id": album_id}, {"$set": patch})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Álbum não encontrado")
    await log_action(admin, f"Editou álbum da galeria: '{patch['title']}'", f"id {album_id}")
    return await db.gallery_albums.find_one({"id": album_id}, {"_id": 0})


@api_router.delete("/gallery/{album_id}")
async def delete_gallery_album(album_id: str, admin=Depends(require_admin)):
    await db.gallery_albums.delete_one({"id": album_id})
    await log_action(admin, "Excluiu álbum da galeria", f"id {album_id}")
    return {"ok": True}


# ------------------------ Comprovantes ------------------------

@api_router.get("/receipts/me")
async def my_receipts(user=Depends(get_current_user)):
    return await db.receipts.find({"member_id": user["id"]}, {"_id": 0}).sort("submitted_at", -1).to_list(200)


@api_router.post("/receipts")
async def submit_receipt(data: ReceiptIn, user=Depends(get_current_user)):
    role = "admin" if user.get("is_admin") else (user.get("role") or "member")
    if role == "visitor":
        raise HTTPException(status_code=403, detail="Visitantes não enviam comprovante de mensalidade")
    doc = {
        "id": str(uuid.uuid4()),
        "member_id": user["id"],
        "member_name": user.get("name", ""),
        "member_cpf": user.get("cpf", ""),
        "month": data.month,
        "year": data.year,
        "amount": data.amount,
        "photo": data.photo,
        "notes": data.notes or "",
        "status": "pending",  # pending | approved | rejected
        "submitted_at": now_iso(),
        "reviewed_at": None,
        "reviewed_by": None,
    }
    await db.receipts.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api_router.get("/receipts")
async def list_receipts(admin=Depends(require_admin), status: Optional[str] = None):
    q = {}
    if status:
        q["status"] = status
    return await db.receipts.find(q, {"_id": 0}).sort("submitted_at", -1).to_list(500)


@api_router.put("/receipts/{receipt_id}/approve")
async def approve_receipt(receipt_id: str, admin=Depends(require_admin)):
    receipt = await db.receipts.find_one({"id": receipt_id})
    if not receipt:
        raise HTTPException(status_code=404, detail="Comprovante não encontrado")
    await db.receipts.update_one({"id": receipt_id}, {"$set": {
        "status": "approved", "reviewed_at": now_iso(), "reviewed_by": admin.get("name", ""),
    }})
    # Atualiza/gera automaticamente o registro de pagamento do mês — status financeiro
    # do membro passa a refletir "em dia" imediatamente.
    existing_payment = await db.payments.find_one({"member_id": receipt["member_id"], "year": receipt["year"], "month": receipt["month"]})
    if existing_payment:
        await db.payments.update_one({"id": existing_payment["id"]}, {"$set": {"status": "paid", "amount": receipt["amount"], "method": "pix", "paid_at": now_iso()}})
    else:
        await db.payments.insert_one({
            "id": str(uuid.uuid4()), "member_id": receipt["member_id"], "member_name": receipt.get("member_name", ""),
            "member_cpf": receipt.get("member_cpf", ""), "month": receipt["month"], "year": receipt["year"],
            "amount": receipt["amount"], "status": "paid", "method": "pix", "notes": "Aprovado via comprovante",
            "paid_at": now_iso(), "created_at": now_iso(),
        })
    await log_action(admin, f"Aprovou comprovante de {receipt.get('member_name', '')}", f"{receipt['month']}/{receipt['year']}")
    return await db.receipts.find_one({"id": receipt_id}, {"_id": 0})


@api_router.put("/receipts/{receipt_id}/reject")
async def reject_receipt(receipt_id: str, admin=Depends(require_admin)):
    receipt = await db.receipts.find_one({"id": receipt_id})
    if not receipt:
        raise HTTPException(status_code=404, detail="Comprovante não encontrado")
    await db.receipts.update_one({"id": receipt_id}, {"$set": {
        "status": "rejected", "reviewed_at": now_iso(), "reviewed_by": admin.get("name", ""),
    }})
    await log_action(admin, f"Rejeitou comprovante de {receipt.get('member_name', '')}", f"{receipt['month']}/{receipt['year']}")
    return await db.receipts.find_one({"id": receipt_id}, {"_id": 0})


# ------------------------ Log de Auditoria ------------------------

@api_router.get("/audit-logs")
async def get_audit_logs(admin=Depends(require_admin), limit: int = 200):
    limit = min(max(limit, 1), 1000)
    return await db.audit_logs.find({}, {"_id": 0}).sort("created_at", -1).to_list(limit)


# ------------------------ Dashboard do Administrador ------------------------

@api_router.get("/admin/dashboard")
async def admin_dashboard(admin=Depends(require_admin)):
    now = datetime.now(timezone.utc)
    all_members = await db.members.find({}, {"_id": 0}).to_list(2000)
    members_only = [m for m in all_members if not m.get("is_admin") and (m.get("role") or "member") == "member"]
    visitors_only = [m for m in all_members if (m.get("role") or "") == "visitor"]

    payments_this_month = await db.payments.find({"year": now.year, "month": now.month}, {"_id": 0}).to_list(2000)
    paid_member_ids = {p["member_id"] for p in payments_this_month if p.get("status") == "paid"}
    delinquent = [m for m in members_only if m["id"] not in paid_member_ids]

    next_event = await db.events.find_one(
        {"date": {"$gte": now.strftime("%Y-%m-%d")}}, {"_id": 0}, sort=[("date", 1)]
    )
    latest_notices = await db.notices.find({}, {"_id": 0}).sort("created_at", -1).to_list(5)
    latest_receipts = await db.receipts.find({}, {"_id": 0}).sort("submitted_at", -1).to_list(5)
    latest_news = await db.news_posts.find({}, {"_id": 0}).sort("created_at", -1).to_list(5)

    return {
        "total_members": len(members_only),
        "total_visitors": len(visitors_only),
        "active_members": len(members_only),
        "delinquent_members": len(delinquent),
        "paid_this_month": len(paid_member_ids),
        "next_event": next_event,
        "latest_notices": latest_notices,
        "latest_receipts": latest_receipts,
        "latest_news": latest_news,
    }


# ------------------------ Pesquisa Global ------------------------

@api_router.get("/search")
async def global_search(q: str, admin=Depends(require_admin)):
    if not q or len(q.strip()) < 2:
        return {"members": [], "events": [], "notices": [], "news": []}
    rx = {"$regex": re.escape(q.strip()), "$options": "i"}
    members = await db.members.find({"$or": [{"name": rx}, {"cpf": rx}]}, {"_id": 0}).to_list(20)
    events = await db.events.find({"title": rx}, {"_id": 0}).to_list(20)
    notices = await db.notices.find({"title": rx}, {"_id": 0}).to_list(20)
    news = await db.news_posts.find({"title": rx}, {"_id": 0}).to_list(20)
    return {"members": members, "events": events, "notices": notices, "news": news}


# ------------------------ Backup / Exportação ------------------------

@api_router.get("/admin/backup")
async def export_backup(admin=Depends(require_admin)):
    collections = ["members", "settings", "payments", "events", "notices", "news_posts", "gallery_albums", "receipts", "audit_logs", "chat_messages", "webauthn_credentials", "calls", "feed_posts", "feed_comments", "stories", "music_connections"]
    data = {}
    for name in collections:
        data[name] = await db[name].find({}, {"_id": 0}).to_list(10000)
    await log_action(admin, "Exportou backup completo do sistema")
    return {"exported_at": now_iso(), "data": data}


# ------------------------ Área do Visitante (pública, sem login) ------------------------

@api_router.get("/public/settings")
async def public_settings():
    s = await db.settings.find_one({"key": "app"}, {"_id": 0}) or {}
    return {
        "house_name": s.get("house_name"),
        "house_short": s.get("house_short"),
        "founded_year": s.get("founded_year"),
        "logo_image": s.get("logo_image", ""),
        "cover_image": s.get("cover_image", ""),
        "history_text": s.get("history_text", ""),
        "about_text": s.get("about_text", ""),
        "address": s.get("address", ""),
        "maps_link": s.get("maps_link", ""),
        "contact_phone": s.get("contact_phone", ""),
        "whatsapp": s.get("whatsapp", ""),
        "contact_email": s.get("contact_email", ""),
        "instagram": s.get("instagram", ""),
        "facebook": s.get("facebook", ""),
        "business_hours": s.get("business_hours", ""),
    }


@api_router.get("/public/events")
async def public_events(year: Optional[int] = None, month: Optional[int] = None):
    now = datetime.now(timezone.utc)
    y = year or now.year
    m = month or now.month
    prefix = f"{y:04d}-{m:02d}"
    q = {"date": {"$regex": f"^{prefix}"}, "$or": [{"audience": {"$in": visible_to('visitor')}}, {"audience": {"$exists": False}}]}
    return await db.events.find(q, {"_id": 0}).sort("date", 1).to_list(500)


@api_router.get("/public/notices")
async def public_notices():
    q = {"$or": [{"audience": {"$in": visible_to('visitor')}}, {"audience": {"$exists": False}}]}
    return await db.notices.find(q, {"_id": 0}).sort("created_at", -1).to_list(100)


@api_router.get("/public/news")
async def public_news():
    q = {"$or": [{"audience": {"$in": visible_to('visitor')}}, {"audience": {"$exists": False}}]}
    return await db.news_posts.find(q, {"_id": 0}).sort("created_at", -1).to_list(500)


@api_router.get("/public/gallery")
async def public_gallery():
    q = {"$or": [{"audience": {"$in": visible_to('visitor')}}, {"audience": {"$exists": False}}]}
    return await db.gallery_albums.find(q, {"_id": 0}).sort("date", -1).to_list(500)


# ============================================================
#  Chat (v2.0) — Grupo dos Membros + conversas privadas com a administração
# ============================================================

def _msg_out(m: dict) -> dict:
    m = dict(m)
    m.pop("_id", None)
    return m


@api_router.get("/chat/group/messages")
async def group_history(user=Depends(get_current_user), before: Optional[str] = None, limit: int = 50):
    if not can_access_conversation(user, GROUP_CONVERSATION_ID):
        raise HTTPException(status_code=403, detail="Sem acesso ao grupo")
    q = {"conversation_id": GROUP_CONVERSATION_ID, "deleted": {"$ne": True}}
    if before:
        q["created_at"] = {"$lt": before}
    limit = min(max(limit, 1), 200)
    items = await db.chat_messages.find(q, {"_id": 0}).sort("created_at", -1).to_list(limit)
    return list(reversed(items))


@api_router.get("/chat/private/{owner_id}/messages")
async def private_history(owner_id: str, user=Depends(get_current_user), before: Optional[str] = None, limit: int = 50):
    conv = f"private_{owner_id}"
    if not can_access_conversation(user, conv):
        raise HTTPException(status_code=403, detail="Sem acesso a esta conversa")
    q = {"conversation_id": conv, "deleted": {"$ne": True}}
    if before:
        q["created_at"] = {"$lt": before}
    limit = min(max(limit, 1), 200)
    items = await db.chat_messages.find(q, {"_id": 0}).sort("created_at", -1).to_list(limit)
    return list(reversed(items))


@api_router.get("/chat/private/threads")
async def private_threads(admin=Depends(require_admin)):
    """Lista, para o administrador, todas as conversas privadas com a última mensagem — inbox."""
    pipeline = [
        {"$match": {"conversation_id": {"$regex": "^private_"}, "deleted": {"$ne": True}}},
        {"$sort": {"created_at": -1}},
        {"$group": {
            "_id": "$conversation_id",
            "last_message": {"$first": "$content"},
            "last_type": {"$first": "$type"},
            "last_at": {"$first": "$created_at"},
            "last_sender_name": {"$first": "$sender_name"},
        }},
        {"$sort": {"last_at": -1}},
    ]
    threads = await db.chat_messages.aggregate(pipeline).to_list(500)
    out = []
    for t in threads:
        owner_id = t["_id"][len("private_"):]
        owner = await db.members.find_one({"id": owner_id}, {"_id": 0, "name": 1, "photo": 1, "role": 1, "is_admin": 1})
        out.append({
            "conversation_id": t["_id"],
            "owner_id": owner_id,
            "owner_name": owner.get("name") if owner else "Usuário removido",
            "owner_photo": owner.get("photo") if owner else None,
            "last_message": t["last_message"] if t["last_type"] == "text" else f"[{t['last_type']}]",
            "last_at": t["last_at"],
            "last_sender_name": t["last_sender_name"],
        })
    return out


@api_router.delete("/chat/messages/{message_id}")
async def delete_chat_message(message_id: str, admin=Depends(require_admin)):
    """Moderação: exclui (soft-delete) uma mensagem inadequada."""
    result = await db.chat_messages.update_one({"id": message_id}, {"$set": {"deleted": True}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Mensagem não encontrada")
    msg = await db.chat_messages.find_one({"id": message_id}, {"_id": 0})
    await chat_manager.broadcast(msg["conversation_id"], {"event": "message_deleted", "message_id": message_id})
    await log_action(admin, "Excluiu mensagem do chat", f"id {message_id}")
    return {"ok": True}


@api_router.post("/chat/mute")
async def mute_member(data: MuteIn, admin=Depends(require_admin)):
    until = (datetime.now(timezone.utc) + timedelta(minutes=data.minutes)).isoformat()
    result = await db.members.update_one({"id": data.member_id}, {"$set": {"chat_muted_until": until}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Membro não encontrado")
    await log_action(admin, "Silenciou um usuário no chat", f"id {data.member_id} por {data.minutes} min")
    return {"ok": True, "muted_until": until}


@api_router.post("/chat/unmute/{member_id}")
async def unmute_member(member_id: str, admin=Depends(require_admin)):
    await db.members.update_one({"id": member_id}, {"$unset": {"chat_muted_until": ""}})
    await log_action(admin, "Retirou o silenciamento de um usuário no chat", f"id {member_id}")
    return {"ok": True}


@api_router.post("/chat/group/remove/{member_id}")
async def remove_from_group(member_id: str, admin=Depends(require_admin)):
    result = await db.members.update_one({"id": member_id}, {"$set": {"chat_removed": True}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Membro não encontrado")
    await log_action(admin, "Removeu um usuário do Grupo dos Membros (chat)", f"id {member_id}")
    return {"ok": True}


@api_router.post("/chat/group/restore/{member_id}")
async def restore_to_group(member_id: str, admin=Depends(require_admin)):
    await db.members.update_one({"id": member_id}, {"$set": {"chat_removed": False}})
    await log_action(admin, "Readicionou um usuário ao Grupo dos Membros (chat)", f"id {member_id}")
    return {"ok": True}


@api_router.get("/chat/group/participants")
async def group_participants(admin=Depends(require_admin)):
    members = await db.members.find(
        {"is_admin": {"$ne": True}, "role": {"$ne": "visitor"}},
        {"_id": 0, "id": 1, "name": 1, "photo": 1, "chat_removed": 1, "chat_muted_until": 1},
    ).sort("name", 1).to_list(1000)
    now = datetime.now(timezone.utc)
    for m in members:
        until = m.get("chat_muted_until")
        m["muted"] = bool(until and datetime.fromisoformat(until) > now)
    return members


async def _persist_and_broadcast(user: dict, data: ChatMessageIn):
    if not can_access_conversation(user, data.conversation_id):
        return {"error": "Sem acesso a esta conversa"}
    role = user_role(user)
    if role != "admin":
        member = await db.members.find_one({"id": user["id"]}, {"_id": 0})
        if member and member.get("chat_removed") and data.conversation_id == GROUP_CONVERSATION_ID:
            return {"error": "Você foi removido deste grupo pela administração"}
        if await is_muted(user["id"]):
            return {"error": "Você está temporariamente silenciado neste chat"}
    if data.type not in ("text", "image", "document", "audio"):
        return {"error": "Tipo de mensagem inválido"}
    if not data.content:
        return {"error": "Mensagem vazia"}
    if data.type != "text" and len(data.content) > 7_000_000:  # ~5MB de arquivo em base64
        return {"error": "Arquivo muito grande (máx. ~5MB)"}
    msg = {
        "id": str(uuid.uuid4()),
        "conversation_id": data.conversation_id,
        "sender_id": user["id"],
        "sender_name": user.get("name", ""),
        "sender_photo": user.get("photo"),
        "sender_role": role,
        "type": data.type,
        "content": data.content,
        "file_name": data.file_name or "",
        "reply_to": data.reply_to,
        "deleted": False,
        "created_at": now_iso(),
        "expires_at": datetime.now(timezone.utc),  # Política de retenção — v2.x: mensagens somem sozinhas após 72h (ver índice TTL no startup)
    }
    await db.chat_messages.insert_one(dict(msg))
    out = _msg_out(msg)
    await chat_manager.broadcast(data.conversation_id, {"event": "message", "message": out})
    if data.conversation_id.startswith("private_"):
        await chat_manager.notify_admin_inbox({"event": "private_activity", "conversation_id": data.conversation_id, "preview": out})
    return {"ok": True, "message": out}


@api_router.post("/chat/messages")
async def send_chat_message_rest(data: ChatMessageIn, user=Depends(get_current_user)):
    """Fallback REST (usado quando o WebSocket não está disponível) — mesma
    lógica de persistência e transmissão em tempo real do WebSocket."""
    result = await _persist_and_broadcast(user, data)
    if "error" in result:
        raise HTTPException(status_code=403, detail=result["error"])
    return result["message"]


@api_router.websocket("/ws/chat/{conversation_id}")
async def ws_chat(websocket: WebSocket, conversation_id: str, token: str = Query(...)):
    user = await get_user_from_ws_token(token)
    if not user or not can_access_conversation(user, conversation_id):
        await websocket.close(code=4401)
        return
    await websocket.accept()
    await chat_manager.join(conversation_id, websocket)
    try:
        while True:
            raw = await websocket.receive_json()
            try:
                data = ChatMessageIn(**{**raw, "conversation_id": conversation_id})
            except Exception:
                await websocket.send_json({"event": "error", "detail": "Payload inválido"})
                continue
            result = await _persist_and_broadcast(user, data)
            if "error" in result:
                await websocket.send_json({"event": "error", "detail": result["error"]})
    except WebSocketDisconnect:
        pass
    finally:
        chat_manager.leave(conversation_id, websocket)


@api_router.websocket("/ws/admin-inbox")
async def ws_admin_inbox(websocket: WebSocket, token: str = Query(...)):
    user = await get_user_from_ws_token(token)
    if not user or not user.get("is_admin"):
        await websocket.close(code=4401)
        return
    await websocket.accept()
    await chat_manager.join_admin_inbox(websocket)
    try:
        while True:
            await websocket.receive_text()  # canal somente de notificação; ignora entrada
    except WebSocketDisconnect:
        pass
    finally:
        chat_manager.leave_admin_inbox(websocket)


# ============================================================
#  Credencial Digital (v2.0)
# ============================================================

def _month_status_history(member_id: str, payments: list, year: int) -> list:
    by_month = {p["month"]: p for p in payments if p.get("year") == year and p.get("member_id") == member_id}
    out = []
    for i in range(1, 13):
        p = by_month.get(i)
        out.append({"month": i, "month_name": MONTHS_PT_LIST[i - 1], "status": p["status"] if p else "sem_registro"})
    return out


MONTHS_PT_LIST = ["Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho", "Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"]


class MyPhotoIn(BaseModel):
    photo: str  # data URL da foto capturada pela câmera


@api_router.put("/members/me/photo")
async def update_my_photo(data: MyPhotoIn, user=Depends(get_current_user)):
    """Autoatendimento: o próprio membro atualiza sua foto oficial da Credencial
    Digital (capturada pela câmera no app, nunca da galeria)."""
    await db.members.update_one({"id": user["id"]}, {"$set": {"photo": data.photo}})
    return {"ok": True}


@api_router.get("/members/me/credential")
async def my_credential(user=Depends(get_current_user)):
    """Dados completos da credencial do próprio membro (uso no app, autenticado)."""
    user = await ensure_credential_code(user)
    role = "admin" if user.get("is_admin") else (user.get("role") or "member")
    settings = await db.settings.find_one({"key": "app"}, {"_id": 0}) or {}
    year = datetime.now(timezone.utc).year
    payments = await db.payments.find({"member_id": user["id"], "year": year}, {"_id": 0}).to_list(20)
    return {
        "id": user["id"],
        "credential_code": user.get("credential_code"),
        "name": user.get("name"),
        "cpf": user.get("cpf"),
        "photo": user.get("photo"),
        "mother_name": user.get("mother_name", ""),
        "father_name": user.get("father_name", ""),
        "birth_date": user.get("birth_date", ""),
        "join_date": user.get("join_date", ""),
        "status": user.get("status", "ativo"),
        "role": role,
        "house_name": settings.get("house_name", ""),
        "house_short": settings.get("house_short", ""),
        "signature_image": settings.get("signature_image", ""),
        "signature_name": settings.get("signature_name", "Márcio Nascimento Santos"),
        "signature_title": settings.get("signature_title", "Juremeiro Responsável"),
        "contribution_history": _month_status_history(user["id"], payments, year),
    }


@api_router.get("/credential/{code}")
async def public_credential(code: str):
    """Página pública aberta ao escanear o QR Code — sem dados pessoais sensíveis."""
    member = await db.members.find_one({"credential_code": code}, {"_id": 0})
    if not member:
        raise HTTPException(status_code=404, detail="Credencial não encontrada")
    settings = await db.settings.find_one({"key": "app"}, {"_id": 0}) or {}
    year = datetime.now(timezone.utc).year
    payments = await db.payments.find({"member_id": member["id"], "year": year}, {"_id": 0}).to_list(20)
    return {
        "credential_code": member.get("credential_code"),
        "name": member.get("name"),
        "photo": member.get("photo"),
        "join_date": member.get("join_date", ""),
        "status": member.get("status", "ativo"),
        "house_name": settings.get("house_name", ""),
        "house_short": settings.get("house_short", ""),
        "contribution_history": _month_status_history(member["id"], payments, year),
    }


@api_router.get("/members/{member_id}/credential")
async def member_credential_admin(member_id: str, admin=Depends(require_admin)):
    """Visão da credencial de um membro específico, para o administrador."""
    member = await db.members.find_one({"id": member_id}, {"_id": 0})
    if not member:
        raise HTTPException(status_code=404, detail="Membro não encontrado")
    member = await ensure_credential_code(member)
    settings = await db.settings.find_one({"key": "app"}, {"_id": 0}) or {}
    year = datetime.now(timezone.utc).year
    payments = await db.payments.find({"member_id": member_id, "year": year}, {"_id": 0}).to_list(20)
    return {
        **with_role(member),
        "house_name": settings.get("house_name", ""),
        "house_short": settings.get("house_short", ""),
        "signature_image": settings.get("signature_image", ""),
        "signature_name": settings.get("signature_name", "Márcio Nascimento Santos"),
        "signature_title": settings.get("signature_title", "Juremeiro Responsável"),
        "contribution_history": _month_status_history(member_id, payments, year),
    }


@api_router.post("/members/{member_id}/credential/regenerate")
async def regenerate_credential_code(member_id: str, admin=Depends(require_admin)):
    """Gera um novo código de credencial (ex: em caso de suspeita de uso indevido do QR)."""
    member = await db.members.find_one({"id": member_id})
    if not member:
        raise HTTPException(status_code=404, detail="Membro não encontrado")
    for _ in range(5):
        code = generate_credential_code()
        if not await db.members.find_one({"credential_code": code}):
            await db.members.update_one({"id": member_id}, {"$set": {"credential_code": code}})
            await log_action(admin, f"Gerou novo código de credencial para '{member.get('name', '')}'", f"id {member_id}")
            return {"credential_code": code}
    raise HTTPException(status_code=500, detail="Não foi possível gerar um código único, tente novamente")


@api_router.get("/members/me/receipts-with-status")
async def my_receipts_with_status(user=Depends(get_current_user)):
    """'Meus Comprovantes' — comprovantes enviados, com o status de aprovação de cada um."""
    return await db.receipts.find({"member_id": user["id"]}, {"_id": 0}).sort("submitted_at", -1).to_list(200)


@api_router.delete("/receipts/{receipt_id}")
async def delete_receipt(receipt_id: str, admin=Depends(require_admin)):
    """Gerenciamento de armazenamento: administrador remove comprovantes antigos/duplicados."""
    result = await db.receipts.delete_one({"id": receipt_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Comprovante não encontrado")
    await log_action(admin, "Excluiu um comprovante (limpeza de armazenamento)", f"id {receipt_id}")
    return {"ok": True}


# ------------------------ WebAuthn — biometria do aparelho (v2.0) ------------------------
# Trava LOCAL adicional para abrir a Credencial Digital. O login por CPF
# continua sendo a autenticação principal do sistema; se a biometria falhar
# ou não estiver configurada, o app permanece 100% utilizável pelo CPF.

class WebAuthnRegisterVerifyIn(BaseModel):
    credential: dict
    device_label: Optional[str] = ""


class WebAuthnLoginVerifyIn(BaseModel):
    credential: dict


@api_router.post("/webauthn/register/options")
async def webauthn_register_options(user=Depends(get_current_user)):
    existing_creds = await db.webauthn_credentials.find({"member_id": user["id"]}, {"_id": 0}).to_list(20)
    exclude = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credential_id"])) for c in existing_creds]
    options = webauthn.generate_registration_options(
        rp_id=WEBAUTHN_RP_ID,
        rp_name=WEBAUTHN_RP_NAME,
        user_id=user["id"].encode(),
        user_name=user.get("cpf", user["id"]),
        user_display_name=user.get("name", "Membro"),
        exclude_credentials=exclude,
        authenticator_selection=AuthenticatorSelectionCriteria(user_verification=UserVerificationRequirement.REQUIRED),
    )
    await db.members.update_one({"id": user["id"]}, {"$set": {"webauthn_challenge": bytes_to_base64url(options.challenge)}})
    return json.loads(options_to_json(options))


@api_router.post("/webauthn/register/verify")
async def webauthn_register_verify(data: WebAuthnRegisterVerifyIn, user=Depends(get_current_user)):
    member = await db.members.find_one({"id": user["id"]})
    challenge_b64 = member.get("webauthn_challenge") if member else None
    if not challenge_b64:
        raise HTTPException(status_code=400, detail="Nenhum registro de biometria em andamento. Tente novamente.")
    try:
        cred = parse_registration_credential_json(json.dumps(data.credential))
        verification = webauthn.verify_registration_response(
            credential=cred,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=WEBAUTHN_RP_ID,
            expected_origin=WEBAUTHN_ORIGIN,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Não foi possível confirmar a biometria: {e}")
    await db.webauthn_credentials.insert_one({
        "id": str(uuid.uuid4()),
        "member_id": user["id"],
        "credential_id": bytes_to_base64url(verification.credential_id),
        "public_key": bytes_to_base64url(verification.credential_public_key),
        "sign_count": verification.sign_count,
        "device_label": data.device_label or "Este aparelho",
        "created_at": now_iso(),
    })
    await db.members.update_one({"id": user["id"]}, {"$unset": {"webauthn_challenge": ""}})
    return {"ok": True}


@api_router.get("/webauthn/credentials")
async def webauthn_list_credentials(user=Depends(get_current_user)):
    return await db.webauthn_credentials.find({"member_id": user["id"]}, {"_id": 0, "public_key": 0}).to_list(20)


@api_router.delete("/webauthn/credentials/{cred_id}")
async def webauthn_delete_credential(cred_id: str, user=Depends(get_current_user)):
    await db.webauthn_credentials.delete_one({"id": cred_id, "member_id": user["id"]})
    return {"ok": True}


@api_router.post("/webauthn/login/options")
async def webauthn_login_options(user=Depends(get_current_user)):
    creds = await db.webauthn_credentials.find({"member_id": user["id"]}, {"_id": 0}).to_list(20)
    if not creds:
        raise HTTPException(status_code=404, detail="Nenhuma biometria cadastrada neste aparelho")
    allow = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credential_id"])) for c in creds]
    options = webauthn.generate_authentication_options(
        rp_id=WEBAUTHN_RP_ID, allow_credentials=allow, user_verification=UserVerificationRequirement.REQUIRED,
    )
    await db.members.update_one({"id": user["id"]}, {"$set": {"webauthn_challenge": bytes_to_base64url(options.challenge)}})
    return json.loads(options_to_json(options))


@api_router.post("/webauthn/login/verify")
async def webauthn_login_verify(data: WebAuthnLoginVerifyIn, user=Depends(get_current_user)):
    member = await db.members.find_one({"id": user["id"]})
    challenge_b64 = member.get("webauthn_challenge") if member else None
    if not challenge_b64:
        raise HTTPException(status_code=400, detail="Nenhuma verificação de biometria em andamento.")
    cred_id_b64 = data.credential.get("id")
    stored = await db.webauthn_credentials.find_one({"member_id": user["id"], "credential_id": cred_id_b64})
    if not stored:
        raise HTTPException(status_code=400, detail="Biometria não reconhecida para este usuário.")
    try:
        cred = parse_authentication_credential_json(json.dumps(data.credential))
        verification = webauthn.verify_authentication_response(
            credential=cred,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=WEBAUTHN_RP_ID,
            expected_origin=WEBAUTHN_ORIGIN,
            credential_public_key=base64url_to_bytes(stored["public_key"]),
            credential_current_sign_count=stored.get("sign_count", 0),
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Biometria não confirmada: {e}")
    await db.webauthn_credentials.update_one({"id": stored["id"]}, {"$set": {"sign_count": verification.new_sign_count}})
    await db.members.update_one({"id": user["id"]}, {"$unset": {"webauthn_challenge": ""}})
    return {"ok": True}


# ============================================================
#  Chamadas (v2.0) — voz/vídeo com WebRTC (sinalização via WebSocket)
# ============================================================
# O servidor NUNCA processa áudio/vídeo — apenas ajuda os participantes a
# trocarem as informações necessárias (SDP/ICE) para se conectarem
# diretamente entre si. Isso mantém o uso de recursos do Render mínimo,
# mesmo em chamadas longas.

# Servidores STUN/TURN gratuitos usados para atravessar NAT/firewall.
# STUN público do Google (sem custo, sem limite prático de uso).
# TURN: usa o serviço gratuito do Open Relay Project (cota generosa, sem
# cartão de crédito) como retaguarda para redes mais restritas. Se preferir
# outro provedor no futuro, basta trocar aqui — nada mais no código muda.
ICE_SERVERS = [
    {"urls": ["stun:stun.l.google.com:19302", "stun:global.stun.twilio.com:3478"]},
    {
        "urls": ["turn:openrelay.metered.ca:80", "turn:openrelay.metered.ca:443"],
        "username": "openrelayproject",
        "credential": "openrelayproject",
    },
]


@api_router.get("/members/admins")
async def list_admins(user=Depends(get_current_user)):
    """Lista mínima de administradores — usada pelo membro para saber para
    quem ligar ao chamar 'a administração' (Chamadas — v2.0)."""
    admins = await db.members.find({"is_admin": True}, {"_id": 0, "id": 1, "name": 1, "photo": 1}).to_list(20)
    return admins


@api_router.get("/calls/ice-servers")
async def get_ice_servers(user=Depends(get_current_user)):
    return {"iceServers": ICE_SERVERS}


@api_router.post("/calls")
async def start_call(data: CallStartIn, user=Depends(get_current_user)):
    role = user_role(user)
    if role == "visitor":
        raise HTTPException(status_code=403, detail="Visitantes não têm acesso a chamadas")
    if data.mode == "direct":
        if not data.target_member_id:
            raise HTTPException(status_code=400, detail="Informe o membro para chamar")
        target = await db.members.find_one({"id": data.target_member_id}, {"_id": 0})
        if not target:
            raise HTTPException(status_code=404, detail="Membro não encontrado")
        participants_planned = [user["id"], data.target_member_id]
    else:
        participants_planned = [user["id"]]

    call = {
        "id": str(uuid.uuid4()),
        "call_type": data.call_type if data.call_type in ("audio", "video") else "audio",
        "mode": data.mode if data.mode in ("direct", "group") else "direct",
        "title": (data.title or "").strip(),
        "created_by": user["id"],
        "created_by_name": user.get("name", ""),
        "participants_planned": participants_planned,
        "participants_joined": [],
        "status": "ringing",
        "created_at": now_iso(),
        "ended_at": None,
    }
    await db.calls.insert_one(call)
    call.pop("_id", None)

    if data.mode == "direct":
        await presence_manager.notify(data.target_member_id, {
            "event": "incoming_call", "call": call,
        })
    return call


@api_router.post("/calls/{call_id}/invite")
async def invite_to_call(call_id: str, data: CallInviteIn, user=Depends(get_current_user)):
    call = await db.calls.find_one({"id": call_id})
    if not call:
        raise HTTPException(status_code=404, detail="Chamada não encontrada")
    await db.calls.update_one({"id": call_id}, {"$addToSet": {"participants_planned": data.member_id}})
    call["participants_planned"] = list(set(call.get("participants_planned", []) + [data.member_id]))
    call.pop("_id", None)
    await presence_manager.notify(data.member_id, {"event": "incoming_call", "call": call})
    return {"ok": True}


@api_router.post("/calls/{call_id}/join")
async def join_call(call_id: str, user=Depends(get_current_user)):
    result = await db.calls.update_one(
        {"id": call_id},
        {"$addToSet": {"participants_joined": user["id"]}, "$set": {"status": "active"}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Chamada não encontrada")
    return {"ok": True}


@api_router.post("/calls/{call_id}/leave")
async def leave_call(call_id: str, user=Depends(get_current_user)):
    call = await db.calls.find_one({"id": call_id})
    if not call:
        raise HTTPException(status_code=404, detail="Chamada não encontrada")
    joined = [p for p in call.get("participants_joined", []) if p != user["id"]]
    patch = {"participants_joined": joined}
    if not joined:
        patch["status"] = "ended"
        patch["ended_at"] = now_iso()
    await db.calls.update_one({"id": call_id}, {"$set": patch})
    call_signal_manager.leave(call_id, user["id"])
    return {"ok": True}


@api_router.get("/calls/{call_id}")
async def get_call(call_id: str, user=Depends(get_current_user)):
    call = await db.calls.find_one({"id": call_id}, {"_id": 0})
    if not call:
        raise HTTPException(status_code=404, detail="Chamada não encontrada")
    return call


@api_router.websocket("/ws/call/{room_id}")
async def ws_call_signal(websocket: WebSocket, room_id: str, token: str = Query(...)):
    """Canal de sinalização: retransmite SDP/ICE entre os participantes da
    sala. Nunca transporta áudio/vídeo (isso vai direto entre os navegadores)."""
    user = await get_user_from_ws_token(token)
    if not user:
        await websocket.close(code=4401)
        return
    if user_role(user) == "visitor":
        await websocket.close(code=4403)
        return
    await websocket.accept()
    await call_signal_manager.join(room_id, user["id"], websocket)
    try:
        while True:
            payload = await websocket.receive_json()
            await call_signal_manager.relay(room_id, user["id"], payload)
    except WebSocketDisconnect:
        pass
    finally:
        call_signal_manager.leave(room_id, user["id"])


@api_router.websocket("/ws/presence")
async def ws_presence(websocket: WebSocket, token: str = Query(...)):
    """Conexão de presença: mantida aberta enquanto o membro está no app,
    usada para avisar sobre chamadas recebidas em tempo real — v2.0."""
    user = await get_user_from_ws_token(token)
    if not user:
        await websocket.close(code=4401)
        return
    await websocket.accept()
    await presence_manager.join(user["id"], websocket)
    try:
        while True:
            await websocket.receive_text()  # canal só de notificação; ignora entrada
    except WebSocketDisconnect:
        pass
    finally:
        presence_manager.leave(user["id"], websocket)


# ============================================================
#  Feed & Stories (v2.x)
# ============================================================
# Feed: permanente (só apaga por ação do autor/admin). Stories: some sozinho
# em 24h (índice TTL criado no startup — ver seed_defaults).

def _feed_visible_query(role: str) -> dict:
    return {"$or": [{"audience": {"$in": visible_to(role)}}, {"audience": {"$exists": False}}]}


@api_router.get("/feed")
async def list_feed(user=Depends(get_current_user), limit: int = 20, before: Optional[str] = None):
    role = user_role(user)
    q = _feed_visible_query(role)
    if before:
        q = {"$and": [q, {"created_at": {"$lt": before}}]}
    limit = min(max(limit, 1), 50)
    posts = await db.feed_posts.find(q, {"_id": 0}).sort("created_at", -1).to_list(limit)
    for p in posts:
        p["like_count"] = len(p.get("likes", []))
        p["liked_by_me"] = user["id"] in p.get("likes", [])
        p["comment_count"] = await db.feed_comments.count_documents({"post_id": p["id"]})
        p.pop("likes", None)
    return posts


@api_router.get("/public/feed")
async def public_feed(limit: int = 20):
    q = _feed_visible_query("visitor")
    limit = min(max(limit, 1), 50)
    posts = await db.feed_posts.find(q, {"_id": 0}).sort("created_at", -1).to_list(limit)
    for p in posts:
        p["like_count"] = len(p.get("likes", []))
        p["comment_count"] = await db.feed_comments.count_documents({"post_id": p["id"]})
        p.pop("likes", None)
    return posts


@api_router.post("/feed")
async def create_feed_post(data: FeedPostIn, user=Depends(get_current_user)):
    if user_role(user) == "visitor":
        raise HTTPException(status_code=403, detail="Visitantes não publicam no Feed")
    audience = data.audience if data.audience in AUDIENCE_VALUES else "all"
    doc = {
        "id": str(uuid.uuid4()),
        "author_id": user["id"],
        "author_name": user.get("name", ""),
        "author_photo": user.get("photo"),
        "media_type": data.media_type,
        "media": data.media or "",
        "media_transform": data.media_transform or {},
        "caption": (data.caption or "").strip(),
        "elements": [e.dict() for e in data.elements],
        "music_track": data.music_track,
        "audience": audience,
        "likes": [],
        "created_at": now_iso(),
    }
    await db.feed_posts.insert_one(dict(doc))
    doc.pop("_id", None)
    await log_action(user, f"Publicou no Feed", f"post {doc['id']}")
    return doc


@api_router.put("/feed/{post_id}")
async def update_feed_post(post_id: str, data: FeedPostIn, user=Depends(get_current_user)):
    post = await db.feed_posts.find_one({"id": post_id})
    if not post:
        raise HTTPException(status_code=404, detail="Publicação não encontrada")
    if post["author_id"] != user["id"] and not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Sem permissão para editar esta publicação")
    audience = data.audience if data.audience in AUDIENCE_VALUES else "all"
    patch = {
        "media_type": data.media_type, "media": data.media or "", "media_transform": data.media_transform or {},
        "caption": (data.caption or "").strip(), "elements": [e.dict() for e in data.elements],
        "music_track": data.music_track, "audience": audience,
    }
    await db.feed_posts.update_one({"id": post_id}, {"$set": patch})
    return await db.feed_posts.find_one({"id": post_id}, {"_id": 0})


@api_router.delete("/feed/{post_id}")
async def delete_feed_post(post_id: str, user=Depends(get_current_user)):
    post = await db.feed_posts.find_one({"id": post_id})
    if not post:
        raise HTTPException(status_code=404, detail="Publicação não encontrada")
    if post["author_id"] != user["id"] and not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Sem permissão para excluir esta publicação")
    await db.feed_posts.delete_one({"id": post_id})
    await db.feed_comments.delete_many({"post_id": post_id})
    if user.get("is_admin") and post["author_id"] != user["id"]:
        await log_action(user, "Removeu publicação do Feed de outro autor", f"post {post_id}")
    return {"ok": True}


@api_router.post("/feed/{post_id}/like")
async def toggle_like(post_id: str, user=Depends(get_current_user)):
    post = await db.feed_posts.find_one({"id": post_id})
    if not post:
        raise HTTPException(status_code=404, detail="Publicação não encontrada")
    likes = post.get("likes", [])
    if user["id"] in likes:
        await db.feed_posts.update_one({"id": post_id}, {"$pull": {"likes": user["id"]}})
        return {"liked": False}
    await db.feed_posts.update_one({"id": post_id}, {"$addToSet": {"likes": user["id"]}})
    return {"liked": True}


@api_router.get("/feed/{post_id}/comments")
async def list_comments(post_id: str, user=Depends(get_current_user)):
    return await db.feed_comments.find({"post_id": post_id}, {"_id": 0}).sort("created_at", 1).to_list(500)


@api_router.post("/feed/{post_id}/comments")
async def add_comment(post_id: str, data: CommentIn, user=Depends(get_current_user)):
    if not await db.feed_posts.find_one({"id": post_id}):
        raise HTTPException(status_code=404, detail="Publicação não encontrada")
    comment = {
        "id": str(uuid.uuid4()), "post_id": post_id, "author_id": user["id"],
        "author_name": user.get("name", ""), "body": data.body.strip(), "created_at": now_iso(),
    }
    await db.feed_comments.insert_one(dict(comment))
    comment.pop("_id", None)
    return comment


@api_router.delete("/feed/comments/{comment_id}")
async def delete_comment(comment_id: str, user=Depends(get_current_user)):
    comment = await db.feed_comments.find_one({"id": comment_id})
    if not comment:
        raise HTTPException(status_code=404, detail="Comentário não encontrado")
    if comment["author_id"] != user["id"] and not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Sem permissão para excluir este comentário")
    await db.feed_comments.delete_one({"id": comment_id})
    return {"ok": True}


# ------------------------ Stories (expiram em 24h) ------------------------

@api_router.get("/stories")
async def list_stories(user=Depends(get_current_user)):
    role = user_role(user)
    q = {"$or": [{"audience": {"$in": visible_to(role)}}, {"audience": {"$exists": False}}]}
    items = await db.stories.find(q, {"_id": 0}).sort("created_at", -1).to_list(200)
    return items


@api_router.get("/public/stories")
async def public_stories():
    q = {"$or": [{"audience": {"$in": visible_to('visitor')}}, {"audience": {"$exists": False}}]}
    return await db.stories.find(q, {"_id": 0}).sort("created_at", -1).to_list(200)


@api_router.post("/stories")
async def create_story(data: StoryIn, user=Depends(get_current_user)):
    if user_role(user) == "visitor":
        raise HTTPException(status_code=403, detail="Visitantes não publicam Stories")
    doc = {
        "id": str(uuid.uuid4()),
        "author_id": user["id"],
        "author_name": user.get("name", ""),
        "author_photo": user.get("photo"),
        "media_type": data.media_type,
        "media": data.media,
        "media_transform": data.media_transform or {},
        "elements": [e.dict() for e in data.elements],
        "music_track": data.music_track,
        "audience": "all",
        "views": [],
        "created_at": now_iso(),
        "expires_at": datetime.now(timezone.utc),  # TTL — some sozinho em 24h
    }
    await db.stories.insert_one(dict(doc))
    doc.pop("_id", None)
    return doc


@api_router.post("/stories/{story_id}/view")
async def view_story(story_id: str, user=Depends(get_current_user)):
    await db.stories.update_one({"id": story_id}, {"$addToSet": {"views": user["id"]}})
    return {"ok": True}


@api_router.delete("/stories/{story_id}")
async def delete_story(story_id: str, user=Depends(get_current_user)):
    story = await db.stories.find_one({"id": story_id})
    if not story:
        raise HTTPException(status_code=404, detail="Story não encontrado")
    if story["author_id"] != user["id"] and not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Sem permissão para excluir este Story")
    await db.stories.delete_one({"id": story_id})
    return {"ok": True}


# ------------------------ Música (preparação para integração futura) ------------------------
# Sem catálogo próprio, sem armazenar música nenhuma. Só guarda se o membro já
# conectou a conta (via OAuth, quando essa etapa for implementada) e o
# provedor escolhido — a associação da faixa em si acontece no app do
# provedor, respeitando os limites da API dele.

@api_router.get("/music/status")
async def music_status(user=Depends(get_current_user)):
    conn = await db.music_connections.find_one({"member_id": user["id"]}, {"_id": 0})
    return conn or {"member_id": user["id"], "connected": False, "provider": None}


@api_router.post("/music/connect-placeholder")
async def music_connect_placeholder(data: MusicConnectIn, user=Depends(get_current_user)):
    """Reserva a estrutura para quando a integração OAuth real existir —
    ainda não conecta a nenhum serviço de música de verdade."""
    await db.music_connections.update_one(
        {"member_id": user["id"]},
        {"$set": {"member_id": user["id"], "provider": data.provider, "connected": False, "requested_at": now_iso()}},
        upsert=True,
    )
    return {"ok": True, "detail": "Integração ainda não disponível — estrutura reservada para quando a API do provedor for habilitada."}


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
