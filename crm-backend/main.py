from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime, date
from typing import Optional, List
import os
from dotenv import load_dotenv

from database import Base, engine, get_db
from models import User, Lead, Interaction, AuditLog, UserProfile, LeadStatus, InteractionType
from schemas import (
    UserLogin, Token, UserCreate, UserOut, LeadCreate, LeadUpdate, LeadOut,
    InteractionCreate, InteractionOut, AuditLogOut, ChangePassword, KPIOut
)
from auth import verify_password, create_access_token, decode_token, hash_password

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key")
FIRST_SUPERUSER = os.getenv("FIRST_SUPERUSER", "flavio")

Base.metadata.create_all(bind=engine)

app = FastAPI(title="EPQ CRM")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_current_user(token: str, db: Session) -> User:
    if not token:
        raise HTTPException(status_code=401, detail="Token ausente")
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")
    user = db.query(User).filter(User.id == payload.get("sub")).first()
    if not user or user.status != "ativo":
        raise HTTPException(status_code=401, detail="Usuário inativo")
    user.last_login = datetime.utcnow()
    db.commit()
    return user

def require_profile(user: User, allowed: List[UserProfile]):
    if user.perfil not in [p.value for p in allowed]:
        raise HTTPException(status_code=403, detail="Sem permissão")

def log_audit(db: Session, user_id: Optional[str], acao: str, lead_id: Optional[str] = None, campo: Optional[str] = None, valor_anterior: Optional[str] = None, valor_novo: Optional[str] = None):
    db.add(AuditLog(
        user_id=user_id,
        lead_id=lead_id,
        acao=acao,
        campo=campo,
        valor_anterior=valor_anterior,
        valor_novo=valor_novo,
        created_at=datetime.utcnow(),
    ))
    db.commit()

@app.post("/auth/login", response_model=Token)
def login(payload: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    token = create_access_token({"sub": user.id, "perfil": user.perfil.value})
    return Token(access_token=token, token_type="bearer", user_id=user.id, nome=user.nome, perfil=user.perfil.value, must_change_password=bool(user.must_change_password))

@app.post("/auth/change-password")
def change_password(payload: ChangePassword, db: Session = Depends(get_db), authorization: Optional[str] = None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token ausente")
    user = get_current_user(authorization.split(" ",1)[1], db)
    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Senha atual incorreta")
    if payload.new_password == payload.current_password:
        raise HTTPException(status_code=400, detail="Nova senha igual à atual")
    user.hashed_password = hash_password(payload.new_password)
    user.must_change_password = False
    db.commit()
    log_audit(db, user.id, "Alterou senha")
    return {"status": "ok"}

@app.get("/users/me", response_model=UserOut)
def me(db: Session = Depends(get_db), authorization: Optional[str] = None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token ausente")
    user = get_current_user(authorization.split(" ",1)[1], db)
    return user

@app.post("/users", response_model=UserOut)
def create_user(payload: UserCreate, db: Session = Depends(get_db), authorization: Optional[str] = None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token ausente")
    requester = get_current_user(authorization.split(" ",1)[1], db)
    if requester.perfil != UserProfile.ADMIN_MASTER.value:
        raise HTTPException(status_code=403, detail="Sem permissão")
    exists = db.query(User).filter(User.email == payload.email).first()
    if exists:
        raise HTTPException(status_code=400, detail="E-mail já cadastrado")
    user = User(
        nome=payload.nome,
        email=payload.email,
        hashed_password=hash_password("mudar123"),
        perfil=UserProfile(payload.perfil),
        status=payload.status,
        must_change_password=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    log_audit(db, requester.id, "Criou usuário", campo="perfil", valor_anterior=None, valor_novo=user.perfil.value)
    return user

@app.get("/users", response_model=List[UserOut])
def list_users(db: Session = Depends(get_db), authorization: Optional[str] = None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token ausente")
    user = get_current_user(authorization.split(" ",1)[1], db)
    if user.perfil != UserProfile.ADMIN_MASTER.value:
        raise HTTPException(status_code=403, detail="Sem permissão")
    return db.query(User).all()

@app.post("/leads", response_model=LeadOut)
def create_lead(payload: LeadCreate, db: Session = Depends(get_db), authorization: Optional[str] = None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token ausente")
    requester = get_current_user(authorization.split(" ",1)[1], db)
    lead = Lead(
        **payload.dict(),
        created_by=requester.id,
        updated_by=requester.id,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(lead)
    db.commit()
    db.refresh(lead)
    log_audit(db, requester.id, "Criou lead", lead_id=lead.id, campo="nome", valor_novo=lead.nome)
    return lead

@app.get("/leads", response_model=List[LeadOut])
def list_leads(db: Session = Depends(get_db), authorization: Optional[str] = None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token ausente")
    requester = get_current_user(authorization.split(" ",1)[1], db)
    query = db.query(Lead)
    if requester.perfil == UserProfile.OPERACIONAL.value:
        query = query.filter(Lead.responsavel_id == requester.id)
    return query.all()

@app.get("/leads/{lead_id}", response_model=LeadOut)
def get_lead(lead_id: str, db: Session = Depends(get_db), authorization: Optional[str] = None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token ausente")
    requester = get_current_user(authorization.split(" ",1)[1], db)
    lead = db.query(Lead).filter(Lead.id == lead_id).first()
    if not lead:
        raise HTTPException(status_code=404, detail="Lead não encontrado")
    if requester.perfil == UserProfile.OPERACIONAL.value and lead.responsavel_id != requester.id:
        raise HTTPException(status_code=403, detail="Sem permissão")
    return lead

@app.put("/leads/{lead_id}", response_model=LeadOut)
def update_lead(lead_id: str, payload: LeadUpdate, db: Session = Depends(get_db), authorization: Optional[str] = None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token ausente")
    requester = get_current_user(authorization.split(" ",1)[1], db)
    lead = db.query(Lead).filter(Lead.id == lead_id).first()
    if not lead:
        raise HTTPException(status_code=404, detail="Lead não encontrado")
    if requester.perfil == UserProfile.OPERACIONAL.value and lead.responsavel_id != requester.id:
        raise HTTPException(status_code=403, detail="Sem permissão")
    previous = {c: getattr(lead, c) for c in payload.dict().keys() if hasattr(lead, c)}
    for k, v in payload.dict().items():
        if hasattr(lead, k):
            setattr(lead, k, v)
    lead.updated_by = requester.id
    lead.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(lead)
    for k, v in payload.dict().items():
        old = previous.get(k)
        if old != v:
            log_audit(db, requester.id, "Alterou lead", lead_id=lead.id, campo=k, valor_anterior=str(old), valor_novo=str(v))
    return lead

@app.post("/interactions", response_model=InteractionOut)
def create_interaction(payload: InteractionCreate, db: Session = Depends(get_db), authorization: Optional[str] = None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token ausente")
    requester = get_current_user(authorization.split(" ",1)[1], db)
    interaction = Interaction(
        lead_id=payload.lead_id,
        user_id=requester.id,
        tipo=InteractionType(payload.tipo),
        descricao=payload.descricao,
        created_at=datetime.utcnow(),
    )
    db.add(interaction)
    lead = db.query(Lead).filter(Lead.id == payload.lead_id).first()
    if lead:
        lead.last_contact = datetime.utcnow().date()
        lead.updated_by = requester.id
    db.commit()
    db.refresh(interaction)
    log_audit(db, requester.id, "Registrou interação", lead_id=payload.lead_id, campo="tipo", valor_novo=payload.tipo)
    return interaction

@app.get("/interactions/{lead_id}", response_model=List[InteractionOut])
def list_interactions(lead_id: str, db: Session = Depends(get_db), authorization: Optional[str] = None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token ausente")
    get_current_user(authorization.split(" ",1)[1], db)
    return db.query(Interaction).filter(Interaction.lead_id == lead_id).order_by(Interaction.created_at.desc()).all()

@app.get("/audit", response_model=List[AuditLogOut])
def list_audit(db: Session = Depends(get_db), authorization: Optional[str] = None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token ausente")
    requester = get_current_user(authorization.split(" ",1)[1], db)
    if requester.perfil != UserProfile.ADMIN_MASTER.value:
        raise HTTPException(status_code=403, detail="Sem permissão")
    return db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(200).all()

@app.get("/kpis", response_model=KPIOut)
def kpis(db: Session = Depends(get_db), authorization: Optional[str] = None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token ausente")
    requester = get_current_user(authorization.split(" ",1)[1], db)
    query = db.query(Lead)
    if requester.perfil == UserProfile.OPERACIONAL.value:
        query = query.filter(Lead.responsavel_id == requester.id)
    leads = query.all()
    today_str = date.today().isoformat()
    return KPIOut(
        total=len(leads),
        novos=sum(1 for l in leads if l.etapa == "Novo"),
        hoje=sum(1 for l in leads if l.proximo_followup and l.proximo_followup.isoformat() == today_str and l.status == "ativo"),
        atrasados=sum(1 for l in leads if l.proximo_followup and l.proximo_followup.isoformat() < today_str and l.status == "ativo"),
        quentes=sum(1 for l in leads if l.temperatura == "Quente"),
        convertidos=sum(1 for l in leads if l.etapa == "Matriculado"),
        perdidos=sum(1 for l in leads if l.status == LeadStatus.PERDIDO.value),
        arquivados=sum(1 for l in leads if l.status == LeadStatus.ARQUIVADO.value),
    )

@app.get("/health")
def health():
    return {"status": "ok"}
