from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user_id: str
    nome: str
    perfil: str
    must_change_password: bool

class UserCreate(BaseModel):
    nome: str
    email: str
    perfil: str
    status: str = "ativo"
    must_change_password: bool = True

class UserOut(BaseModel):
    id: str
    nome: str
    email: str
    perfil: str
    status: str
    must_change_password: bool
    last_login: Optional[datetime] = None
    created_at: Optional[datetime] = None

class LeadBase(BaseModel):
    nome: str
    telefone: Optional[str] = None
    email: Optional[str] = None
    whatsapp: Optional[str] = None
    empresa: Optional[str] = None
    origem: Optional[str] = None
    produto: Optional[str] = None
    etapa: Optional[str] = None
    temperatura: Optional[str] = None
    proximo_followup: Optional[datetime] = None
    proximo_tipo: Optional[str] = None
    proximo_nota: Optional[str] = None
    responsavel_id: Optional[str] = None
    status: str = "ativo"

class LeadCreate(LeadBase):
    pass

class LeadUpdate(LeadBase):
    pass

class LeadOut(LeadBase):
    id: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    created_by: Optional[str] = None
    updated_by: Optional[str] = None

class InteractionCreate(BaseModel):
    lead_id: str
    tipo: str
    descricao: Optional[str] = None

class InteractionOut(InteractionCreate):
    id: str
    user_id: Optional[str] = None
    created_at: Optional[datetime] = None

class AuditLogOut(BaseModel):
    id: str
    user_id: Optional[str] = None
    lead_id: Optional[str] = None
    acao: str
    campo: Optional[str] = None
    valor_anterior: Optional[str] = None
    valor_novo: Optional[str] = None
    created_at: Optional[datetime] = None

class ChangePassword(BaseModel):
    current_password: str
    new_password: str

class KPIOut(BaseModel):
    total: int
    novos: int
    hoje: int
    atrasados: int
    quentes: int
    convertidos: int
    perdidos: int
    arquivados: int
