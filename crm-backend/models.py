from sqlalchemy import Column, String, Date, DateTime, Boolean, Text, ForeignKey, Enum as SAEnum
from sqlalchemy.orm import relationship
from database import Base
import uuid
import enum
from datetime import datetime

class UserProfile(str, enum.Enum):
    ADMIN_MASTER = "ADMIN_MASTER"
    GESTOR = "GESTOR"
    OPERACIONAL = "OPERACIONAL"

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    nome = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    perfil = Column(SAEnum(UserProfile), nullable=False, default=UserProfile.OPERACIONAL)
    status = Column(String, nullable=False, default="ativo")
    must_change_password = Column(Boolean, default=True)
    last_login = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class LeadStatus(str, enum.Enum):
    ATIVO = "ativo"
    ARQUIVADO = "arquivado"
    PERDIDO = "perdido"

class Lead(Base):
    __tablename__ = "leads"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    nome = Column(String, nullable=False)
    telefone = Column(String, nullable=True)
    email = Column(String, nullable=True)
    whatsapp = Column(String, nullable=True)
    empresa = Column(String, nullable=True)
    origem = Column(String, nullable=True)
    produto = Column(String, nullable=True)
    etapa = Column(String, nullable=True)
    temperatura = Column(String, nullable=True)
    proximo_followup = Column(Date, nullable=True)
    proximo_tipo = Column(String, nullable=True)
    proximo_nota = Column(Text, nullable=True)
    responsavel_id = Column(String, ForeignKey("users.id"), nullable=True)
    status = Column(String, nullable=False, default="ativo")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String, ForeignKey("users.id"), nullable=True)
    updated_by = Column(String, ForeignKey("users.id"), nullable=True)

class InteractionType(str, enum.Enum):
    WHATSAPP = "WhatsApp"
    LIGACAO = "Ligação"
    FOLLOWUP = "Follow-up"
    EMAIL = "E-mail"
    NOTA = "Nota"

class Interaction(Base):
    __tablename__ = "interactions"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    lead_id = Column(String, ForeignKey("leads.id"), nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    tipo = Column(SAEnum(InteractionType), nullable=False)
    descricao = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    lead_id = Column(String, ForeignKey("leads.id"), nullable=True)
    acao = Column(String, nullable=False)
    campo = Column(String, nullable=True)
    valor_anterior = Column(Text, nullable=True)
    valor_novo = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
