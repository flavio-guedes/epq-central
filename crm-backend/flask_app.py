from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import or_
import os
import re
import hashlib
import secrets
import jwt
from database import SessionLocal, Base, engine
from models import User, Lead, Interaction, AuditLog, UserProfile, LeadStatus, InteractionType
from auth import hash_password, verify_password

Base.metadata.create_all(bind=engine)
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'super-secret-key')

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_user_from_token(db: Session):
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    token = auth.split(' ', 1)[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception:
        return None
    return db.query(User).filter(User.id == payload.get('sub')).first()

def require_auth(db: Session):
    user = get_user_from_token(db)
    if not user or user.status != 'ativo':
        return None
    user.last_login = datetime.utcnow()
    db.commit()
    return user

def require_profile(user: User, allowed):
    if user.perfil not in [p.value if hasattr(p, 'value') else p for p in allowed]:
        return False
    return True

def log_audit(db: Session, user_id, acao, lead_id=None, campo=None, valor_anterior=None, valor_novo=None):
    db.add(AuditLog(user_id=user_id, lead_id=lead_id, acao=acao, campo=campo, valor_anterior=valor_anterior, valor_novo=valor_novo, created_at=datetime.utcnow()))
    db.commit()

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json(force=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')
    db = next(get_db())
    try:
        user = db.query(User).filter(User.email == username).first()
        if not user or not verify_password(password, user.hashed_password):
            return jsonify({'detail': 'Credenciais inválidas'}), 401
        token = jwt.encode({'sub': user.id, 'perfil': user.perfil.value}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({
            'access_token': token,
            'token_type': 'bearer',
            'user_id': user.id,
            'nome': user.nome,
            'perfil': user.perfil.value,
            'must_change_password': bool(user.must_change_password),
        })
    finally:
        db.close()

@app.route('/auth/change-password', methods=['POST'])
def change_password():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'detail': 'Token ausente'}), 401
    db = next(get_db())
    try:
        user = get_user_from_token(db)
        if not user:
            return jsonify({'detail': 'Token inválido'}), 401
        data = request.get_json(force=True) or {}
        if not verify_password(data.get('current_password', ''), user.hashed_password):
            return jsonify({'detail': 'Senha atual incorreta'}), 400
        if data.get('new_password') == data.get('current_password'):
            return jsonify({'detail': 'Nova senha igual à atual'}), 400
        user.hashed_password = hash_password(data.get('new_password', ''))
        user.must_change_password = False
        db.commit()
        log_audit(db, user.id, 'Alterou senha')
        return jsonify({'status': 'ok'})
    finally:
        db.close()

@app.route('/users/me', methods=['GET'])
def me():
    db = next(get_db())
    try:
        user = require_auth(db)
        if not user:
            return jsonify({'detail': 'Token ausente'}), 401
        return jsonify({
            'id': user.id,
            'nome': user.nome,
            'email': user.email,
            'perfil': user.perfil.value,
            'status': user.status,
            'must_change_password': bool(user.must_change_password),
            'last_login': user.last_login.isoformat() if user.last_login else None,
            'created_at': user.created_at.isoformat() if user.created_at else None,
        })
    finally:
        db.close()

@app.route('/users', methods=['GET'])
def list_users():
    db = next(get_db())
    try:
        requester = require_auth(db)
        if not requester or requester.perfil != UserProfile.ADMIN_MASTER.value:
            return jsonify({'detail': 'Sem permissão'}), 403
        users = db.query(User).all()
        return jsonify([
            {
                'id': u.id,
                'nome': u.nome,
                'email': u.email,
                'perfil': u.perfil.value,
                'status': u.status,
                'must_change_password': bool(u.must_change_password),
                'last_login': u.last_login.isoformat() if u.last_login else None,
                'created_at': u.created_at.isoformat() if u.created_at else None,
            }
            for u in users
        ])
    finally:
        db.close()

@app.route('/users', methods=['POST'])
def create_user():
    db = next(get_db())
    try:
        requester = require_auth(db)
        if not requester or requester.perfil != UserProfile.ADMIN_MASTER.value:
            return jsonify({'detail': 'Sem permissão'}), 403
        data = request.get_json(force=True) or {}
        email = data.get('email')
        if not email or db.query(User).filter(User.email == email).first():
            return jsonify({'detail': 'E-mail já cadastrado'}), 400
        user = User(
            nome=data.get('nome', ''),
            email=email,
            hashed_password=hash_password('mudar123'),
            perfil=UserProfile(data.get('perfil', 'OPERACIONAL')),
            status=data.get('status', 'ativo'),
            must_change_password=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        log_audit(db, requester.id, 'Criou usuário', campo='perfil', valor_anterior=None, valor_novo=user.perfil.value)
        return jsonify({
            'id': user.id,
            'nome': user.nome,
            'email': user.email,
            'perfil': user.perfil.value,
            'status': user.status,
            'must_change_password': bool(user.must_change_password),
            'last_login': None,
            'created_at': user.created_at.isoformat() if user.created_at else None,
        }), 201
    finally:
        db.close()

@app.route('/leads', methods=['POST'])
def create_lead():
    db = next(get_db())
    try:
        requester = require_auth(db)
        if not requester:
            return jsonify({'detail': 'Token ausente'}), 401
        data = request.get_json(force=True) or {}
        lead = Lead(
            nome=data.get('nome', ''),
            telefone=data.get('telefone'),
            email=data.get('email'),
            whatsapp=data.get('whatsapp'),
            empresa=data.get('empresa'),
            origem=data.get('origem'),
            produto=data.get('produto'),
            etapa=data.get('etapa'),
            temperatura=data.get('temperatura'),
            proximo_followup=datetime.fromisoformat(data['proximo_followup']) if data.get('proximo_followup') else None,
            proximo_tipo=data.get('proximo_tipo'),
            proximo_nota=data.get('proximo_nota'),
            responsavel_id=data.get('responsavel_id') or requester.id,
            status=data.get('status', 'ativo'),
            created_by=requester.id,
            updated_by=requester.id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(lead)
        db.commit()
        db.refresh(lead)
        log_audit(db, requester.id, 'Criou lead', lead_id=lead.id, campo='nome', valor_novo=lead.nome)
        return jsonify({
            'id': lead.id,
            'nome': lead.nome,
            'telefone': lead.telefone,
            'email': lead.email,
            'whatsapp': lead.whatsapp,
            'empresa': lead.empresa,
            'origem': lead.origem,
            'produto': lead.produto,
            'etapa': lead.etapa,
            'temperatura': lead.temperatura,
            'proximo_followup': lead.proximo_followup.isoformat() if lead.proximo_followup else None,
            'proximo_tipo': lead.proximo_tipo,
            'proximo_nota': lead.proximo_nota,
            'responsavel_id': lead.responsavel_id,
            'status': lead.status,
            'created_at': lead.created_at.isoformat() if lead.created_at else None,
            'updated_at': lead.updated_at.isoformat() if lead.updated_at else None,
            'created_by': lead.created_by,
            'updated_by': lead.updated_by,
        }), 201
    finally:
        db.close()

@app.route('/leads', methods=['GET'])
def list_leads():
    db = next(get_db())
    try:
        requester = require_auth(db)
        if not requester:
            return jsonify({'detail': 'Token ausente'}), 401
        query = db.query(Lead)
        if requester.perfil == UserProfile.OPERACIONAL.value:
            query = query.filter(Lead.responsavel_id == requester.id)
        leads = query.all()
        return jsonify([
            {
                'id': l.id,
                'nome': l.nome,
                'telefone': l.telefone,
                'email': l.email,
                'whatsapp': l.whatsapp,
                'empresa': l.empresa,
                'origem': l.origem,
                'produto': l.produto,
                'etapa': l.etapa,
                'temperatura': l.temperatura,
                'proximo_followup': l.proximo_followup.isoformat() if l.proximo_followup else None,
                'proximo_tipo': l.proximo_tipo,
                'proximo_nota': l.proximo_nota,
                'responsavel_id': l.responsavel_id,
                'status': l.status,
                'created_at': l.created_at.isoformat() if l.created_at else None,
                'updated_at': l.updated_at.isoformat() if l.updated_at else None,
                'created_by': l.created_by,
                'updated_by': l.updated_by,
            }
            for l in leads
        ])
    finally:
        db.close()

@app.route('/leads/<lead_id>', methods=['GET'])
def get_lead(lead_id):
    db = next(get_db())
    try:
        requester = require_auth(db)
        if not requester:
            return jsonify({'detail': 'Token ausente'}), 401
        lead = db.query(Lead).filter(Lead.id == lead_id).first()
        if not lead:
            return jsonify({'detail': 'Lead não encontrado'}), 404
        if requester.perfil == UserProfile.OPERACIONAL.value and lead.responsavel_id != requester.id:
            return jsonify({'detail': 'Sem permissão'}), 403
        return jsonify({
            'id': lead.id,
            'nome': lead.nome,
            'telefone': lead.telefone,
            'email': lead.email,
            'whatsapp': lead.whatsapp,
            'empresa': lead.empresa,
            'origem': lead.origem,
            'produto': lead.produto,
            'etapa': lead.etapa,
            'temperatura': lead.temperatura,
            'proximo_followup': lead.proximo_followup.isoformat() if lead.proximo_followup else None,
            'proximo_tipo': lead.proximo_tipo,
            'proximo_nota': lead.proximo_nota,
            'responsavel_id': lead.responsavel_id,
            'status': lead.status,
            'created_at': lead.created_at.isoformat() if lead.created_at else None,
            'updated_at': lead.updated_at.isoformat() if lead.updated_at else None,
            'created_by': lead.created_by,
            'updated_by': lead.updated_by,
        })
    finally:
        db.close()

@app.route('/leads/<lead_id>', methods=['PUT'])
def update_lead(lead_id):
    db = next(get_db())
    try:
        requester = require_auth(db)
        if not requester:
            return jsonify({'detail': 'Token ausente'}), 401
        lead = db.query(Lead).filter(Lead.id == lead_id).first()
        if not lead:
            return jsonify({'detail': 'Lead não encontrado'}), 404
        if requester.perfil == UserProfile.OPERACIONAL.value and lead.responsavel_id != requester.id:
            return jsonify({'detail': 'Sem permissão'}), 403
        data = request.get_json(force=True) or {}
        previous = {
            'nome': lead.nome,
            'telefone': lead.telefone,
            'email': lead.email,
            'whatsapp': lead.whatsapp,
            'empresa': lead.empresa,
            'origem': lead.origem,
            'produto': lead.produto,
            'etapa': lead.etapa,
            'temperatura': lead.temperatura,
            'proximo_followup': lead.proximo_followup.isoformat() if lead.proximo_followup else None,
            'proximo_tipo': lead.proximo_tipo,
            'proximo_nota': lead.proximo_nota,
            'responsavel_id': lead.responsavel_id,
            'status': lead.status,
        }
        for field in ['nome', 'telefone', 'email', 'whatsapp', 'empresa', 'origem', 'produto', 'etapa', 'temperatura', 'proximo_tipo', 'proximo_nota', 'responsavel_id', 'status']:
            if field in data:
                setattr(lead, field, data.get(field))
        if 'proximo_followup' in data and data.get('proximo_followup'):
            lead.proximo_followup = datetime.fromisoformat(data['proximo_followup'])
        lead.updated_by = requester.id
        lead.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(lead)
        for field in previous.keys():
            old = previous.get(field)
            new = getattr(lead, field)
            if isinstance(new, datetime):
                new = new.isoformat() if new else None
            if old != new:
                log_audit(db, requester.id, 'Alterou lead', lead_id=lead.id, campo=field, valor_anterior=str(old), valor_novo=str(new))
        return jsonify({
            'id': lead.id,
            'nome': lead.nome,
            'telefone': lead.telefone,
            'email': lead.email,
            'whatsapp': lead.whatsapp,
            'empresa': lead.empresa,
            'origem': lead.origem,
            'produto': lead.produto,
            'etapa': lead.etapa,
            'temperatura': lead.temperatura,
            'proximo_followup': lead.proximo_followup.isoformat() if lead.proximo_followup else None,
            'proximo_tipo': lead.proximo_tipo,
            'proximo_nota': lead.proximo_nota,
            'responsavel_id': lead.responsavel_id,
            'status': lead.status,
            'created_at': lead.created_at.isoformat() if lead.created_at else None,
            'updated_at': lead.updated_at.isoformat() if lead.updated_at else None,
            'created_by': lead.created_by,
            'updated_by': lead.updated_by,
        })
    finally:
        db.close()

@app.route('/interactions', methods=['POST'])
def create_interaction():
    db = next(get_db())
    try:
        requester = require_auth(db)
        if not requester:
            return jsonify({'detail': 'Token ausente'}), 401
        data = request.get_json(force=True) or {}
        interaction = Interaction(lead_id=data.get('lead_id'), user_id=requester.id, tipo=InteractionType(data.get('tipo')), descricao=data.get('descricao'), created_at=datetime.utcnow())
        db.add(interaction)
        lead = db.query(Lead).filter(Lead.id == data.get('lead_id')).first()
        if lead:
            lead.updated_by = requester.id
        db.commit()
        db.refresh(interaction)
        log_audit(db, requester.id, 'Registrou interação', lead_id=data.get('lead_id'), campo='tipo', valor_novo=data.get('tipo'))
        return jsonify({
            'id': interaction.id,
            'lead_id': interaction.lead_id,
            'user_id': interaction.user_id,
            'tipo': interaction.tipo.value,
            'descricao': interaction.descricao,
            'created_at': interaction.created_at.isoformat() if interaction.created_at else None,
        }), 201
    finally:
        db.close()

@app.route('/interactions/<lead_id>', methods=['GET'])
def list_interactions(lead_id):
    db = next(get_db())
    try:
        require_auth(db)
        interactions = db.query(Interaction).filter(Interaction.lead_id == lead_id).order_by(Interaction.created_at.desc()).all()
        return jsonify([
            {
                'id': i.id,
                'lead_id': i.lead_id,
                'user_id': i.user_id,
                'tipo': i.tipo.value,
                'descricao': i.descricao,
                'created_at': i.created_at.isoformat() if i.created_at else None,
            }
            for i in interactions
        ])
    finally:
        db.close()

@app.route('/audit', methods=['GET'])
def list_audit():
    db = next(get_db())
    try:
        requester = require_auth(db)
        if not requester or requester.perfil != UserProfile.ADMIN_MASTER.value:
            return jsonify({'detail': 'Sem permissão'}), 403
        logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(200).all()
        return jsonify([
            {
                'id': log.id,
                'user_id': log.user_id,
                'lead_id': log.lead_id,
                'acao': log.acao,
                'campo': log.campo,
                'valor_anterior': log.valor_anterior,
                'valor_novo': log.valor_novo,
                'created_at': log.created_at.isoformat() if log.created_at else None,
            }
            for log in logs
        ])
    finally:
        db.close()

@app.route('/kpis', methods=['GET'])
def kpis():
    db = next(get_db())
    try:
        requester = require_auth(db)
        if not requester:
            return jsonify({'detail': 'Token ausente'}), 401
        query = db.query(Lead)
        if requester.perfil == UserProfile.OPERACIONAL.value:
            query = query.filter(Lead.responsavel_id == requester.id)
        leads = query.all()
        today_str = datetime.utcnow().date().isoformat()
        return jsonify({
            'total': len(leads),
            'novos': sum(1 for l in leads if l.etapa == 'Novo'),
            'hoje': sum(1 for l in leads if l.proximo_followup and l.proximo_followup.isoformat() == today_str and l.status == 'ativo'),
            'atrasados': sum(1 for l in leads if l.proximo_followup and l.proximo_followup.isoformat() < today_str and l.status == 'ativo'),
            'quentes': sum(1 for l in leads if l.temperatura == 'Quente'),
            'convertidos': sum(1 for l in leads if l.etapa == 'Matriculado'),
            'perdidos': sum(1 for l in leads if l.status == LeadStatus.PERDIDO.value),
            'arquivados': sum(1 for l in leads if l.status == LeadStatus.ARQUIVADO.value),
        })
    finally:
        db.close()

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
  try:
      from render_init import main as _render_init_main
      _render_init_main()
  except Exception:
      pass
  app.run(host='0.0.0.0', port=5000)
