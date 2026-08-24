"""
Pós-deploy Render: inicializa usuários padrão no banco de dados.
Sem senhas hardcoded no repositório: usa variáveis de ambiente quando disponíveis.
"""
import os
from pathlib import Path

try:
    from database import SessionLocal, Base, engine
    from models import User, UserProfile
    from auth import hash_password

    Base.metadata.create_all(bind=engine)

    DEFAULT_USERS = [
        {"nome": "Flávio", "email": "flavio@epq.local", "senha": os.getenv("FIRST_SUPERUSER_PASSWORD", ""), "perfil": UserProfile.ADMIN_MASTER},
        {"nome": "Ronan", "email": "ronan@epq.local", "senha": os.getenv("FIRST_SUPERUSER_PASSWORD_RONAN", ""), "perfil": UserProfile.ADMIN_MASTER},
        {"nome": "Clara", "email": "clara@epq.local", "senha": os.getenv("FIRST_SUPERUSER_PASSWORD_CLARA", ""), "perfil": UserProfile.OPERACIONAL},
    ]

    db = SessionLocal()
    try:
        for u in DEFAULT_USERS:
            if not u["senha"]:
                continue
            if db.query(User).filter(User.email == u["email"]).first():
                continue
            db.add(User(
                nome=u["nome"],
                email=u["email"],
                hashed_password=hash_password(u["senha"]),
                perfil=u["perfil"],
                status="ativo",
                must_change_password=True,
            ))
        db.commit()
        print("Render init: default users ensured")
    finally:
        db.close()
except Exception as e:
    print(f"Render init warning: {e}")
