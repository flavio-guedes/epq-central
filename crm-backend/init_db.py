#!/usr/bin/env python3
from sqlalchemy.orm import Session
from database import SessionLocal, Base, engine
from models import User, UserProfile
from auth import hash_password

Base.metadata.create_all(bind=engine)

db: Session = SessionLocal()
try:
    if db.query(User).count() == 0:
        admin = User(
            nome="Flávio",
            email="flavio@epq.local",
            hashed_password=hash_password("EPQ@Admin#2026!"),
            perfil=UserProfile.ADMIN_MASTER,
            status="ativo",
            must_change_password=True,
        )
        ronan = User(
            nome="Ronan",
            email="ronan@epq.local",
            hashed_password=hash_password("EPQ@Ronan#2026!"),
            perfil=UserProfile.ADMIN_MASTER,
            status="ativo",
            must_change_password=True,
        )
        clara = User(
            nome="Clara",
            email="clara@epq.local",
            hashed_password=hash_password("EPQ@Clara#2026!"),
            perfil=UserProfile.OPERACIONAL,
            status="ativo",
            must_change_password=True,
        )
        db.add_all([admin, ronan, clara])
        db.commit()
        print("INIT_OK users=3")
    else:
        print("INIT_SKIPPED users=" + str(db.query(User).count()))
finally:
    db.close()
