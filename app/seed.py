from .database import Base, engine, SessionLocal
from .models import User
from .security import hash_password

SEED_USERS = [
    ("admin@sealtrail.test", "Admin#Demo2026", "admin"),
    ("owner@sealtrail.test", "Owner#Demo2026", "owner"),
    ("viewer@sealtrail.test", "Viewer#Demo2026", "viewer"),
]

def run():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    for email, password, role in SEED_USERS:
        if not db.query(User).filter(User.email == email).first():
            db.add(User(email=email, password_hash=hash_password(password), role=role))
    db.commit()
    db.close()
    print("Seeded users.")

if __name__ == "__main__":
    run()