from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel

from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base, Session

import bcrypt
from cryptography.fernet import Fernet

#Настройка базы данных
DATABASE_URL = 'sqlite:///./passwords.db'
engine = create_engine(DATABASE_URL, connect_args={'check_same_thread': False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

#Ключ шифрования 
SECRET_KEY = Fernet.generate_key()
cipher = Fernet(SECRET_KEY)

#Модель пользователя 
class UserDB(Base):
    __tablename__ = 'users'
    id = Column(Integer,primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    master_hash = Column(String) #хеш мастер-пароля

#Модель пароля
class PasswordDB(Base):
    __tablename__='passwords'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    service = Column(String) #например "gmail.com"
    login = Column(String) #логин на сервисе
    encrypted_password = Column(String) #зашифрованный пароль

Base.metadata.create_all(bind=engine)

#Pydantic-модели
class UserCreate(BaseModel):
    username: str
    master_password: str

class PasswordCreate(BaseModel):
    username: str
    master_password: str
    service: str
    login: str
    password: str

class PasswordOut(BaseModel):
    id: int
    service: str
    login: str
    password: str

#Подключение к базе
def get_db():
    db=SessionLocal()
    try:
        yield db
    finally:
        db.close()

app=FastAPI(title='Password Manager API')

@app.get('/')
def read_root():
    return {"message": "Password Manager API"}

#Регестрация пользователя
@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(UserDB).filter(UserDB.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Пользователь уже существует")

    hashed = bcrypt.hashpw(user.master_password.encode('utf-8'), bcrypt.gensalt())

    new_user = UserDB(
        username=user.username,
        master_hash=hashed.decode('utf-8')
    )
    db.add(new_user)
    db.commit()
    return {"message": f"Пользователь {user.username} зарегестрирован"}

#Добавить пароль
@app.post("/passwords")
def add_password(data: PasswordCreate, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.username == data.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if not bcrypt.checkpw(data.master_password.encode('utf-8'), user.master_hash.encode('utf-8')):
        raise HTTPException(status_code=401, detail="Неверный мастер-пароль")

    encrypted = cipher.encrypt(data.password.encode('utf-8')).decode('utf-8')

    new_password = PasswordDB(
        user_id=user.id,
        service=data.service,
        login=data.login,
        encrypted_password=encrypted
    )
    db.add(new_password)
    db.commit()
    return{"message": "Пароль сохранен"}

#Получить все пароли пользователя
@app.post("/passwords/list", response_model=list[PasswordOut])
def list_passwords(username: str, master_password: str, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    if not bcrypt.checkpw(master_password.encode('utf-8'), user.master_hash.encode('utf-8')):
        raise HTTPException(status_code=401, detail="Неверный мастер-пароль")

    passwords = db.query(PasswordDB).filter(PasswordDB.user_id == user.id).all()

    result = []
    for q in passwords:
        decrypted = cipher.decrypt(q.encrypted_password.encode('utf-8')).decode('utf-8')
        result.append(PasswordOut(
            id=q.id,
            service=q.service,
            login=q.login,
            password=decrypted
        ))
    return result
