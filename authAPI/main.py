import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from jose import JWTError, jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
import redis

DATABASE_URL = "postgresql://postgres:password@localhost/user_db"
SECRET_KEY = "secret_key"  
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


redis_client = redis.Redis(host='localhost', port=6379, db=0)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)

Base.metadata.create_all(bind=engine)


app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password):
    return pwd_context.hash(password)


def create_user(db: Session, email: str, password: str):
    db_user = User(email=email, hashed_password=get_password_hash(password))
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def get_user(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()


def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(SessionLocal)):
    user = get_user_by_email(db, form_data.username)
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Kullanıcı adı veya şifre yanlış", headers={"WWW-Authenticate": "Bearer"})
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/user/")
async def create_user_endpoint(email: str, password: str, db: Session = Depends(SessionLocal)):
    return create_user(db=db, email=email, password=password)


@app.put("/user/{user_id}")
async def update_user(user_id: int, email: str, db: Session = Depends(SessionLocal)):
    user = get_user(db, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
    user.email = email
    db.commit()
    db.refresh(user)
    return user


@app.get("/user/")
async def read_users(skip: int = 0, limit: int = 10, db: Session = Depends(SessionLocal)):
    users = db.query(User).offset(skip).limit(limit).all()
    return users


@app.delete("/user/{user_id}")
async def delete_user(user_id: int, db: Session = Depends(SessionLocal)):
    user = get_user(db, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
    user.is_active = False
    db.commit()
    return {"message": "Kullanıcı silindi"}


@app.delete("/logout")
async def logout(token: str):
    redis_client.set(token, "revoked", ex=ACCESS_TOKEN_EXPIRE_MINUTES * 60)  
    return {"message": "Başarıyla çıkış yapıldı"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
