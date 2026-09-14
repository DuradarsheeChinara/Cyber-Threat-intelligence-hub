from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import schemas
from ..auth import current_user, issue_token, password_hash
from ..database import get_db
from ..models import User

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=schemas.TokenOut, status_code=201)
def register(credentials: schemas.UserCredentials, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == credentials.username).first():
        raise HTTPException(409, "Username already registered")
    db.add(User(username=credentials.username, password_hash=password_hash(credentials.password)))
    db.commit()
    return {"access_token": issue_token(credentials.username)}

@router.post("/login", response_model=schemas.TokenOut)
def login(credentials: schemas.UserCredentials, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == credentials.username).first()
    if not user or user.password_hash != password_hash(credentials.password):
        raise HTTPException(401, "Invalid username or password")
    return {"access_token": issue_token(user.username)}

@router.get("/me")
def me(user: User = Depends(current_user)):
    return {"username": user.username}
