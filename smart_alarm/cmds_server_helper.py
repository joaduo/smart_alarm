"""
smart_alarm
Copyright (c) 2020, Joaquin G. Duo

Code Licensed under LGPL License. See LICENSE file.
"""
from datetime import datetime, timedelta
from typing import Optional
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from fastapi import Depends, HTTPException, status, FastAPI
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
import logging
import requests
from fastapi.security import OAuth2PasswordRequestForm
from smart_alarm.solve_settings import solve_settings


logger = logging.getLogger('cmds_server_helper')

settings = solve_settings()

def get_db():
    fake_users_db = {
        "salarm": {
            "username": "salarm",
            "hashed_password": settings.user_hashed_password,
            "disabled": False,
        }
    }
    return fake_users_db

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(get_db(), username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

origins = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "https://null.jsbin.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(get_db(), form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.jwt_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


class AndroidRPC:
    def __getattr__(self, name):
        def method(*args, **kwargs):
            r = self.do_rpc(name, *args, **kwargs)
            if r.get('error'):
                logger.error(f'While calling AndroidRPC.{name}(*{args},**{kwargs}) {r}')
            return r
        return method

    def do_rpc(self, method, *args, **kwargs):
        url = f'http://{settings.android_server}:{settings.android_server_port}' 
        json = {'method': method,
                'args': args,
                'kwargs':kwargs,
                'auth_token': settings.android_auth_token}
        try:
            logger.debug(f'Requesting to {url} {json}')
            r = requests.post(url, json=json)
            logger.debug(f'Got {r.json()} for {method!r} {args} {kwargs}')
            return dict(result=r.json())
        except Exception as e:
            logger.exception(f'While RPC {method!r} {args} {kwargs}')
            return dict(error=f'RPC {method!r} {args} {kwargs} {e} {e!r}')

    def sms_send(self, phone, msg):
        return self.do_rpc('sms_send', phone=phone, msg=msg)

    def sms_get_messages(self, unread=True):
        return self.do_rpc('sms_get_messages', unread=unread)
