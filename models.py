from typing import Literal

from pydantic import BaseModel, Field


Role = Literal["admin", "user", "guest"]


class UserBase(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)


class User(UserBase):
    password: str = Field(..., min_length=1, max_length=128)
    role: Role = "user"


class UserInDB(UserBase):
    hashed_password: str
    role: Role = "user"


class LoginRequest(UserBase):
    password: str = Field(..., min_length=1, max_length=128)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class Message(BaseModel):
    message: str


class TodoCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1, max_length=1000)


class TodoUpdate(TodoCreate):
    completed: bool


class TodoOut(TodoUpdate):
    id: int
