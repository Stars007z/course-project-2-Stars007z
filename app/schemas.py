from pydantic import BaseModel, EmailStr, StringConstraints
from typing_extensions import Annotated

NonEmptyShortStr = Annotated[str, StringConstraints(min_length=1, max_length=100)]
NonEmptyLongStr = Annotated[str, StringConstraints(min_length=1, max_length=1000)]
PasswordStr = Annotated[str, StringConstraints(min_length=8, max_length=128)]
EmailType = Annotated[EmailStr, StringConstraints(max_length=254)]


class FeatureBase(BaseModel):
    title: NonEmptyShortStr
    description: NonEmptyLongStr


class FeatureCreate(FeatureBase):
    pass


class FeatureOut(FeatureBase):
    id: int
    vote_count: int
    owner_id: int

    model_config = {"from_attributes": True}


class UserBase(BaseModel):
    email: EmailType
    full_name: NonEmptyShortStr


class UserCreate(UserBase):
    password: PasswordStr


class UserOut(UserBase):
    id: int
    role: str

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    full_name: NonEmptyShortStr

    model_config = {"from_attributes": True}


class Token(BaseModel):
    access_token: str
    token_type: str


class VoteRequest(BaseModel):
    pass


class UserLogin(BaseModel):
    email: EmailType
    password: str
