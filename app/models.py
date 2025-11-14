from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(
        String, default="user"
    )  # например: "user", "admin" (пока что только user)

    features = relationship("Feature", back_populates="owner")
    votes = relationship("Vote", back_populates="user")


class Feature(Base):
    __tablename__ = "features"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)
    vote_count = Column(Integer, default=0)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    owner = relationship("User", back_populates="features")
    votes = relationship("Vote", back_populates="feature")


class Vote(Base):
    __tablename__ = "votes"

    id = Column(Integer, primary_key=True, index=True)
    feature_id = Column(Integer, ForeignKey("features.id"))
    user_id = Column(Integer, ForeignKey("users.id"))

    feature = relationship("Feature", back_populates="votes")
    user = relationship("User", back_populates="votes")
