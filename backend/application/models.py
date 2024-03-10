from .database import db
from flask_security import UserMixin, RoleMixin

class User(db.Model,UserMixin):
    __tablename__ = 'UserLogin'
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    aadhar = db.Column(db.String, unique=True)
    password = db.Column(db.String)
    email = db.Column(db.String)
    firstname = db.Column(db.String)
    lastname = db.Column(db.String)
    status = db.Column(db.String)

class Hospital(db.Model,UserMixin):
    __tablename__ = 'HospitalLogin'
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    hno = db.Column(db.String, unique=True)
    password = db.Column(db.String)
    status = db.Column(db.String)

class userdata(db.Model,UserMixin):
    __tablename__ = 'userdata'
    dataid = db.Column(db.Integer, autoincrement=True, primary_key=True)
    name = db.Column(db.String, unique=True)
    contact = db.Column(db.String)
    age = db.Column(db.String)
    gender = db.Column(db.String)
    height = db.Column(db.String)
    weight = db.Column(db.String)
    bloodgrp = db.Column(db.String)
    file = db.Column(db.LargeBinary) 
    ulid = db.Column(db.Integer, db.ForeignKey('UserLogin.id'), nullable=False)


