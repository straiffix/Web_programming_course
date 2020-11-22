#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Nov 18 23:10:06 2020

@author: fractum
"""

import sys

from redis import StrictRedis, ConnectionError
from bcrypt import hashpw, gensalt, checkpw
from os import getenv

REDIS_HOST = getenv("REDIS_HOST")
REDIS_PASS = getenv("REDIS_PASS")
#print(REDIS_HOST, REDIS_PASS)
db = StrictRedis(REDIS_HOST, db=4, password=REDIS_PASS)

# try:
#     db.ping() 
#     print('Connected to redis "{}"'.format(REDIS_HOST)) 
# except ConnectionError:
#     print("Can not connect to database!")
#     sys.exit()




def is_user(username):
    return db.hexists(f"user:{username}", "password")

def save_user(username, password, name, lastname, email, address):
    salt = gensalt(5)
    password = password.encode()
    hashed = hashpw(password, salt)
    db.hset(f"user:{username}", "password", hashed)
    db.hset(f"user:{username}", "name", name)
    db.hset(f"user:{username}", "lastname", lastname)
    db.hset(f"user:{username}", "email", email)
    db.hset(f"user:{username}", "address", address)
    return True

def delete_user(username):
    return db.delete(f"user:{username}")

def get_user(username):
    user = {'username' : username,
            'name' : db.hget(f"user:{username}", "name").decode(),
            'last name': db.hget(f"user:{username}", "lastname").decode(),
            'email' : db.hget(f"user:{username}", "email").decode(),
            'address' : db.hget(f"user:{username}", "address").decode()
        }
    return user
    
def verify_user(username, password):
    password = password.encode()
    hashed = db.hget(f"user:{username}", "password")
    if not hashed:
        print("ERROR")
        return False
    return checkpw(password, hashed)