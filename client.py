#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Dec 18 02:18:44 2020

@author: fractum
"""
import requests
from jwt import encode, decode, InvalidTokenError, ExpiredSignatureError
from datetime import datetime, timedelta
from os import getenv
from dotenv import load_dotenv
import json
import sys



# load_dotenv()
# JWT_SECRET = getenv("JWT_SECRET")
# JWT_EXP = 30

# def generate_autentication_token(user):
#     payload = {
#             "iss": "de-liver auth server",
#             "usr": user,
#             "aud": "de-liver tracking service",
#             "exp": datetime.utcnow() + timedelta(weeks = 100)}
#     token = encode(payload, JWT_SECRET, algorithm='HS256' )
#     return token

# token = generate_autentication_token('Courier')


token = b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJkZS1saXZlciBhdXRoIHNlcnZlciIsInVzciI6IkNvdXJpZXIiLCJhdWQiOiJkZS1saXZlciB0cmFja2luZyBzZXJ2aWNlIiwiZXhwIjoxNjY4ODIwMDQ2fQ.UiBqIOUi7e3Zm-Gvd8oy3bdpCD0sP6_7pCcvEXWdD5Q'
#api_link = 'http://0.0.0.0:5000'
api_link = 'https://krukm-web-app.herokuapp.com'
    
print('Connecting to the api...')
try:
    api_doc = requests.get(api_link + '/api', 
                           headers = {'Authorization': 'Bearer ' + token.decode()}).content.decode()
    print('Connected')
except:
    print('Can not connect to api')
    sys.exit()

links = json.loads(api_doc)['_links']
print('\nGreetings!')

while True:
    print('\nPlease, chose an option from below:\n')
    for link in links:
        print(link)   
    print('q for exit')
    print('m for return to main api')
    option = input()
    
    if option == 'packages:show':
        packages = json.loads(requests.get(api_link + links['packages:show']['href'], 
                           headers = {'Authorization': 'Bearer ' + token.decode()}).content.decode())
        items = packages['_embedded']['items']
        
        links = {}
        for item in items:
            print('\nUser: ', item['user'], ' Package id: ', item['id'], ' Package name: ', 
                  item['package_name'], ' Package weight: ', item['package_weight'], 
                  ' Package cell id: ', item['package_cellid'])
            if 'parcel:update' in item['_links']:
                print('\nParcel already exists and can be updated')
            if 'parcel:create' in item['_links']:
                print('\nParcel for this package does not exist and can be created')
            print('\nYou can chose a following options for this package')
            print(list(item['_links'].keys()))
        for link in packages['_links']:
            links[link] = packages['_links'][link]['href']
        
    elif option == 'parcel:create':
        print('Please enter package id')
        package_id = input()
        post_response = json.loads(requests.post(api_link + f'/api/parcels/{package_id}', 
                           headers = {'Authorization': 'Bearer ' + token.decode()}).content.decode())
        print(post_response)
    
    elif option == 'parcel:update':
        #Parcel id is the same as package, if parcel exists
        print('Please, enter parcel id')
        parcel_id = input()
        put_response = json.loads(requests.put(api_link + f'/api/parcels/{parcel_id}', 
                           headers = {'Authorization': 'Bearer ' + token.decode()}).content.decode())
        print(put_response)
    
    elif option == 'self':
        print('Link is ', links['self']) 
        
    elif option == 'm':
        api_doc = requests.get(api_link + '/api', 
                           headers = {'Authorization': 'Bearer ' + token.decode()}).content.decode()

        links = json.loads(api_doc)['_links']
        
    elif option == 'q':
        break
    else:
        print('\nCan not recognize this option')
        
    
