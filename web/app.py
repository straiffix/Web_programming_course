from flask import Flask, request, render_template, make_response
from flask import session, flash, url_for, redirect, g
from flask_hal import HAL, document
from flask_hal.document import Embedded
from flask_hal.link import Link
from flask_session import Session
from functools import wraps
import requests
import jwt
from jwt import encode, decode, InvalidTokenError, ExpiredSignatureError, ExpiredSignatureError
import atexit
import json
#from redis import StrictRedis

from authlib.integrations.flask_client import OAuth

import sys

from redis import StrictRedis, ConnectionError
from bcrypt import hashpw, gensalt, checkpw

from datetime import datetime, timedelta

from os import getenv
from dotenv import load_dotenv
from six.moves.urllib.request import urlopen

load_dotenv()
SESSION_TYPE='redis' #filesystem
SESSION_COOKIE_NAME = "app_session"
SESSION_PERMANENT = False
global_token = None

REDIS_HOST = getenv("REDIS_HOST")
REDIS_PASS = getenv("REDIS_PASS")
#print(REDIS_HOST, REDIS_PASS)
db = StrictRedis(REDIS_HOST, db=4, password=REDIS_PASS)

#Not neccessary
#SESSION_COOKIE_HTTPONLY = True

#Can't make secure cookie because not using https
#SESSION_COOKIE_SECURE = True
JWT_SECRET = getenv("JWT_SECRET")
JWT_EXP = 30
SESSION_REDIS=db

app = Flask(__name__)
HAL(app)

#app.debug = False
app.config.from_object(__name__)
app.secret_key = getenv('SECRET_KEY')
ses = Session(app)
allowed_origins = ['http://0.0.0.0:5000', 'http://0.0.0.0:8000', 'localhost', 'http://localhost:5000']



#AUTH0

AUTH0_CALLBACK_URL = getenv('AUTH0_CALLBACK_URL')
AUTH0_CLIENT_ID = getenv('AUTH0_CLIENT_ID')
AUTH0_CLIENT_SECRET = getenv('AUTH0_CLIENT_SECRET')
AUTH0_DOMAIN = getenv('AUTH0_DOMAIN')
AUTH0_BASE_URL = 'https://' + AUTH0_DOMAIN
AUTH0_AUDIENCE = getenv('AUTH0_AUDIENCE')
API_IDENTIFIER = getenv('API_IDENTIFIER')


oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url=AUTH0_BASE_URL + '/oauth/token',
    authorize_url=AUTH0_BASE_URL + '/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

from jose import jwt
def verify_auth_token(token):
        jsonurl = urlopen("https://"+AUTH0_DOMAIN+"/.well-known/jwks.json")
        jwks = json.loads(jsonurl.read())
        try:
            unverified_header = jwt.get_unverified_header(token)
        except Exception as e:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Invalid header. "
                                "Use an RS256 signed JWT Access Token"}, 401)
        if unverified_header["alg"] == "HS256":
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Invalid header. "
                                "Use an RS256 signed JWT Access Token"}, 401)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=["RS256"],
                    audience=API_IDENTIFIER,
                    issuer="https://"+AUTH0_DOMAIN+"/"
                )
            except ExpiredSignatureError:
                raise AuthError({"code": "token_expired",
                                "description": "token is expired"}, 401)
            except Exception:
                raise AuthError({"code": "invalid_claims",
                                "description":
                                    "incorrect claims,"
                                    " please check the audience and issuer"}, 401)
            except Exception:
                raise AuthError({"code": "invalid_header",
                                "description":
                                    "Unable to parse authentication"
                                    " token."}, 401)

            return True
        raise AuthError({"code": "invalid_header",
                        "description": "Unable to find appropriate key"}, 401)

def allowed_methods(methods):
    if 'OPTIONS' not in methods:
        methods.append('OPTIONS')
    response = make_response('', 204)
    response.headers['Allow'] = ', '.join(methods)
    return response



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
    db.lpush("users", username)
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


def generate_tracking_token(package, user):
    payload = {
            "iss": "de-liver auth server",
            "sub": package,
            "usr": user, 
            "aud": "de-liver tracking service",
            "exp": datetime.utcnow() + timedelta(seconds=JWT_EXP)}
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256' )
    return token

def generate_autentication_token(user):
    payload = {
            "iss": "de-liver auth server",
            "usr": user,
            "aud": "de-liver tracking service",
            "exp": datetime.utcnow() + timedelta(seconds=600)}
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256' )
    return token



#def redirect(url, status=301):
#    response = make_response('', status)
#    response.headers['Location'] = url
#    return response

def error(msg, status=400):
    response = make_response({"status":"error", "message":msg}, status)
    return response


#Api

@app.route('/api', methods=['OPTIONS', 'GET'])
def api():
    
    if_courier = False
    if_user = False
    
    token = request.headers.get('Authorization', '').replace('Bearer', '')
    token = token[1:]
    
    try:
        if_courier = verify_auth_token(token)
        print('Verified Couirer')
    except Exception as e:
        print(e, 'Courier Oauth does not working')
    
    try:
        decoded_token = decode(token.encode(), JWT_SECRET, algorithms=['HS256'], audience="de-liver tracking service")
        if_user = True
        print('Verified User')
    except:
        print('Not user')
        
    
    if if_courier:
        user = 'Courier'
    elif if_user:
        user = decoded_token['usr']
    else:
        return {'error' : 'not authorized'}, 401
    
    if token != None:
        links = []
        if user == 'Courier':
            if request.method == 'OPTIONS':
                return allowed_methods(['OPTIONS', 'GET'])
            links.append(Link('packages:show', '/api/packages'))
            links.append(Link('parcel:create', '/api/parcels/{id}', templated=True))
            links.append(Link('parcel:update', '/api/parcels/{id}', templated=True))
            return document.Document(data={}, links=links).to_json()
        
        else:
            if request.method == 'OPTIONS':
                return allowed_methods(['OPTIONS','GET'])
            links.append(Link('userlist:show', '/api/userlist/' + user))
            links.append(Link('package:create', '/api/packages/{id}', templated=True))
            links.append(Link('package:remove', '/api/packages/{id}', templated=True))
            return document.Document(data={}, links=links).to_json()
            
    else:
        return make_response('400', 'Not authorized')


@app.route('/api/packages/', methods=['OPTIONS', 'GET'])
def packages_all():
    token = request.headers.get('Authorization', '').replace('Bearer', '')
    token = token[1:]
    try:
        decoded_token = decode(token.encode(), JWT_SECRET, algorithms=['HS256'], audience="de-liver tracking service")
    except:
        print('Not authorized!')
        return {'error' : 'not authorized'}, 401
     
    user = decoded_token['usr']
    
    if user != 'Courier':
        return {'error' : 'not allowed'}, 405
    
    users = db.lrange('users', 0, db.llen('users'))
    users = [user.decode() for user in users]
    items = []
    ln = []
    ln.append(Link('packages:show', '/api/packages'))
    ln.append(Link('parcel:create', '/api/parcels/{id}', templated=True))
    ln.append(Link('parcel:update', '/api/parcels/{id}', templated=True))
    for key in db.keys():
         dkey = key.decode()
         user = dkey.split(':')[0]
         pid = dkey.split(':')[-1]
         if user in users and pid != 'packages':
             package_name = db.hget(key, "pckg_name").decode()
             package_weight = db.hget(key, "pckg_weight").decode()
             package_cellid = db.hget(key, "cell_id").decode()
             package_status = db.hget(key, "status").decode()
             if package_status is None:
                 db.hset(key, "status", "created".encode())
                 package_status = "created"
                
             data = {'user': user, 'id': pid, 'package_name': package_name, 'package_weight': package_weight, 
                     'package_cellid': package_cellid, 'package_status': package_status}
             link = Link('self', '/api/packages/' + pid)
             status = db.hget(f'parcels:{pid}', 'status') 
             if status:
                 link = Link('parcel:update', '/api/parcels/' + pid)
                 db.hset(f"{user}:{pid}", "status", status)
             else:
                 link = Link('parcel:create', '/api/parcels/' + pid)

             items.append(Embedded(data=data, links=[link]))
    doc = document.Document(embedded = {'items' : Embedded(data=items)}, links=ln)
    return doc.to_json()
        

@app.route('/api/parcels/<pid>', methods=['OPTIONS', 'PUT', 'POST'])
def manage_parcel(pid):
    token = request.headers.get('Authorization', '').replace('Bearer', '')
    token = token[1:]
    try:
        decoded_token = decode(token.encode(), JWT_SECRET, algorithms=['HS256'], audience="de-liver tracking service")
    except:
        print('Not authorized!')
        return {'error' : 'not authorized'}, 401
    username = decoded_token['usr']
    
    if username != 'Courier':
        return {'error' : 'not allowed'}, 405
    
    if request.method == 'OPTIONS':
        return allowed_methods(['OPTIONS','PUT', 'POST'])
    
    links = []
    data = {}
    
    if request.method == 'POST':
        status = db.hget(f'parcels:{pid}', 'status')
        if status:
            return {'error' : 'Can not execute an action, resource already exists'}, 403
        else:
            db.hset(f'parcels:{pid}', 'status', 'shipped'.encode())
            data['status'] = 'shipped'
            
            #Messages
            message_user = None
            users = db.lrange('users', 0, db.llen('users'))
            for user in users:
                user = user.decode()
                if db.hexists(f"{user}:{pid}", "status"):
                    db.rpush(f'messages:{user}', f'Parcel for your package {pid} has been created!')
                    db.publish('channel:krukm', f'Parcel for your package {pid} has been created!')
            
            links.append(Link('parcel:update', '/api/parcels/' + pid))
            data['operation_status'] = 'Created'
            
    if request.method == 'PUT':
        available_statuses = ['shipped', 'in transit', 'arrived', 'received']
        status = db.hget(f'parcels:{pid}', 'status').decode()
        if status:
            current_status = available_statuses.index(status)
            next_status = current_status + 1
            if next_status != len(available_statuses) - 1:
                next_status = available_statuses[next_status]
                db.hset(f'parcels:{pid}', 'status', next_status.encode())
                data['operation_status'] = 'updated'
                data['status'] = next_status
                
                #Messages
                message_user = None
                users = db.lrange('users', 0, db.llen('users'))
                for user in users:
                    user = user.decode()
                    if db.hexists(f"{user}:{pid}", "status"):
                        db.rpush(f'messages:{user}', f'Parcel for your package {pid} has been updated! New status is: {next_status}')
                        db.publish('channel:krukm', f'Parcel for your package {pid} has been updated! New status is: {next_status}')
                
                links.append(Link('parcel:update', '/api/parcels/' + pid))
            else:
                return {'error' : 'Can not execute an action, parcel is on the last stage'}, 403
        else:
            return {'error' : 'Can not execute an action, parcel does not exists'}, 403

    
    doc = document.Document(data=data, links=links)
    return doc.to_json()

    


@app.route('/api/packages/<pid>', methods=['OPTIONS', 'GET', 'POST', 'DELETE'])
def manage_package(pid):
    token = request.headers.get('Authorization', '').replace('Bearer', '')
    token = token[1:]
    try:
        decoded_token = decode(token.encode(), JWT_SECRET, algorithms=['HS256'], audience="de-liver tracking service")
    except:
        return {'error' : 'not authorized'}, 401
    
    username = decoded_token['usr']
    links = []
    statuses = ['shipped', 'in transit', 'arrived', 'received', 'created', 'Created']
    
    if request.method == 'OPTIONS':
        return allowed_methods(['OPTIONS', 'GET', 'POST', 'DELETE'])
    
    if request.method == 'POST':
        pckg_name = request.headers.get('pckg_name', '')
        pckg_weight = request.headers.get('pckg_weight', '')
        cell_id = request.headers.get('cell_id', '')
    
        db.hset(f"{username}:{pid}", "pckg_name", pckg_name.encode())
        db.hset(f"{username}:{pid}", "pckg_weight", pckg_weight.encode())
        db.hset(f"{username}:{pid}", "cell_id", cell_id.encode())
        db.hset(f"{username}:{pid}", "status", 'Created'.encode())
        db.lpush(f"{username}:packages", pid.encode())
        links.append(Link('package:remove', f'/api/packages/{pid}'))
        links.append(Link('self', f'/api/packages/{pid}'))
        print('Package created!')
    if request.method == 'GET':
        try:
            status = db.hget(f'parcels:{pid}', 'status')
            db.hset(f"{username}:{pid}", "status", status)
            print('change parcel')
        except:
             print('nothing')
        if db.get(f"{username}:{pid}") is not None:
            
            if db.hget(f'{username}:{pid}', "status").decode() in statuses:
                links.append(Link('package:remove', f'/api/packages/{pid}'))
            else:
                return {'error' : 'Can not execute an action, package does not exist'}, 403
            links.append(Link('self', f'/api/packages/{pid}'))
    if request.method == 'DELETE':
        if db.hexists(f"{username}:{pid}", 'status'):
            if db.hget(f'{username}:{pid}', 'status').decode() in statuses:
                db.delete(f'{username}:{pid}')
                db.lrem(f'{username}:packages', 0, pid.encode())
            else:
                return {'error' : 'Can not execute an action, package does not exist'}, 403
                
    
    doc = document.Document(links=links)
    return doc.to_json()

@app.route('/api/userlist/<req_user>', methods=['OPTIONS', 'GET'])
def packages_user(req_user):
    # users = db.lrange('users', 0, db.llen('users'))
    # users = [user.decode() for user in users]
    token = request.headers.get('Authorization', '').replace('Bearer', '')
    token = token[1:]
    try:
        decoded_token = decode(token.encode(), JWT_SECRET, algorithms=['HS256'], audience="de-liver tracking service")
    except:
        return {'error' : 'not authorized'}, 401
    
    if request.method == 'OPTIONS':
        return allowed_methods(['OPTIONS', 'GET'])
    
    items = []
    ln = Link('test', '/api')
    for key in db.keys():
         dkey = key.decode()
         user = dkey.split(':')[0]
         pid = dkey.split(':')[-1]
         if user == req_user and pid != 'packages':
             package_name = db.hget(key, "pckg_name").decode()
             package_weight = db.hget(key, "pckg_weight").decode()
             package_cellid = db.hget(key, "cell_id").decode()
             package_status = db.hget(key, "status").decode()
             if package_status is None:
                 db.hset(key, "status", "created".encode())
                 package_status = "created"
             status = db.hget(f'parcels:{pid}', 'status') 
             if status:
                 link = Link('parcel:update', '/api/parcels/' + pid)
                 db.hset(f"{user}:{pid}", "status", status)
             data = {'user': user, 'id': pid, 'package_name': package_name, 'package_weight': package_weight, 
                     'package_cellid': package_cellid, 'package_status': package_status}
             link = Link('self', '/api/packages/' + pid)
             items.append(Embedded(data=data, links=[link]))
    doc = document.Document(embedded = {'items' : Embedded(data=items)}, links=[ln])
    return doc.to_json()
        

#Sender

@app.route('/check/<username>', methods=["GET"])
def check(username):
    #origin = request.headers.get('Origin')
    referer_allowed = ['http://localhost:5000/sender/sign_up', 'http://0.0.0.0:5000/sender/sign_up']
    referer = request.headers.get('Referer')
    result = {username: 'available'}
    if is_user(username):
        result = {username: 'taken'}
    response = make_response(result, 200)
    heroku = referer.split('.')
    ifheroku = False
    if 'herokuapp' in heroku:
        ifheroku = True
    if referer in referer_allowed or ifheroku is True:
        response.headers['Access-Control-Allow-Origin'] = referer
    return response
   
#Sender

@app.route('/', methods=['GET', 'OPTIONS'])
def index():
    if request.method == 'OPTIONS':
        return allowed_methods(['GET'])
    
    return render_template("index.html")

@app.route('/sender/sign_up', methods =["GET"])
def register_form():
    return render_template("register.html")

@app.route('/sender/sign_up', methods = ["POST"])
def register():
    
    firstname = request.form.get("firstname")
    lastname = request.form.get("lastname")
    password = request.form.get("password")
    password_second = request.form.get("password_second")
    username = request.form.get("username")
    address = request.form.get("address")
    email = request.form.get("email")
    
    if any([firstname, lastname, password, password_second, username, email, address]) is None:
        flash("Something missing")
        redirect(url_for('register_form'))
    
    if is_user(username):
        flash('User already exist')
        redirect(url_for('register_form'))
    
    
    print(f"Registered new user {username}")

    success = save_user(username, password, firstname, lastname, email, address)

    if success: 
        return redirect(url_for('login_form'))
    else:
        return make_response('Unknown error', 402)
    

@app.route('/user/profile', methods= ["GET"])
def get_profile():
    if g.user is not None:
        #return make_response(get_user(g.user), 200)
        return render_template('profile.html', user = g.user)
    else:
        return make_response('Not authorized', 401)

@app.route('/sender/login', methods = ["GET"])
def login_form():
    return render_template("login.html")


@app.route('/session', methods=['GET'])
def session_view():
    ck = request.cookies.get('app_session')
    print(ck)
    if "username" in session:
        return str(session["username"]) + " " + str(session['logged-in'] + " " + str(session) + str(session['auth-token']))
    
    else:
        return "not ok"


@app.route('/sender/login', methods = ['POST'])
def login():
    if "oauth" not in session.keys():
        print(request.headers)
        username = request.form.get("username")
        password = request.form.get("password")
        
        if not username or not password:
            flash("Missing username and/or password")
            return redirect(url_for('login_form'))
    
        if not verify_user(username, password):
            flash("Invalid username and/or password")
            return redirect(url_for('login_form'))
        
        print("ok")
        flash(f"Welcome {username}!")
        session['username'] = username
        session[username] = "logged-in"
        session['logged-in'] = datetime.now().ctime()
        token = generate_autentication_token(username)
        session['auth-token'] = token
        #ANother way to make session
        response = make_response(redirect(url_for('index')))
        #response.set_cookie("sess_id", username,
        #                       max_age=30, secure=True, httponly=True)
    
        response.headers['Content-Type'] = 'application/json'
        response.headers['Cache-Control']= 'private'
        response.headers['Vary'] = 'Cookie'
        
        print(username, token, type(token) )
        try:
            token = token.decode()
        except:
            print("something wring with token formats")
        response.headers['Authorization'] = 'Bearer ' + token
        #print(generate_tracking_token("dead-beef", username)) 
        #return redirect(url_for('index'))
        return response
    else: 
        return redirect(url_for('index'))

@app.route('/logout1', methods = ['GET'])
def logout1():
    sess = request.cookies.get('app_session')
    session.clear()
    g.user = None
    db.delete(f"session:{sess}")
    resp = make_response(render_template('index.html'))
    resp.set_cookie('app_session', '') 
    
    return resp

from six.moves.urllib.parse import urlencode

@app.route('/logout', methods = ['GET'])
def logout():
    sess = request.cookies.get('app_session')
    try:
        if session['oauth'] == 'oauth':
            print('logout with oauth')
            session.clear()
            params = {'returnTo': url_for('index', _external=True), 'client_id': AUTH0_CLIENT_ID}
            return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))
    except:
        print("Not oatuh logout")
    session.clear()
    g.user = None
    db.delete(f"session:{sess}")
    return make_response(render_template('index.html'))
   
@app.before_request
def get_logged_username():
    if (not 'auth-token' in session):
        try:
            header = request.headers.get('data')
            if 'noti-handler' in header:
                return redirect(url_for('notifications'))
        except:
            pass 
    
    g.user = session.get('username')
    token = session.get('auth-token')
    try:
        g.authorization = decode(token, JWT_SECRET, algorithms=['HS256'], audience="de-liver tracking service")
        print('Authorized: ' + str(g.authorization))
    except Exception as e:
        print(e)
        print('Unauthorized')

@app.route('/sender/create_package', methods = ['GET'])
def package_form():
    return render_template("package-form.html")

import uuid

@app.route('/sender/packages', methods = ['POST'])
def create_and_delete_package():
    username = g.user
    token = session.get('auth-token')
    try:
        decode(token, JWT_SECRET, algorithms=['HS256'], audience="de-liver tracking service")
    except:
        return 'Not authorized', 401
    #Get links
    
    try:
        token = token.decode()
    except:
        pass
    
    try:
        api_doc = requests.get(request.url_root[:-1] + '/api', 
                           headers = {'Authorization': 'Bearer ' + token}).content.decode()
    except:
        return 'Can not connect to api', 503
    links = json.loads(api_doc)['_links']
    print(links)
    
    
    #Package data
    pckg_name = request.form.get("pckgn")
    pckg_weight = request.form.get("pckgw")
    cell_id = request.form.get("pckgcell")
    
    
    remove_package_pid = request.form.get('pckgid')
    
    
    if (pckg_name is not None and pckg_name != "") and (pckg_weight is not None and pckg_weight != "") and (cell_id is not None and cell_id != ""):
    #print(pckg_name, pckg_weight, cell_id)
    
        pckg_id = str(uuid.uuid4())
        
        while db.get(f"{username}:{pckg_id}") is not None:
            pckg_id = str(uuid.uuid4())
            
        #Create package link
        create_package_link = links['package:create']['href'].format(id = pckg_id)
        print(request.url_root[:-1] + create_package_link)
        requests.post(request.url_root[:-1] + create_package_link, 
                                    headers = {'Authorization': 'Bearer ' + token,
                                                'pckg_name': pckg_name,
                                                'pckg_weight': pckg_weight,
                                                'cell_id': cell_id})
        
        items = json.loads(requests.post(request.url_root[:-1] + create_package_link, 
                                    headers = {'Authorization': 'Bearer ' + token,
                                                'pckg_name': pckg_name,
                                                'pckg_weight': pckg_weight,
                                                'cell_id': cell_id}).content.decode())
        
        flash('Created')
    elif remove_package_pid is None:
        flash('Empty fields')
    if remove_package_pid is not None:
        remove_package_link = links['package:remove']['href'].format(id = remove_package_pid)
        requests.delete(request.url_root[:-1] + remove_package_link, 
                                    headers = {'Authorization': 'Bearer ' + token})
        flash('Deleted')
    return redirect('/sender/packages', 302)

def delete_package(pid):
    db.delete(f'{g.user}:{pid}')
    db.lrem(f'{g.user}:packages', 0, pid.encode())



@app.route('/sender/packages', methods=["GET"])
def sender_packages_list():
    
    if g.user is None:
        return "Not authorized", 401
    user = g.user
    
    token = session.get('auth-token')
    
    try:
        token = token.decode()
    except:
        pass
    
    #Get links
    try:
        api_doc = requests.get(request.url_root[:-1] + '/api', 
                           headers = {'Authorization': 'Bearer ' + token}).content.decode()
    except:
        return 'Can not connect to API', 503
    links = json.loads(api_doc)['_links']

    #Show package list link - get only for authorized user
    list_link = links['userlist:show']['href']
    
    #Get packages
    items = json.loads(requests.get(request.url_root[:-1] + list_link, 
                                    headers = {'Authorization': 'Bearer ' + token}).content.decode())
    items_ids = items['_embedded']['items']
    
    api_packages = []
    for item in items_ids:
        api_packages.append(item['id'])
    
    tokens = {}
    for package in api_packages:
        try:
            tokens[package] = generate_tracking_token(package, session['username']).decode()
        except:
            tokens[package] = generate_tracking_token(package, session['username'])
    return render_template("sender-packages.html", tokens = tokens, haspackages = (len(tokens) > 0))
    
    

@app.route('/package/<pid>', methods=["GET"])
def get_package(pid):
    token = request.args.get('token')
    if token is None:
        return 'No access token', 401
    try:
        payload = decode(token, key=JWT_SECRET, algorithm=['HS256'], audience="de-liver tracking service")
    except InvalidTokenError as error:
        print('Invalid token error' + str(error))
        return 'Invalid access token' , 401
    if pid != payload.get('sub'):
        return 'Not aurhotized', 401
    package = db.hvals(f'{g.user}:{pid}')
    package = [item.decode() for item in package]
    #return str(package), 200
    return render_template("packages.html", package = package)


@app.route('/oauth_login', methods=["GET", "POST"])
def oauth_login():
    return auth0.authorize_redirect(redirect_uri=AUTH0_CALLBACK_URL, audience=AUTH0_AUDIENCE)

@app.route('/callback')
def callback_handling():
   
        
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()
    
    username = userinfo["nickname"]
    email = userinfo["email"]
    name = userinfo["given_name"]
    lastname = userinfo["family_name"]
    response = make_response(redirect(url_for('login')))
    
    #If exists, then login
    if is_user(username):
        
        if db.hget(f"user:{username}", "email").decode() == email:
            #login
            session['username'] = username
            session[username] = "logged-in"
            session['logged-in'] = datetime.now().ctime()
            session['auth-token'] = generate_autentication_token(username)
            response = make_response(redirect(url_for('index')))
            print('Successfully loged')
        else:
            print("Wrong matching email and username!")
    else:
    #Register otherwise
        password = str(uuid.uuid4())
        address = "-"
        success = save_user(username, password, name, lastname, email, address)
    
        if success: 
            print(f"Registered new user {username}")
            session['username'] = username
            session[username] = "logged-in"
            session['logged-in'] = datetime.now().ctime()
            session['auth-token'] = generate_autentication_token(username)
            response = make_response(redirect(url_for('index')))
            
        else:
            return make_response('Unknown error', 402)
    
    
    
    session['oauth'] = "oauth"
    print(resp.json())
    # session[constants.PROFILE_KEY] = {
    #     'user_id': userinfo['sub'],
    #     'name': userinfo['name'],
    #     'picture': userinfo['picture']
    # }
    return response



@app.route('/notifications', methods=['GET', 'POST'])
def notifications():
    if g.user is None:
        return "Not authorized", 401
    user = g.user
    
    return render_template("notifications.html")


    
@app.route('/notif_get', methods=['GET', 'POST'])
def notif_get():
    if g.user is None:
        return "Not authorized", 401
    user = g.user
    token = session.get('auth-token')
    
    
    #note = db.lpop(f'messages:{user}' )
    messages = {}
    notes = db.lrange(f'messages:{user}', 0, db.llen(f'messages:{user}'))
    for i, note in enumerate(notes):
        note = note.decode()
        messages[f'{i}'] = note
    
    if request.method == 'POST':
        index = json.loads(request.data.decode())['value']
        print(index)
        db.lset(f'messages:{user}', index, 'delete')
        db.lrem(f'messages:{user}', 1, 'delete')
        
    
    # while not note:
    #     sleep(1)
    #     notes = db.lrange(f'messages:{user}', 0, db.llen(f'messages:{user}'))
    #     #print(note)
    #     if note is not None:
    #          break

    #print('exit cycle')
    #print(messages)
    
    return messages

    
     # response = make_response(note, 200)
    # heroku = referer.split('.')
    # ifheroku = False
    # if 'herokuapp' in heroku:
    #     ifheroku = True
    # if referer in referer_allowed or ifheroku is True:
    #     response.headers['Access-Control-Allow-Origin'] = referer        
    
    # p = db.pubsub()
    # p.subscribe(f'channel:{user}')
    # while messages == []:
    #     for message in p.listen():
    #         print(message)
    #         messages.append(message)

if __name__ == "__main__":
    atexit.register(logout)
    app.run(host="0.0.0.0", port=5000)    
    
    
