from flask import Flask, request, render_template, make_response
from flask import session, flash, url_for, redirect, g
from flask_session import Session
from jwt import encode, decode
import atexit
#from redis import StrictRedis
from utils_db import db, is_user, save_user, delete_user, verify_user, get_user

from datetime import datetime, timedelta

from os import getenv
from dotenv import load_dotenv

load_dotenv()
SESSION_TYPE='redis' #filesystem
SESSION_COOKIE_NAME = "app_session"
SESSION_PERMANENT = False

#Not neccessary
#SESSION_COOKIE_HTTPONLY = True

#Can't make secure cookie because not using https
#SESSION_COOKIE_SECURE = True
JWT_SECRET = getenv("JWT_SECRET")
JWT_EXP = 30
SESSION_REDIS=db

app = Flask(__name__)
#app.debug = False
app.config.from_object(__name__)
app.secret_key = getenv('SECRET_KEY')
ses = Session(app)
allowed_origins = ['localhost', 'http://localhost:5000']


def generate_tracking_token(package, user):
    payload = {
            "iss": "de-liver auth server",
            "sub": package,
            "usr": user, 
            "aud": "de-liver tracking service",
            "exp": datetime.utcnow() + timedelta(seconds=JWT_EXP)}
    token = encode(payload, JWT_SECRET, algorithm='HS256' )
    return token

    
#def redirect(url, status=301):
#    response = make_response('', status)
#    response.headers['Location'] = url
#    return response

def error(msg, status=400):
    response = make_response({"status":"error", "message":msg}, status)
    return response


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
   

@app.route('/')
def index():
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
        return make_response(get_user(g.user), 200)
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
        return str(session["username"]) + " " + str(session['logged-in'] + " " + str(session))
    
    else:
        return "not ok"

@app.route('/sender/login', methods = ['POST'])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
#    if username not in users:
 #       return "No such user", 401
  #  if not checkpw(password.encode('utf8'), users[username]['password']):
   #     return "Inc passw", 401
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
    #ANother way to make session
    #response = make_response(render_template("index.html"))
    #response.set_cookie("sess_id", username,
    #                       max_age=30, secure=True, httponly=True)
    #print(generate_tracking_token("dead-beef", username)) 
    return redirect(url_for('index'))
    #return response

@app.route('/logout1', methods = ['GET'])
def logout1():
    sess = request.cookies.get('app_session')
    session.clear()
    g.user = None
    db.delete(f"session:{sess}")
    resp = make_response(render_template('index.html'))
    resp.set_cookie('app_session', '') 
    
    return resp

@app.route('/logout', methods = ['GET'])
def logout():
    sess = request.cookies.get('app_session')
    session.clear()
    g.user = None
    db.delete(f"session:{sess}")
    return make_response(render_template('index.html'))
   
@app.before_request
def get_logged_username():
    g.user = session.get('username')

@app.route('/sender/create_package', methods = ['GET'])
def package_form():
    return render_template("package-form.html")

import uuid



    

@app.route('/sender/packages', methods = ['POST'])
def create_package():
    username = g.user
    pckg_name = request.form.get("pckgn")
    pckg_weight = request.form.get("pckgw")
    cell_id = request.form.get("pckgcell")
    remove_package = request.form.get('pckgid')
    if (pckg_name is not None and pckg_name != "") and (pckg_weight is not None and pckg_weight != "") and (cell_id is not None and cell_id != ""):
    #print(pckg_name, pckg_weight, cell_id)
        pckg_id = str(uuid.uuid4())
        while db.get(f"{username}:{pckg_id}") is not None:
            pckg_id = str(uuid.uuid4())
        db.hset(f"{username}:{pckg_id}", "pckg_name", pckg_name.encode())
        db.hset(f"{username}:{pckg_id}", "pckg_weight", pckg_weight.encode())
        db.hset(f"{username}:{pckg_id}", "cell_id", cell_id.encode())
        db.lpush(f"{username}:packages", pckg_id.encode())
        flash('Created')
    elif remove_package is None:
        flash('Empty fields')
    if remove_package is not None:
        delete_package(remove_package)
    return redirect('/sender/packages', 302)

def delete_package(pid):
    db.delete(f'{g.user}:{pid}')
    db.lrem(f'{g.user}:packages', 0, pid.encode())


@app.route('/sender/packages', methods=["GET"])
def sender_packages_list():
    if g.user is None:
        return "Not authorized", 401
    user = g.user
    new_packages = db.lrange(f'{user}:packages', 0, db.llen(f'{user}:packages'))
    packages = [item.decode() for item in new_packages]
    tokens = {}
    for package  in packages:
        tokens[package] = generate_tracking_token(package, session['username']).decode()
    return render_template("sender-packages.html", tokens = tokens, haspackages = (len(tokens) > 0))
    
    
import jwt
@app.route('/package/<pid>', methods=["GET"])
def get_package(pid):
    token = request.args.get('token')
    if token is None:
        return 'No access token', 401
    try:
        payload = decode(token, key=JWT_SECRET, algorithm=['HS256'], audience="de-liver tracking service")
    except jwt.InvalidTokenError as error:
        print('Invalid token error' + str(error))
        return 'Invalid access token' , 401
    if pid != payload.get('sub'):
        return 'Not aurhotized', 401
    package = db.hvals(f'{g.user}:{pid}')
    package = [item.decode() for item in package]
    return str(package), 200


if __name__ == "__main__":
    atexit.register(logout)
    app.run(host="0.0.0.0", port=5000)    
    
    
