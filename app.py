from flask import Flask, request, render_template, make_response
app = Flask(__name__)
app.debug = False

users = {
    'krukm': {'firstname':'Mara'}
    }

allowed_origins = ['http://localhost:5000']

@app.route('/check/<username>', methods=["GET"])
def check(username):
    origin = request.headers.get('Origin')
    result = {username: 'available'}
    if username in users:
        result = {username: 'taken'}
    response = make_response(result, 200)
    if origin in allowed_origins or origin.endswith('.herokuapp.com'):
        response.headers['Access-Control-Allow-Origin'] = origin
    return response
   




@app.route('/')
def index():
    return render_template("index.html")

@app.route('/sender/sign_up')
def login():
    return render_template("login.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)