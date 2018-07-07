# coding=utf-8

import threading
import requests
import logging
from flask import Flask, request, render_template, Response, json, jsonify, flash, redirect, abort, url_for
from flask_login import LoginManager, login_required, login_user, logout_user
from flask_login import login_manager
from login import User, is_safe_url

log = logging.getLogger('werkzeug')
log.setLevel(logging.INFO)
# api_server = 'http://labpc:8080/api/'
api_server = 'http://13.250.36.18:8080/api/'
app = Flask(__name__, template_folder='site/templates', static_folder='site/static')
# static_path=None, static_url_path=None, static_folder=’static’, template_folder=’templates’, instance_path=None, instance_relative_config=False, root_path=None
# app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

# flask-login
app.secret_key = 'app_secret_key_bi12$*(!aAa^jf1'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "/login.html"
# login_manager.login_message = u"Bonvolu ensaluti por uzi tiun paĝon."
# login_manager.login_message_category = "info"


def start_server(port=3000):
    app.run(host='', port=port, threaded=True, debug=True)

# @app.route('/<string:page_name>/')
# def static_page(page_name):
#     return app.send_static_file('../templates/index.html')
#     return render_template('%s.html' % page_name)

@app.route('/')
@app.route('/index')
@app.route('/index.html')
@login_required
def index():
    return render_template('index.html')

@app.route('/rule.html', methods = ['GET'])
@login_required
def rule_page():
    rules = requests.get(api_server+'rules', timeout=2).text
    return render_template('rule.html', rules=rules)

@app.route('/config.html', methods = ['GET'])
@login_required
def config_page():
    return render_template('config.html')

@app.route('/login.html', methods = ['GET'])
def login_page():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    passwd = request.form['password']
    print(email, passwd)
    if email == User.admin_email and passwd == User.admin_passwd:
        user = User(email)
        login_user(user)
        flash('Logged in successfully.')
        next = request.args.get('next')
        # is_safe_url should check if the url is safe for redirects.
        # See http://flask.pocoo.org/snippets/62/ for an example.
        if not is_safe_url(next):
            return abort(400)
        return redirect(next or url_for('index'))
    errmsg = "email or password is wrong!"
    return render_template('login.html', email=email, msg=errmsg)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Bye~")
    return redirect("/index.html")

@app.route('/state', methods = ['GET'])
@login_required
def get_state():
    # data = requests.get(api_server+'state').json()
    # data = {'data' : app.context.report()}
    data = {'data' : ''}
    # js = json.dumps(data, indent=4)
    # resp = Response(js, status=200, mimetype='application/json')
    resp = jsonify(data)
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp

@app.route('/stocks', methods = ['POST'])
@login_required
def create_stock():
    name = request.form['name']
    code = request.form['code']
    price = request.form['price']
    shares = request.form['shares']
    print(name, code, price, shares)
    return "ok"

@app.route('/rules', methods = ['POST'])
@login_required
def create_rules():
    rule_json = request.data
    res = requests.post(api_server+"rules", data={"ruleJson":rule_json})
    if res.status_code == 200:
        return "ok"
    return "error"

@app.route('/task/<name>/<action>', methods = ['PUT'])
@login_required
def take_action(name, action):
    resp = jsonify(name + action)
    # app.monitor.stop_task()
    task = app.context.get_task(name)
    code = task.stop()
    resp = jsonify(code)
    return resp

@login_manager.user_loader
def load_user(user_id):
    if user_id == User.admin_email:
        return User(User.admin_email)
    return None

# @login_manager.unauthorized_handler
# def unauthorized():
#     # do stuff
#     return a_response


if __name__ == "__main__":
    start_server(3000)
