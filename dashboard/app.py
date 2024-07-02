from flask import Flask, redirect, url_for, request, render_template
from flask_login import LoginManager, login_user, logout_user, login_required, current_user

from dash import Dash
import dash_bootstrap_components as dbc

from project.layout import register_layout
from project.callbacks import register_callbacks
from project.base import User, users
from project.storage import DatasetManager

server = Flask(__name__)
server.secret_key = 'super secret key'

login_manager = LoginManager()
login_manager.init_app(server)

dm = DatasetManager()
dm.check_available_datasets()

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@server.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and password == users[username]['password']:
            user = User(username)
            login_user(user)
            return redirect('/dashboard/')
    return render_template('login.html')

@server.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@server.route('/')
def root():
    if current_user.is_authenticated:
        return redirect('/dashboard/')
    else:
        return redirect('/login')
    
@server.route('/dashboard/')
@login_required
def dashboard():
    app.layout = register_layout(dm, current_user)
    return app.index()


external_stylesheets = [
    {
        "href": (
            "https://fonts.googleapis.com/css2?"
            "family=Lato:wght@400;700&display=swap"
        ),
        "rel": "stylesheet",
    },
    dbc.themes.BOOTSTRAP
]


app = Dash(__name__, server=server, external_stylesheets=external_stylesheets)
app.title = "TLHOP/SAM Analytics on EPSS"
app.layout = register_layout(dm, current_user)
register_callbacks(dm, app)

if __name__ == '__main__':
    app.run_server(debug=True, host="0.0.0.0", port=8080, use_reloader=False)
