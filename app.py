from flask import Flask, redirect, url_for, request, render_template
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from dash import Dash
import dash_bootstrap_components as dbc

from project.layout import register_layout
from project.callbacks import register_callbacks

server = Flask(__name__)
server.secret_key = 'super secret key'

login_manager = LoginManager()
login_manager.init_app(server)

class User(UserMixin):
    def __init__(self, username):
        self.id = username

    def __str__(self):
        return self.id

users = {'admin': {'password': 'admin'}}

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
    app.layout = register_layout(current_user)
    return app.index()

app = Dash(__name__, server=server, external_stylesheets=[dbc.themes.BOOTSTRAP])
app.title = "TLHOP/SAM Analytics on EPSS"
app.layout = register_layout(current_user)
register_callbacks(app)

if __name__ == '__main__':
    app.run_server(debug=True)
