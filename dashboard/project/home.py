from flask import Flask, redirect, url_for, request, render_template, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user

from dash import Dash
import dash_bootstrap_components as dbc

from project.layout import register_layout
from project.callbacks import register_callbacks
from project.storage import DatasetManager

from models import db, User, Vote
import os

import pyarrow.dataset as ds

def start_dash(host='127.0.0.1', port=8080, scan_enabled=True):

    server = Flask(__name__)
    server.secret_key = 'super secret key'

    postgres_url = os.environ.get("POSTGRES_URL","postgres:5432")
    postgres_user = os.environ.get('POSTGRES_USER', "postgres")
    postgres_password = os.environ.get('POSTGRES_PASSWORD')
    postgres_db = os.environ.get('POSTGRES_DB', 'postgres')

    server.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{postgres_user}:{postgres_password}@{postgres_url}/{postgres_db}"
    server.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(server)

    login_manager = LoginManager()
    login_manager.init_app(server)

    dm = DatasetManager()
    dm.check_available_datasets()

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @server.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
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

    # Iframe
    @server.route('/details_ip')
    def serve_details_ip():
        return render_template('index.html', user=current_user)

    @server.route('/save_vote', methods=['POST'])
    def save_vote():
        data = request.get_json()
        meta_id = data.get('meta_id')
        vote_value = data.get('vote')

        if meta_id and current_user.is_authenticated:
            existing_vote = Vote.query.filter_by(user_id=current_user.id, meta_id=meta_id).first()
            if existing_vote:
                if vote_value is None:
                    db.session.delete(existing_vote)
                else:
                    existing_vote.vote = vote_value 
            else:
                if vote_value is not None:
                    new_vote = Vote(user_id=current_user.id, meta_id=meta_id, vote=vote_value)
                    db.session.add(new_vote)

            db.session.commit()
            return jsonify({'status': 'success', 'message': 'Vote saved'}), 200
        return jsonify({'status': 'error', 'message': 'Failed to save vote'}), 400

    @server.route('/api/user_votes', methods=['GET'])
    @login_required
    def get_user_votes():
        votes = Vote.query.filter_by(user_id=current_user.id).all()
        votes_dict = {vote.meta_id: vote.vote for vote in votes}
        return jsonify(votes_dict)

    @server.route('/details/<meta_id>')
    def get_details_meta(meta_id):
        return render_template('details_ip.html', meta_id=meta_id, user='a')

    @server.route('/api/details/<meta_id>')
    def get_details_json(meta_id):
        day = request.args.get('day', '2024-05-02')
        condition = ds.field("meta_id") == meta_id
        filtered_data = dm.get_report_dataset_new(day, condition=condition, single_output=True)
        return jsonify(filtered_data)

    @server.route('/api/data_count', methods=['GET'])
    def get_data_count():
        date_value = request.args.get('date', '2024-05-02')
        total_entries = dm.get_total_entries_new(date_value)
        return jsonify({'total_entries': total_entries})

    @server.route('/api/data/<page>', methods=['GET'])
    def get_details(page):
        date_value = request.args.get('date', '2024-05-02')
        page_size = 10
        page_int = int(page)
        start = (page_int - 1) * page_size
        finish = page_int * page_size

        df = dm.get_report_dataset_new(
            date_value, 
            columns=["data", "ip_str", "port", "city", "os", "org", "hostnames", "domains", "meta_id", "vulns_scores"], 
            start=start, 
            finish=finish,
            sort_by='epss',
            ascending=False
        )

        partial = df.to_json(orient='records')
        return partial

    @server.route('/signup', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            
            # Check if the user already exists
            if User.query.filter_by(username=username).first():
                flash('Registration failed: user already exists')
                return redirect('/signup')
            
            # If the user does not exist, then add them to the database
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            return redirect('/login')
        return render_template('signup.html')

    app = Dash(__name__, server=server, external_stylesheets=external_stylesheets)
    app.scan_enabled = scan_enabled 
    app.title = "TLHOP/SAM Cybersecurity Dashboards"
    app.layout = register_layout(dm, current_user)
    register_callbacks(dm, app)

    with server.app_context():
        db.create_all()

    app.run(debug=True, host=host, port=port, use_reloader=False)
