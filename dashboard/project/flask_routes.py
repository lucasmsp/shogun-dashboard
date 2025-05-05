from flask import Flask, redirect, url_for, request, render_template, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash

from project.models import db, User, Vote
from project.layout import register_layout
from project.auxiliar import logging

import pyarrow.dataset as ds
import pandas as pd
import os
from datetime import datetime

def global_date():
    file_path = os.path.join('date', 'selected_date.csv')
    if not os.path.exists('date'):
        os.makedirs('date')
    if os.path.exists(file_path):
        df = pd.read_csv(file_path)
        if not df.empty and 'date' in df.columns:
            return df['date'].iloc[0].strip()
    return None

def start_flask(dm):
    """
    Starts the custom flask server to handle authentication and the advanced queries.
    """

    server = Flask("SAM/CRIVO Cybersecurity Dashboards", template_folder='./templates', static_folder="./templates/static")
    # During the process of signing a cookie, the SECRET_KEY is used in a way similar to how a "salt" would be used to muddle a password before hashing it. 
    # Do not set the SECRET_KEY directly with a function that generates a different key each time it's called. Otherwise, each time your application is
    # restarted it will be given a new key, thus invalidating the previous. A good recipe to generate FLASK_SECRET is copy the content of `import os; os.urandom(24)`
    server.secret_key = os.environ.get("FLASK_SECRET", 'super secret key') 

    postgres_url = os.environ.get("POSTGRES_URL","postgres:5432")
    postgres_user = os.environ.get('POSTGRES_USER', "postgres")
    postgres_password = os.environ.get('POSTGRES_PASSWORD')
    postgres_db = os.environ.get('POSTGRES_DB', 'postgres')

    server.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{postgres_user}:{postgres_password}@{postgres_url}/{postgres_db}"
    server.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(server)

    with server.app_context():
        db.create_all()

        if not User.query.filter_by(username='admin').first():
            admin_password = generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'admin'))
            admin_user = User(username='admin', password=admin_password)
            db.session.add(admin_user)
            db.session.commit()
            logging.info("Admin user created with username 'admin'")

    login_manager = LoginManager()
    login_manager.init_app(server)

    @server.route('/')
    def root():
        if current_user.is_authenticated:
            logging.info("logged, redirecting to /dashboard/summary")
            return redirect('/dashboard/summary')
        else:
            return redirect('/login')

    @server.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            try:
                username = request.form['username']
                password = request.form['password']
                user = User.query.filter_by(username=username).first()
                if user and user.check_password(password):
                    login_user(user)
                    logging.info("logged")
                    return redirect('/dashboard/summary')
            except:
                pass
        return render_template('login.html')

    @login_manager.user_loader
    def load_user(user_id):
        try:
            result = User.query.get(int(user_id))
        except User.DoesNotExist:
            result = None
        return result

    @server.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login'))

    return server, db, login_manager


def set_routes(server, db, login_manager, app):
    dm = app.dm

    @server.route('/dashboard/summary')
    @login_required
    def dashboard():
        logging.info("login_required")
        app.layout = register_layout(dm)
        return app.index()
    
    ### FEATURE FLAG

    @server.route('/profile2')
    @login_required
    def feature_flag():
        return render_template('feature_flag_profile.html', user="teste")    
    
    ### FEATURE FLAG END

    @server.route('/save_vote', methods=['POST'])
    @login_required
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
                    existing_vote.vote_date = datetime.utcnow()  # Update vote_date
            else:
                if vote_value is not None:
                    new_vote = Vote(user_id=current_user.id, meta_id=meta_id, vote=vote_value, vote_date=datetime.utcnow())
                    db.session.add(new_vote)

            db.session.commit()
            return jsonify({'status': 'success', 'message': 'Vote saved'}), 200
        return jsonify({'status': 'error', 'message': 'Failed to save vote'}), 400

    @server.route('/api/user_votes', methods=['GET'])
    @login_required
    def get_user_votes():
        try:
            votes = Vote.query.filter_by(user_id=current_user.id).all()
            votes_dict = {vote.meta_id: vote.vote for vote in votes}
        except:
            votes_dict = {}
        return jsonify(votes_dict)
    
    @server.route('/api/user_vote_single', methods=['GET'])
    @login_required
    def get_user_vote():
        meta_id = request.args.get('meta_id')
        if not meta_id:
            return jsonify({"error": "meta_id is required"}), 400
        try:
            vote = Vote.query.filter_by(user_id=current_user.id, meta_id=meta_id).first()
            if vote:
                vote_dict = {
                    "meta_id": vote.meta_id,
                    "vote": vote.vote,
                    "vote_type": type(vote.vote).__name__
                }
            else:
                vote_dict = {"message": "No vote found for the given meta_id"}
        except Exception as e:
            vote_dict = {"error": str(e)}
        return jsonify(vote_dict)

    @server.route('/details/<meta_id>')
    @login_required
    def get_details_meta(meta_id):
        return render_template('details_ip.html', meta_id=meta_id)

    @server.route('/api/details/<meta_id>')
    @login_required
    def get_details_json(meta_id):
        try:
            day = global_date()
            condition = ds.field("meta_id") == meta_id
            filtered_data = dm.get_report_dataset(day, condition=condition, single_output=True)
        except:
            filtered_data = {}
        return jsonify(filtered_data)

    @server.route('/admin')
    @login_required
    def admin_page():
        if current_user.username != 'admin':
            return redirect(url_for('root'))
        return render_template('admin.html')
    
    @server.route('/create_user', methods=['POST'])
    @login_required
    def create_user():
        if current_user.username != 'admin':
            return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 403

        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if User.query.filter_by(username=username).first():
            return jsonify({'status': 'error', 'message': 'User already exists'}), 400

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'User created successfully!'}), 200
    
    @server.route('/change_password', methods=['POST'])
    @login_required
    def change_password():
        data = request.get_json()
        current_password = data.get('currentPassword')
        new_password = data.get('newPassword')

        if not current_password or not new_password:
            return jsonify({'message': 'Current and new passwords are required'}), 400

        if not check_password_hash(current_user.password, current_password):
            return jsonify({'message': 'Current password is incorrect'}), 400

        current_user.password = generate_password_hash(new_password)

        db.session.commit()

        return jsonify({'message': 'Password successfully changed'}), 200
    
    @server.route('/admin_change_password', methods=['POST'])
    @login_required
    def admin_change_password():
        if current_user.username != 'admin':
            return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 403

        data = request.get_json()
        username = data.get('username')
        new_password = data.get('newPassword')

        if not username or not new_password:
            return jsonify({'status': 'error', 'message': 'Username and new password are required'}), 400

        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'status': 'error', 'message': 'User does not exist'}), 400

        user.password = generate_password_hash(new_password)
        db.session.commit()

        return jsonify({'status': 'success', 'message': f'Password for user {username} successfully changed'}), 200
    
    # User deletion
    @server.route('/delete_user', methods=['POST'])
    @login_required
    def delete_user():
        data = request.get_json()
        username = data.get('username')

        # Block admin removal
        if username == 'admin':
            return jsonify({'status': 'error', 'message': 'The admin user cannot be deleted.'}), 403

        if current_user.username != 'admin':
            return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 403

        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'status': 'error', 'message': 'User does not exist'}), 400

        db.session.delete(user)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'User deleted successfully!'}), 200
    
    @server.route('/get_users', methods=['GET'])
    @login_required
    def get_users():
        if current_user.username != 'admin':
            return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 403

        users = User.query.all()
        users_list = [{'username': user.username} for user in users]
        return jsonify(users_list), 200
    
    @server.route('/profile')
    @login_required
    def profile():
        user = current_user
        return render_template('profile.html', user=user)
    
    @server.route('/remove_vote', methods=['POST'])
    def remove_vote():
        data = request.get_json()
        meta_id = data.get('meta_id')

        if not meta_id:
            return jsonify({'status': 'error', 'message': 'Meta ID not provided'}), 400

        try:
            vote = Vote.query.filter_by(meta_id=meta_id).first()

            if vote:
                db.session.delete(vote)
                db.session.commit()
                return jsonify({'status': 'success'})
            else:
                return jsonify({'status': 'error', 'message': 'Vote not found'}), 404
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

    return app
