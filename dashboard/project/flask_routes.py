from flask import Flask, redirect, url_for, request, render_template, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from project.models import db, User, Vote
from project.layout import register_layout
import pyarrow.dataset as ds
import os

def start_flask(dm):
    """
    Starts the custom flask server to handle authentication and the advanced queries.
    """

    server = Flask("TLHOP/SAM Cybersecurity Dashboards", template_folder='./dashboard/templates', static_folder="./dashboard/templates/static")
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

    login_manager = LoginManager()
    login_manager.init_app(server)

    @server.route('/')
    def root():
        if current_user.is_authenticated:
            return redirect('/dashboard/')
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
                    return redirect('/dashboard/')
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

    @server.route('/dashboard/')
    @login_required
    def dashboard():
        app.layout = register_layout(dm, current_user.username)
        return app.index()

    @server.route('/details_ip')
    @login_required
    def serve_details_ip():
        return render_template('panel.html', user=current_user)

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
        try:
            votes = Vote.query.filter_by(user_id=current_user.id).all()
            votes_dict = {vote.meta_id: vote.vote for vote in votes}
        except:
            votes_dict = {}
        return jsonify(votes_dict)

    @server.route('/details/<meta_id>')
    @login_required
    def get_details_meta(meta_id):
        return render_template('details_ip.html', meta_id=meta_id)

    @server.route('/api/details/<meta_id>')
    @login_required
    def get_details_json(meta_id):
        print(meta_id)
        try:
            print(request.args)
            print(request.form)
            print(request.data)

            day = request.args.get('date')
            print(day)
            condition = ds.field("meta_id") == meta_id
            filtered_data = dm.get_report_dataset_new(day, condition=condition, single_output=True)
        except:
            filtered_data = {}
        print(filtered_data)
        return jsonify(filtered_data)

    @server.route('/api/data_count', methods=['GET'])
    @login_required
    def get_data_count():
        try:
            date_value = request.args.get('date')
            total_entries = dm.get_total_entries_new(date_value)
        except:
            total_entries = -1
        return jsonify({'total_entries': total_entries})

    @server.route('/api/data/<page>', methods=['GET'])
    @login_required
    def get_details(page):
        try:
            date_value = request.args.get('date')
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
        except:
            partial = {}
        return partial
    
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
    
    @server.route('/get_users', methods=['GET'])
    @login_required
    def get_users():
        if current_user.username != 'admin':
            return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 403

        users = User.query.all()
        users_list = [{'username': user.username} for user in users]
        return jsonify(users_list), 200

    @server.route('/change_password', methods=['POST'])
    @login_required
    def change_password():
        if current_user.username != 'admin':
            return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 403

        data = request.get_json()
        username = data.get('username')
        new_password = data.get('newPassword')

        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        user.set_password(new_password)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Password changed successfully!'}), 200
    
    @server.route('/profile')
    @login_required
    def profile():
        user = current_user
        return render_template('profile.html', user=user)

    return app