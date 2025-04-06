from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_cors import CORS
from models import db, Policy, User
import os
import json
from datetime import datetime, timedelta
from opa_client import evaluate_policy
import jwt
from functools import wraps

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///policies.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this in production!
JWT_SECRET = "your-secret-key-here"  # Change this in production!

db.init_app(app)
with app.app_context():
    db.create_all()
    # Create default MRM user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', role='mrm')
        admin.set_password('admin')  # Change this in production!
        db.session.add(admin)
        db.session.commit()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def mrm_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_mrm():
            return jsonify({"error": "MRM role required"}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        
        return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    user = User.query.get(session['user_id'])
    return render_template('index.html', user=user)

@app.route('/validate')
@login_required
def validate_page():
    user = User.query.get(session['user_id'])
    return render_template('validate.html', user=user)

@app.route('/api/policies', methods=['GET'])
@login_required
def get_policies():
    policies = Policy.query.all()
    return jsonify([{
        'id': policy.id,
        'name': policy.name,
        'content': policy.content,
        'created_at': policy.created_at.isoformat(),
        'updated_at': policy.updated_at.isoformat()
    } for policy in policies])

@app.route('/api/policies', methods=['POST'])
@mrm_required
def create_policy():
    data = request.json
    if not data.get('name') or not data.get('content'):
        return jsonify({"error": "Name and content are required"}), 400
    
    policy = Policy(
        name=data['name'],
        content=data['content'],
        user_id=session['user_id']
    )
    db.session.add(policy)
    db.session.commit()
    
    return jsonify({
        'id': policy.id,
        'name': policy.name,
        'content': policy.content,
        'created_at': policy.created_at.isoformat(),
        'updated_at': policy.updated_at.isoformat()
    })

@app.route('/api/policies/<int:id>', methods=['PUT'])
@mrm_required
def update_policy(id):
    policy = Policy.query.get_or_404(id)
    data = request.json
    
    if not data.get('name') or not data.get('content'):
        return jsonify({"error": "Name and content are required"}), 400
    
    policy.name = data['name']
    policy.content = data['content']
    db.session.commit()
    
    return jsonify({
        'id': policy.id,
        'name': policy.name,
        'content': policy.content,
        'created_at': policy.created_at.isoformat(),
        'updated_at': policy.updated_at.isoformat()
    })

@app.route('/api/evaluate', methods=['POST'])
@login_required
def evaluate_policy_endpoint():
    data = request.json
    
    policy_content = data.get('policy', '').strip()
    if not policy_content:
        return jsonify({"error": "Policy content is empty"}), 400

    try:
        input_data = data.get('input', {})
        if isinstance(input_data, str):
            input_data = json.loads(input_data)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid input JSON"}), 400
    
    result = eval   `uate_policy(
        policy_content=policy_content,
        input_data=input_data
    )
    
    if 'error' in result:
        return jsonify(result), 500
    return jsonify(result)

@app.route('/api/generate-token', methods=['POST'])
@login_required
def generate_token():
    data = request.json
    policy_content = data.get('policy', '').strip()
    
    if not policy_content:
        return jsonify({"error": "Policy content is empty"}), 400
    
    try:
        payload = {
            'policy': policy_content,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(days=30)
        }
        
        token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
        
        return jsonify({
            "token": token,
            "expires": payload['exp'].isoformat()
        })
        
    except Exception as e:
        return jsonify({"error": f"Failed to generate token: {str(e)}"}), 500

@app.route('/api/validate-token', methods=['POST'])
@login_required
def validate_token():
    data = request.json
    token = data.get('token', '').strip()
    
    if not token:
        return jsonify({"error": "Token is required"}), 400
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        
        return jsonify({
            "valid": True,
            "policy": payload['policy'],
            "issued_at": datetime.fromtimestamp(payload['iat']).isoformat(),
            "expires_at": datetime.fromtimestamp(payload['exp']).isoformat()
        })
        
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 400
    except jwt.InvalidSignatureError:
        return jsonify({"error": "Invalid token signature"}), 400
    except jwt.DecodeError:
        return jsonify({"error": "Token is invalid"}), 400
    except Exception as e:
        return jsonify({"error": f"Failed to validate token: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
