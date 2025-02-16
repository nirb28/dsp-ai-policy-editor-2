from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from models import db, Policy
import os
import requests
import json
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///policies.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/policies', methods=['GET'])
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
def create_policy():
    data = request.json
    policy = Policy(name=data['name'], content=data['content'])
    db.session.add(policy)
    db.session.commit()
    return jsonify({
        'id': policy.id,
        'name': policy.name,
        'content': policy.content,
        'created_at': policy.created_at.isoformat(),
        'updated_at': policy.updated_at.isoformat()
    })

@app.route('/api/policies/<int:policy_id>', methods=['PUT'])
def update_policy(policy_id):
    policy = Policy.query.get_or_404(policy_id)
    data = request.json
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
def evaluate_policy():
    data = request.json
    playground_url = "https://play.openpolicyagent.org/v1/data"
    
    # Prepare the policy document
    policy_content = data.get('policy', '')
    if not policy_content.strip():
        return jsonify({"error": "Policy content is empty"}), 400

    # Prepare the input document
    try:
        input_data = data.get('input', {})
        if isinstance(input_data, str):
            input_data = json.loads(input_data)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid input JSON"}), 400

    # Prepare the query path (convert data.example.allow to example/allow)
    query = data.get('query', 'data.example.allow')
    if query.startswith('data.'):
        query = query[5:].replace('.', '/')
    
    # Prepare the request payload
    payload = {
        "input": input_data,
        "modules": [{
            "path": "policy.rego",
            "content": policy_content
        }]
    }
    
    try:
        response = requests.post(f"{playground_url}/{query}", json=payload)
        response.raise_for_status()
        result = response.json()
        
        if 'result' in result:
            return jsonify({"result": result['result']})
        elif 'error' in result:
            return jsonify({"error": result['error']}), 400
        else:
            return jsonify({"error": "Unknown evaluation error"}), 400
            
    except requests.RequestException as e:
        return jsonify({"error": f"Failed to evaluate policy: {str(e)}"}), 500
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid response from OPA Playground"}), 500

if __name__ == '__main__':
    app.run(debug=True)
