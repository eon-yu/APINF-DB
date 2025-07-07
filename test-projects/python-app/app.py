#!/usr/bin/env python3
"""
Python test application for OSS compliance scanning
"""

import os
import sys
import json
import datetime
from flask import Flask, request, jsonify
import requests
import pandas as pd
import numpy as np
from cryptography.fernet import Fernet
import jwt
import bcrypt
from sqlalchemy import create_engine, text
import pymongo
from PIL import Image
import yaml

app = Flask(__name__)
app.config['SECRET_KEY'] = 'test-secret-key'

# Sample data
users_data = [
    {'id': 1, 'name': 'Alice', 'email': 'alice@example.com'},
    {'id': 2, 'name': 'Bob', 'email': 'bob@example.com'},
    {'id': 3, 'name': 'Charlie', 'email': 'charlie@example.com'}
]

@app.route('/')
def home():
    """Home endpoint with system information"""
    return jsonify({
        'message': 'Python test application for OSS compliance scanning',
        'timestamp': datetime.datetime.now().isoformat(),
        'python_version': sys.version,
        'dependencies': {
            'flask': 'Web framework',
            'requests': 'HTTP library',
            'pandas': 'Data analysis',
            'numpy': 'Numerical computing',
            'cryptography': 'Cryptographic library',
            'PyJWT': 'JWT tokens',
            'bcrypt': 'Password hashing'
        }
    })

@app.route('/users')
def get_users():
    """Get all users using pandas for data processing"""
    df = pd.DataFrame(users_data)
    # Add some numpy operations
    df['score'] = np.random.randint(1, 100, size=len(df))
    return jsonify(df.to_dict('records'))

@app.route('/external')
def external_api():
    """Make external API call using requests"""
    try:
        response = requests.get('https://jsonplaceholder.typicode.com/posts/1', timeout=5)
        return jsonify(response.json())
    except requests.RequestException as e:
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    """Login endpoint with JWT token generation"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    # Hash password using bcrypt
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # Generate JWT token (using potentially vulnerable library version)
    payload = {
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({
        'token': token,
        'message': 'Login successful',
        'hashed_password': hashed.decode('utf-8')
    })

@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    """Encrypt data using cryptography library"""
    data = request.get_json()
    message = data.get('message', '')
    
    # Generate a key
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    
    # Encrypt the message
    encrypted_message = cipher_suite.encrypt(message.encode())
    
    return jsonify({
        'original': message,
        'encrypted': encrypted_message.decode(),
        'key': key.decode(),
        'algorithm': 'Fernet (AES 128)'
    })

@app.route('/process-yaml', methods=['POST'])
def process_yaml():
    """Process YAML data (using potentially vulnerable yaml.load)"""
    data = request.get_json()
    yaml_data = data.get('yaml', '')
    
    try:
        # Using unsafe yaml.load for testing vulnerability detection
        parsed = yaml.load(yaml_data, Loader=yaml.FullLoader)
        return jsonify({
            'parsed': parsed,
            'type': str(type(parsed)),
            'warning': 'Using potentially unsafe yaml.load'
        })
    except yaml.YAMLError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/image-info', methods=['POST'])
def image_info():
    """Process image information using Pillow"""
    if 'image' not in request.files:
        return jsonify({'error': 'No image file provided'}), 400
    
    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        img = Image.open(file.stream)
        return jsonify({
            'format': img.format,
            'mode': img.mode,
            'size': img.size,
            'info': dict(img.info)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/database-test')
def database_test():
    """Test database connections (mock)"""
    return jsonify({
        'postgresql': 'psycopg2-binary available',
        'mongodb': 'pymongo available',
        'sqlalchemy': 'ORM available',
        'note': 'This is a mock endpoint for testing dependencies'
    })

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.datetime.now().isoformat(),
        'dependencies_loaded': True
    })

if __name__ == '__main__':
    print("Starting Python test application")
    print(f"Dependencies loaded: Flask, requests, pandas, numpy, cryptography, PyJWT, bcrypt")
    app.run(host='0.0.0.0', port=5000, debug=True) 