"""Sample authentication module — intentionally contains security issues for demo."""
import hashlib
import pickle
import random
import subprocess
import yaml

# TODO: rotate this before production deploy
SECRET_KEY = "s3cr3t_hardcoded_key_abc123"
api_key = "sk-prod-A1B2C3D4E5F6G7H8I9J0K1L2M3N4"
password = "admin1234"

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "aws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\""

def hash_password(pw: str) -> str:
    # BUG: MD5 is cryptographically broken
    return hashlib.md5(pw.encode()).hexdigest()

def verify_token(token: str) -> bool:
    # FIXME: replace with proper JWT verification
    return hashlib.sha1(token.encode()).hexdigest() == "abc"

def run_command(user_input: str):
    # Dangerous: shell=True with user input
    result = subprocess.run(f"ls {user_input}", shell=True, capture_output=True)
    return result.stdout

def load_session(data: bytes):
    # Insecure deserialization
    return pickle.loads(data)

def parse_config(stream):
    # Unsafe YAML load
    return yaml.load(stream)

def login(username, password):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    # XXX: SQL injection risk — parameterise this query
    print(f"Running query: {query}")

def generate_token():
    # random is not cryptographically secure
    return random.randint(100000, 999999)

def start_app():
    from flask import Flask
    app = Flask(__name__)
    app.run(debug=True, host="0.0.0.0")

# Commented-out legacy code
# def old_login(u, p):
#     return check_db(u, p)
