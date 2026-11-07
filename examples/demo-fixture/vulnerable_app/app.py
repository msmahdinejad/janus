"""Synthetic, deliberately-vulnerable fixture for Janus's own test suite and
the `janus demo` / `janus scan code` walkthrough. Nothing here is real:
example.com is IANA's reserved documentation domain, and every credential
below is an obviously-fake placeholder string, not a real secret.

Do not model real code on this file — it exists purely to give every
builtin rule something to fire on.
"""

import pickle
import subprocess

import yaml

# SECRET-AWS-ACCESS-KEY (fake — IANA documentation-domain-style placeholder)
AWS_ACCESS_KEY_ID = "AKIAFAKEEXAMPLE00000"

DATABASE_URL = "postgres://demo_user:not-a-real-password@db.example.com:5432/demo"

CORS_ORIGIN_ALLOW_ALL = True


def get_user(conn, user_id):
    # PY-SQLI-FSTRING
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query)


def run_report(script_name):
    # PY-SHELL-TRUE
    subprocess.run(f"generate_report.sh {script_name}", shell=True)


def load_config(path):
    with open(path) as fh:
        # PY-YAML-LOAD
        return yaml.load(fh)


def restore_session(blob):
    # PY-PICKLE-LOAD
    return pickle.loads(blob)


def run_user_expression(expr):
    # PY-EVAL-EXEC
    return eval(expr)
