"""Deliberately vulnerable target for testing the RedTeam Linter console.

Every credential below is synthetic and worthless — it exists to prove that the
console masks secrets before they reach the browser or the exported report.

Expected results (embedded engine, default sinks.yaml):
  * 7 sink findings: 4 critical (eval, exec, compile, pickle.loads),
    2 high (os.system, subprocess.call with shell=True), 1 medium
    (os.system with a literal argument)
  * 4 credential findings: AWS key, GitHub token, JWT, hardcoded password
  * The two "safe counterparts" at the bottom must produce no findings.
  * 1 parse finding if you delete the closing bracket of run_query().

Paste the whole file into the "Paste code" tab as target.py, or upload it.
"""

import os
import pickle
import subprocess

# --- credentials that must come back redacted ------------------------------
AWS_ACCESS_KEY = "AKIAZ3TQ7XK2LMNOP4YZ"
GITHUB_TOKEN = "ghp_9fK2mQ7pR4tV8xZ1bN6cL3dH5jS0aE2wG4yU"
SESSION_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJyb290In0.c2lnbmF0dXJlLXBsYWNlaG9sZGVyLXZhbHVl"
DB_PASSWORD = "Pr0d-Sup3r-S3cret-2024"


# --- remote code execution ------------------------------------------------
def run_expression(request):
    """User-controlled eval: the classic one-liner RCE."""
    expression = request.args.get("expr")
    return eval(expression)


def run_script(request):
    """User-controlled exec with a multi-statement payload."""
    body = request.form.get("body")
    exec(body)


def compile_rule(request):
    """compile() of attacker source feeds a later exec()."""
    pattern = request.json.get("pattern")
    return compile(pattern, "<rule>", "exec")


# --- command injection ----------------------------------------------------
def ping_host(host):
    """Shell metacharacters in host are passed straight to /bin/sh."""
    os.system("ping -c 1 " + host)


def archive_dir(name):
    """shell=True with a concatenated argument: argument injection."""
    subprocess.call("tar -czf " + name + ".tgz " + name, shell=True)


# --- unsafe deserialization ----------------------------------------------
def load_session(blob):
    """pickle on untrusted bytes is code execution by design."""
    return pickle.loads(blob)


def save_config(data):
    """Same shape, but arguments are literals only -> lower severity."""
    os.system("echo 'config saved'")


# --- safe counterparts (expected to produce no findings) ------------------
def ping_host_safe(host):
    """List argv + shell=False and no eval: not matched by the rules."""
    subprocess.run(["ping", "-c", "1", host], shell=False, check=False)


def run_query(cursor, user_id):
    """Parameterised SQL is intentionally not flagged."""
    cursor.execute("SELECT * FROM orders WHERE user_id = ?", (user_id,))
