from pathlib import Path

from janus.engines.code.builtin import scan_file


def _rule_ids(path: str, text: str) -> set[str]:
    findings = scan_file(Path(path), text)
    return {f.rule_id for f in findings}


def test_sql_fstring_detected():
    text = 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
    assert "PY-SQLI-FSTRING" in _rule_ids("app.py", text)


def test_eval_detected():
    assert "PY-EVAL-EXEC" in _rule_ids("app.py", "eval(user_input)\n")


def test_commented_match_is_ignored():
    assert "PY-EVAL-EXEC" not in _rule_ids("app.py", "# eval(user_input)  -- disabled\n")


def test_shell_true_detected():
    assert "PY-SHELL-TRUE" in _rule_ids("app.py", 'subprocess.run(cmd, shell=True)\n')


def test_pickle_load_detected():
    assert "PY-PICKLE-LOAD" in _rule_ids("app.py", "pickle.loads(blob)\n")


def test_yaml_load_without_safe_loader_detected():
    assert "PY-YAML-LOAD" in _rule_ids("app.py", "yaml.load(fh)\n")


def test_yaml_safe_load_not_flagged():
    assert "PY-YAML-LOAD" not in _rule_ids("app.py", "yaml.safe_load(fh)\n")
    assert "PY-YAML-LOAD" not in _rule_ids("app.py", "yaml.load(fh, Loader=yaml.SafeLoader)\n")


def test_tls_verify_false_detected():
    assert "PY-TLS-VERIFY-FALSE" in _rule_ids("app.py", "requests.get(url, verify=False)\n")


def test_jwt_noverify_detected():
    assert "PY-JWT-NOVERIFY" in _rule_ids("app.py", "jwt.decode(token, key, verify=False)\n")


def test_cors_wildcard_detected_bare_and_quoted_and_bracketed():
    assert "CFG-CORS-WILDCARD" in _rule_ids("app.py", "CORS_ORIGIN_ALLOW_ALL = True\n")
    assert "CFG-CORS-WILDCARD" in _rule_ids("app.yaml", 'allow_origins: "*"\n')
    assert "CFG-CORS-WILDCARD" in _rule_ids("app.py", 'ALLOWED_ORIGINS = ["*"]\n')


def test_js_eval_detected():
    assert "JS-EVAL" in _rule_ids("app.js", "eval(userInput);\n")


def test_go_tls_skip_verify_detected():
    assert "GO-TLS-SKIP-VERIFY" in _rule_ids("main.go", "tls.Config{InsecureSkipVerify: true}\n")


def test_dockerfile_root_user_flagged_when_absent():
    text = "FROM python:3.12\nCOPY . .\nCMD [\"python\", \"app.py\"]\n"
    assert "DOCKER-ROOT-USER" in _rule_ids("Dockerfile", text)


def test_dockerfile_root_user_not_flagged_when_nonroot_user_set():
    text = "FROM python:3.12\nRUN useradd app\nUSER app\nCMD [\"python\", \"app.py\"]\n"
    assert "DOCKER-ROOT-USER" not in _rule_ids("Dockerfile", text)


def test_dockerfile_unpinned_base_detected():
    assert "DOCKER-UNPINNED-BASE" in _rule_ids("Dockerfile", "FROM python\n")
    assert "DOCKER-UNPINNED-BASE" in _rule_ids("Dockerfile", "FROM python:latest\n")


def test_dockerfile_pinned_base_not_flagged():
    assert "DOCKER-UNPINNED-BASE" not in _rule_ids("Dockerfile", "FROM python:3.12-slim\n")


def test_aws_key_detected():
    assert "SECRET-AWS-ACCESS-KEY" in _rule_ids("app.py", 'key = "AKIAABCDEFGHIJKLMNOP"\n')


def test_private_key_block_detected():
    assert "SECRET-PRIVATE-KEY-BLOCK" in _rule_ids("id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIe...\n")


def test_generic_high_entropy_secret_detected_but_placeholder_is_not():
    assert "SECRET-GENERIC-KV" in _rule_ids("app.py", 'api_key = "zQ3f9kLp2vR8xT1mN6cJ"\n')
    assert "SECRET-GENERIC-KV" not in _rule_ids("app.py", 'api_key = "changeme"\n')
    assert "SECRET-GENERIC-KV" not in _rule_ids("app.py", 'api_key = "${API_KEY}"\n')


def test_secret_value_never_appears_unmasked_in_snippet():
    text = 'password = "SuperSecretValue123456"\n'
    findings = scan_file(Path("app.py"), text)
    for f in findings:
        assert "SuperSecretValue123456" not in f.snippet
        assert "SuperSecretValue123456" not in f.message


def test_gitlab_token_detected():
    assert "SECRET-GITLAB-TOKEN" in _rule_ids("app.py", 'TOKEN = "glpat-ABCDEFGHIJKLMNOPQRST"\n')


def test_vault_token_detected():
    assert "SECRET-VAULT-TOKEN" in _rule_ids("app.py", 'VAULT_TOKEN = "hvs.ABCDEFGHIJKLMNOPQRSTUVWX"\n')


def test_npm_token_detected():
    assert "SECRET-NPM-TOKEN" in _rule_ids("app.py", 'NPM_TOKEN = "npm_abcdefghijklmnopqrstuvwxyz012345"\n')


def test_allowed_hosts_wildcard_detected():
    assert "CFG-ALLOWED-HOSTS-WILDCARD" in _rule_ids("settings.py", "ALLOWED_HOSTS = ['*']\n")


def test_csrf_exempt_detected():
    assert "CFG-CSRF-EXEMPT" in _rule_ids("views.py", "@csrf_exempt\ndef my_view(request):\n    pass\n")


def test_js_tls_reject_unauthorized_false_detected():
    assert "JS-TLS-REJECT-UNAUTHORIZED-FALSE" in _rule_ids("app.js", "https.request({rejectUnauthorized: false})\n")


def test_js_child_process_exec_detected_but_not_execfile():
    assert "JS-CHILD-PROCESS-EXEC" in _rule_ids("app.js", "child_process.exec(cmd)\n")
    assert "JS-CHILD-PROCESS-EXEC" not in _rule_ids("app.js", "child_process.execFile(bin, args)\n")


def test_go_sql_sprintf_detected():
    assert "GO-SQL-SPRINTF" in _rule_ids("main.go", 'db.Query(fmt.Sprintf("SELECT * FROM t WHERE id=%s", id))\n')


def test_go_exec_shell_detected():
    assert "GO-EXEC-SHELL" in _rule_ids("main.go", 'exec.Command("sh", "-c", script)\n')


def test_ci_pull_request_target_detected():
    assert "CI-PULL-REQUEST-TARGET" in _rule_ids("workflow.yml", "on:\n  pull_request_target:\n")


def test_doc_file_secret_downgraded_to_low():
    findings = scan_file(Path("README.md"), 'api_key = "zQ3f9kLp2vR8xT1mN6cJ"\n')
    hit = [f for f in findings if f.rule_id == "SECRET-GENERIC-KV"]
    assert hit and hit[0].severity == "low"
