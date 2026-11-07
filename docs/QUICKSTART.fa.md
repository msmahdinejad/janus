# Janus — راهنمای کوتاه دستی (ترب)

بدون ایجنت، ۱۰ دقیقه تا اولین اسکن.

## ۱. نصب

```powershell
cd D:\Janus
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q          # ۱۴۷ سبز
```

## ۲. ابزارها

`gitleaks`، `trivy`، `nuclei` را در `.tools/bin` بگذار؛ `uv tool install semgrep --python 3.11`.

```powershell
$env:TRIVY_DB_REPOSITORY="ghcr.io/aquasecurity/trivy-db:2"
janus doctor --tools-dir .tools/bin
```

## ۳. scope

```powershell
# از کد: هاست‌های غیرتولیدی allow، تولیدی‌ها deny
janus discover --repo ..\backend-api --owned torob.com,torob.ir,torobpay.com,torob.dev,badem.shop `
  --write-scope scope.toml
# یا دستی از روی scope.example.toml
janus init --dir my-scan --interactive
```

حداقل: `allow`، `deny`، `seeds` (برای پورت غیر ۴۴۳)، `reference` (شماره تیکت)،
`[code].roots`.

## ۴. کلید مدل (فقط برای ایجنت)

```powershell
$env:TOROB_LITELLM_KEY="<key>"
janus llm-shim --port 18081 --upstream https://litellm.torob.ir/v1 --api-key-env TOROB_LITELLM_KEY
janus doctor --providers-file providers.torob.toml --check-models
```

## ۵. اسکن

```powershell
janus scan code  --scope scope.toml --out out
janus scan recon --scope scope.toml --out out --mode passive
janus scan all   --scope scope.toml --out out --mode agent --lens all `
  --providers-file providers.torob.toml --agent-providers torob-deepseek
janus review code --repo ..\backend-api --agent codex --lens authz,business --out out/review
```

مسیر نوشتنی (فقط staging) با `[[write.targets]]` و `allow_state_changing = true`.

## ۶. دیدن نتایج

```powershell
janus dashboard --register out/register.json
```

- `/#/` — وضعیت فعلی، فیلتر شدت/ابزار، تریاژ با کلیک
- `/#/scans` — تاریخچه‌ی همه‌ی اجراها + Δ
- `/#/scans?id=<run_id>` — یافته‌های همان اجرا، موتورها، شکاف‌ها

خروجی‌ها: `out/report.md`، `findings.sarif`، `coverage.json`، `out/scans/<run_id>/`.

## ۷. تریاژ

```powershell
janus triage --agent codex --repo . --out out/triage.md
```

## ۸. CI

فقط موتور کد؛ recon را در پایپ‌لاین مشترک نگذار.

```yaml
janus-code:
  script: [janus scan code --scope scope.toml --out out --fail-on high]
  artifacts: { when: always, paths: [out/] }
```

`1` = یافته، `2` = scope خراب. جزئیات: [CI.md](CI.md).

## امنیت

فقط دارایی خودت؛ `deny` را جدی بگیر. ابزار پیش‌فرض GET-only است. گزارش‌ها secret
را ماسک می‌کنند، ولی قبل از اشتراک یک نگاه بینداز. برای lab: `allow_private_targets = true`.
