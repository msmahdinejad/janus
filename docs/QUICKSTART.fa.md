# راهنمای کوتاه (حالت دستی)

برای وقتی که خودت بدون ایجنت راه می‌اندازی. ۱۰ دقیقه.

## ۱. نصب

```powershell
cd janus
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q        # باید همه سبز باشند
```

## ۲. ابزارهای اختیاری (هرکدام را داشتی، بهتر)

```powershell
# gitleaks و trivy: zip ویندوز از GitHub Releases را در .tools/bin باز کن
uv tool install semgrep --python 3.11
$env:TRIVY_DB_REPOSITORY="ghcr.io/aquasecurity/trivy-db:2"
```

`janus doctor --tools-dir .tools/bin` می‌گوید چه چیزی داری و چه چیزی `skipped`
خواهد شد.

## ۳. scope بساز

```powershell
janus init --dir my-scan --interactive
# یا دستی: my-scan/scope.toml را از scope.example.toml کپی و ویرایش کن
```

حداقل: `allow` (دامنه‌های مجاز)، `deny` (ممنوع‌ها)، `reference` (برچسب یا شناسه‌ی
خوداظهاری اجرای تیم)،
`[code].roots` (مسیر ریپو). برای پورت غیر ۴۴۳ از `seeds` استفاده کن.

## ۴. کلید مدل (فقط برای ایجنت)

```powershell
$env:OPENAI_API_KEY = "<key>"       # یا DEEPSEEK_API_KEY / GLM_API_KEY / OPENROUTER_API_KEY
janus doctor --check-models
```

اگر گیت‌وی داخلی شما فقط Chat Completions دارد، همان profile را در
`providers.toml` نگه دارید. برای endpointهای Responses API، مقدار
`api_format = "responses"` را در profile تنظیم کنید؛ کلید همیشه در environment
می‌ماند و داخل scope یا گزارش نوشته نمی‌شود.

## ۵. اسکن

```powershell
# فقط کد
janus scan code  --scope my-scan/scope.toml --out my-scan/out

# سطح خارجی، بدون ایجنت
janus scan recon --scope my-scan/scope.toml --out my-scan/out --mode passive

# کامل (کد + پسیو + nuclei + ایجنت)
janus scan all --scope my-scan/scope.toml --out my-scan/out --mode agent --lens all `
  --agent-providers deepseek --fail-on none
```

### مسیر نوشتنی (اختیاری، فقط staging)

اگر endpointهای نوشتنی را لیست کنی، سه بررسی قطعی اجرا می‌شود:

```toml
[limits]
allow_state_changing   = true
mutating_methods       = ["POST"]
require_nonprod_marker = true

[[write.targets]]
url = "https://staging.example.com/api/orders"
method = "POST"
body = { product_id = 1, qty = 1 }
```

`WRITE-UNAUTH` (critical)، `WRITE-MASS-ASSIGN` (high)، `WRITE-VERB-TAMPER`
(medium). فقط همان URLها لمس می‌شوند و `DELETE` هرگز مجاز نیست.

## ۶. دیدن نتایج

```powershell
janus dashboard --register my-scan/out/register.json
```

- `http://127.0.0.1:8787/#/` → وضعیت فعلی، فیلتر شدت/ابزار، کلیک روی ردیف برای
  تریاژ (open / fixed / ruled-out).
- `http://127.0.0.1:8787/#/scans` → تاریخچه‌ی همه‌ی اجراها، با Δ نسبت به اجرای
  قبلی هم‌نوع.
- `http://127.0.0.1:8787/#/scans?id=<run_id>` → یافته‌های همان اجرا + وضعیت
  موتورها + شکاف‌های پوشش + لینک report و SARIF.

## ۷. فایل‌های خروجی

```
my-scan/out/
├── register.json          وضعیت ادغام‌شده (منبع حقیقت داشبورد)
├── report.md              گزارش خوانا + بخش Coverage
├── findings.sarif         برای GitLab/GitHub code scanning
├── coverage.json          چه چیزی تست شد / چه چیزی نه
└── scans/<run_id>/        تاریخچه‌ی هر اجرا (پاک نمی‌شود)
```

## ۸. اجرا در CI (اختیاری)

فقط موتور کد را در CI بگذار، نه recon را:

```yaml
janus-code:
  script:
    - janus scan code --scope scope.toml --out out --fail-on high
  artifacts:
    when: always
    paths: [out/]
```

`1` یعنی یافته‌ی بالای آستانه، `2` یعنی scope خراب است (نه یافته). نمونه‌ی کامل
GitLab/GitHub و توضیح `--diff` و `TRIVY_DB_REPOSITORY` در [CI.md](CI.md).

## نکته‌های امنیتی

- فقط دارایی خودت؛ `deny` را جدی بگیر.
- ابزار فقط GET/HEAD/OPTIONS می‌فرستد مگر `allow_state_changing` را روشن کنی.
- گزارش‌ها secret را ماسک می‌کنند، ولی قبل از اشتراک‌گذاری یک نگاه بینداز.
- برای اهداف محلی: `allow_private_targets = true` و سرور روی `0.0.0.0`.
