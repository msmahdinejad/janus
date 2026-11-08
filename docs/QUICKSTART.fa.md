# راهنمای شروع Janus برای کارکنان ترب

این راهنما برای اجرای دستی روی Windows، Linux و macOS است. اگر می‌خواهی ایجنت
همه مراحل را انجام بدهد، فایل prompts/torob-agent-setup.fa.md را به آن بده.

Janus دو کار جدا انجام می‌دهد:

- code: خواندن repo و اجرای قواعد داخلی، Semgrep، Gitleaks، Trivy و ابزارهای
  IaC/secret در صورت نصب؛ بدون درخواست به سرویس زنده.
- recon: بررسی deployment داخل scope با discovery، header و cookie، CORS،
  مسیرهای حساس، JavaScript و sourcemap، fingerprint، SPF/DMARC، nuclei و
  agentهای اختیاری.

هر اجرا یک register مشترک، report.md، findings.json، findings.sarif و
coverage.json می‌نویسد. coverage را همیشه بخوان؛ skipped یا failed یعنی آن
بخش تست نشده و «۰ یافته» به‌تنهایی clean بودن را ثابت نمی‌کند.

## ۱. نصب و بررسی ابزارها

Python باید 3.11 یا بالاتر باشد. در ریشه‌ی Janus یکی از این دو بلوک را اجرا
کن و بعد virtualenv را فعال نگه دار:

~~~powershell
cd D:/Janus
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
pytest -q
~~~

~~~bash
cd /path/to/janus
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest -q
~~~

بعد از فعال‌سازی، همه‌ی دستورهای این راهنما با خود command janus اجرا می‌شوند:

~~~text
janus doctor --tools-dir .tools/bin
~~~

doctor وضعیت semgrep، gitleaks، trivy،
nuclei، subfinder، strix، docker و CLIهای Codex/Claude را نشان می‌دهد. نبودن
ابزار مانع code یا passive نمی‌شود، اما در coverage به‌عنوان skipped می‌آید.

برای نصب Semgrep، Python 3.11 را به uv بده. اگر Trivy نتوانست CVE
database را از mirror بگیرد:

~~~powershell
uv tool install semgrep --python 3.11
$env:TRIVY_DB_REPOSITORY = "ghcr.io/aquasecurity/trivy-db:2"
~~~

~~~bash
uv tool install semgrep --python 3.11
export TRIVY_DB_REPOSITORY="ghcr.io/aquasecurity/trivy-db:2"
~~~

--offline دانلود CVE را متوقف می‌کند و SCA را محدود می‌گذارد؛ secret و
misconfiguration را با همین محدودیت اجرا کن، نه اینکه نتیجه را clean فرض کنی.

## ۲. ساخت scope.toml

برای دیدن داشبورد بدون نصب ابزار و بدون target واقعی، از داده‌ی ساختگی demo
استفاده کن:

~~~powershell
janus demo --out examples/demo-fixture/out
~~~

این خروجی درباره یک شرکت خیالی است و نباید با نتیجه‌ی engagement واقعی قاطی
شود.

scope هم برای code لازم است و هم برای recon. wizard:

~~~powershell
janus init --dir engagements/<name> --interactive
~~~

یا scope.example.toml را کپی و ویرایش کن. این موارد را دقیق بنویس:

- code roots و excludeها؛
- hostهای recon در targets.allow؛
- denyهای صریح، allow_ports، seedهای URL کامل و forbidden_paths؛
- نام engagement، authorized_by، reference و بازه اعتبار؛
- max_rps، max_requests و max_seconds؛
- برای active: allow_active_recon=true؛
- برای agent: allow_agent=true؛
- برای lab محلی: allow_private_targets=true.

authorized_by و reference فقط برچسب audit خوداظهاری‌اند و شماره تیکت اجباری
نیست. target را از روی حدس وارد نکن. janus discover فقط candidate می‌دهد:

~~~powershell
janus discover --repo <repo-path> --owned <domain-1>,<domain-2> --write-scope engagements/<name>/scope.draft.toml
~~~

draft را بازبینی کن و بعد به scope.toml تبدیل کن. wildcard، apex را شامل
نمی‌شود؛ برای پورت غیر 443 از seed مثل https://staging.example.com:8443
استفاده کن. قبل از recon فایل را یک‌بار کامل بخوان.

## ۳. سه مدل ترب

برای Janus سه profile جدا لازم است:

| نقش | مسیر | تنظیم wire |
|---|---|---|
| DeepSeek | LiteLLM در https://litellm.torob.ir/v1 | chat completions |
| GLM | ai-sub در https://ai-sub.torob.dev | Responses API |
| GPT/Codex | ai-sub در https://ai-sub.torob.dev | Responses API |

از providers.torob.toml داخلی تیم استفاده کن. اگر profileهای GLM و GPT روی
LiteLLM بودند، یک providers.torob.local.toml خارج از git بساز و آن‌ها را روی
ai-sub بگذار. نمونه:

این سه profile برای agent داخل خود Janus هستند. دستورهای review و triage که
پایین‌تر می‌بینی از CLI جداگانه‌ی Codex یا Claude استفاده می‌کنند و این profile
ها را مصرف نمی‌کنند.

~~~toml
[providers.torob-deepseek]
base_url = "https://litellm.torob.ir/v1"
model = "openrouter/deepseek/deepseek-v4.1-flash-1017"
api_key_env = "TOROB_LITELLM_KEY"
api_format = "chat_completions"
transport = "urllib"

[providers.torob-glm-aisub]
base_url = "https://ai-sub.torob.dev"
model = "glm-5.3"
api_key_env = "TOROB_LITELLM_KEY"
api_format = "responses"

[providers.torob-codex-aisub]
base_url = "https://ai-sub.torob.dev"
model = "gpt-6-astra"
api_key_env = "TOROB_LITELLM_KEY"
api_format = "responses"
~~~

مدل‌ها را از account خودت با doctor چک کن؛ این idها تضمین دسترسی نیستند:

~~~powershell
$env:TOROB_LITELLM_KEY = Read-Host "Torob model key"
janus doctor --providers-file providers.torob.local.toml --check-models
~~~

~~~bash
read -r -s TOROB_LITELLM_KEY
export TOROB_LITELLM_KEY
janus doctor --providers-file providers.torob.local.toml --check-models
~~~

برای هر سه profile باید key set و reachable=yes ببینی. key را در فایل، chat
یا report ننویس. ai-sub روی chat/completions پاسخ نمی‌دهد. اگر LiteLLM با
httpx خطای TLS داد، janus llm-shim را روی 18081 اجرا کن و فقط base_url
DeepSeek را به http://127.0.0.1:18081/v1 تغییر بده. 127.0.0.1 آدرس شیم است.

~~~text
janus llm-shim --port 18081 --upstream https://litellm.torob.ir/v1 --api-key-env TOROB_LITELLM_KEY
~~~

## ۴. سه سطح اسکن

### فقط کد

~~~powershell
janus scan code --scope engagements/<name>/scope.toml --out engagements/<name>/out --tools-dir .tools/bin --fail-on high
~~~

--diff BASE_REF فقط فایل‌های تغییرکرده را می‌خواند و اگر root git نباشد با
هشدار full scan می‌کند. --baseline FILE یافته‌های accepted-risk را از fail
شدن CI کنار می‌گذارد. برای حذف عمدی adapter از --no-semgrep، --no-gitleaks یا
--no-trivy استفاده کن. --cache و --offline هم در دسترس‌اند.

### recon پسیو

~~~powershell
janus scan recon --scope engagements/<name>/scope.toml --out engagements/<name>/out --mode passive --tools-dir .tools/bin
~~~

passive هم ترافیک واقعی دارد، اما بررسی‌های معمول آن GET/HEAD/OPTIONS و داخل
budget scope هستند. discovery، DNS/CT، header/cookie، CORS، مسیرهای حساس،
JS/sourcemap، fingerprint و SPF/DMARC را پوشش می‌دهد.

### active با nuclei

در scope، allow_active_recon را true کن و بعد:

~~~powershell
janus scan recon --scope engagements/<name>/scope.toml --out engagements/<name>/out --mode active --rate-limit 10 --nuclei-templates .tools/nuclei-templates --tools-dir .tools/bin
~~~

بدون opt-in داخل scope، active با خطای scope و exit code 2 متوقف می‌شود.

### agent با سه مدل

در scope هم allow_active_recon و هم allow_agent را true کن:

~~~powershell
janus scan all --scope engagements/<name>/scope.toml --out engagements/<name>/out --mode agent --agent-backend native --lens all --agent-providers torob-deepseek,torob-glm-aisub,torob-codex-aisub --providers-file providers.torob.local.toml --agent-max-turns 25 --agent-max-budget 2 --fail-on none --tools-dir .tools/bin
~~~

lens all شامل authz، authn، injection، secrets، business، files، client،
write و infra است. برای اجرای agent بدون passive قبلی --skip-passive را اضافه
کن. هر provider که key نداشته باشد skipped می‌شود و در coverage می‌آید.

Strix به Docker و proxy allowlist نیاز دارد:

~~~powershell
janus proxy --scope engagements/<name>/scope.toml --port 8899
$env:JANUS_AGENT_PROXY = "http://127.0.0.1:8899"
janus scan recon --scope engagements/<name>/scope.toml --out engagements/<name>/out-strix --mode agent --agent-backend strix --skip-passive --agent-providers torob-deepseek --providers-file providers.torob.local.toml
~~~

~~~bash
janus proxy --scope engagements/<name>/scope.toml --port 8899
export JANUS_AGENT_PROXY="http://127.0.0.1:8899"
janus scan recon --scope engagements/<name>/scope.toml --out engagements/<name>/out-strix --mode agent --agent-backend strix --skip-passive --agent-providers torob-deepseek --providers-file providers.torob.local.toml
~~~

native داخل Janus با ScopeClient کار می‌کند. Strix خارجی است و باید از proxy
عبور کند. برای هدف lab روی همین ماشین، سرویس را روی 0.0.0.0 باز کن؛ برای
staging اینترنتی این کار لازم نیست. آدرس مدل را از target جدا نگه دار و host
مدل را در NO_PROXY بگذار.

## ۵. write-path روی staging

این بخش اختیاری است و فقط endpointهای فهرست‌شده را لمس می‌کند:

~~~toml
[limits]
allow_state_changing = true
mutating_methods = ["POST"]
require_nonprod_marker = true

[[write.targets]]
url = "https://staging.example.com/api/orders"
method = "POST"
body = { product_id = 1, qty = 1 }
expect_auth = true

[write]
mass_assignment_fields = ["role", "owner_id", "price", "is_staff", "approved"]
~~~

سه check قطعی:

- WRITE-UNAUTH: endpointی که باید auth بخواهد anonymous دوصد برگرداند؛
- WRITE-MASS-ASSIGN: field ممتاز پذیرفته یا در response بازتاب شود؛
- WRITE-VERB-TAMPER: مسیر نوشتنی با method امن هم رفتار مشابه نشان دهد.

DELETE هرگز مجاز نیست و Janus چیزی را پاک نمی‌کند. رکورد ساختگی‌ای که ساخته
می‌شود با تیم تست است که cleanup شود. write check فقط در recon active/agent
و scan all همان modeها اجرا می‌شود.

## ۶. review، triage و گزارش

برای review عمیق سورس:

~~~powershell
janus review code --repo <repo-path> --agent codex --lens authz,authn,injection,secrets,business,files,client,infra --out engagements/<name>/out/review --timeout 1800
~~~

این review فقط‌خواندنی است و finding را با file:line می‌دهد. برای triage
یافته‌های high/critical:

~~~powershell
janus triage --agent codex --repo <repo-path> --out engagements/<name>/out/triage-report.md --timeout 1800
~~~

برای بازسازی گزارش:

~~~powershell
janus report --register engagements/<name>/out/register.json --out engagements/<name>/out
~~~

نبودن Codex یا Claude باید skipped گزارش شود.

اگر فقط register داری و reportها حذف شده‌اند، همین report command آن‌ها را
دوباره می‌سازد. برای خروجی dashboard بدون بازکردن مرورگر از --no-open استفاده
کن.

## ۷. داشبورد و فایل‌ها

~~~powershell
janus dashboard --register engagements/<name>/out/register.json --port 8787
~~~

- http://127.0.0.1:8787/#/ وضعیت فعلی و triage؛
- http://127.0.0.1:8787/#/scans تاریخچه، فیلتر بر اساس engagement و نوع اجرا،
  مرتب‌سازی بر اساس جدیدترین/بیشترین یافته/بیشترین یافته‌ی جدید، و Δ هم‌نوع؛
- http://127.0.0.1:8787/#/scans?id=<run_id> جزئیات findingها با فیلتر severity،
  tool، confidence و status، جدول وضعیت engineها، coverage gap، مقایسه با اجرای
  قبلی و لینک report/SARIF.

در صفحه اصلی می‌توانی findingها را جست‌وجو و triage کنی. برای رفتن به تاریخچه
از میانبر g سپس s استفاده کن؛ بازکردن یک finding با صفحه‌کلید نباید جای اسکرول
را از بین ببرد.

در out این‌ها را نگه دار: register.json، report.md، findings.json،
findings.sarif، coverage.json و scans/<run_id>/. dashboard local است، build
step و telemetry ندارد. bind غیرلوپ‌بک به --allow-remote و --token نیاز دارد.

## ۸. معنی خروجی و exit code

قبل از گفتن «clean»، coverage.json و status ابزارها را بخوان. وضعیت‌ها:

- ok: ابزار واقعاً اجرا شده؛
- skipped: عمداً، به‌دلیل نبودن ابزار/key یا گزینه؛
- failed: اجرا شروع شده اما خطا داده؛
- partial: agent به turn/budget رسیده و نتیجه کامل نیست.

exit code صفر یعنی finding فعال بالاتر از fail-on نیست، یک یعنی هست، و دو یعنی
scope/config خراب، منقضی یا خاموش است. تعداد یافته‌ها را با severity و tool
گزارش کن و سه مورد مهم را بدون secret توضیح بده.

برای CI معمولاً فقط scan code را بگذار. recon را از runner مشترک اجرا نکن مگر
scope و مسیر اجرا را جداگانه بررسی کرده باشی:

~~~yaml
janus-code:
  script:
    - janus scan code --scope scope.toml --out out --fail-on high
  artifacts:
    when: always
    paths: [out/]
~~~

## خطاهای رایج

- Trivy 403: TRIVY_DB_REPOSITORY یا --offline و ذکر محدودیت SCA.
- semgrep نصب نشد: Python 3.11 یا --no-semgrep و ثبت gap.
- LiteLLM TLS: janus llm-shim.
- ai-sub روی chat 404 داد: GLM و GPT باید api_format=responses داشته باشند.
- reachable=NO: model id واقعی /models را در profile بگذار.
- Strix 405: host مدل از proxy عبور کرده؛ NO_PROXY را تنظیم کن.
- Strix connection error: آدرس مدل برای process درست نیست؛ shim میزبان را
  استفاده کن.
- متن فارسی console خراب است: PYTHONIOENCODING=utf-8.

برای اسکن واقعی باید scope دقیق داشته باشی. هیچ نتیجه‌ای را که اجرا نشده
گزارش نکن.
