# v2ray-new-version

**A deployment blueprint for a multi-source VPN subscription aggregator and a portable v2rayN client.**

این مخزن، راهنمای استقرار یک تجمیع‌کننده چندمنبعی اشتراک و کلاینت قابل‌حمل v2rayN است.

> **Repository status / وضعیت مخزن:** The documented aggregation pipeline is implemented in this repository: `scripts/aggregate.py`, `config/sources.json`, the GitHub Actions workflow, and a stdlib test suite are present. The configured upstream source currently returns HTTP 404, so no generated feeds are committed yet; a failed run never replaces existing output. The v2rayN application source/build output is **not** included here.
>
> **وضعیت مخزن:** خط لوله تجمیع شرح‌داده‌شده در این مخزن پیاده‌سازی شده است: `scripts/aggregate.py`، `config/sources.json`، گردش‌کار GitHub Actions و مجموعه آزمون مبتنی بر کتابخانه استاندارد موجود هستند. منبع بالادستی پیکربندی‌شده در حال حاضر HTTP 404 برمی‌گرداند، بنابراین هنوز فید تولیدشده‌ای commit نشده است؛ اجرای ناموفق هرگز خروجی قبلی را جایگزین نمی‌کند. کد/خروجی ساخت v2rayN در این مخزن وجود ندارد.

## Contents

- [English](#english)
- [فارسی](#راهنمای-فارسی)

---

## English

### Overview

The target deployment has two parts:

1. A Python 3.12 job collects configured subscription sources, normalizes and deduplicates node URIs, applies best-effort country labels, performs an optional TCP reachability check, and publishes plain-text subscription feeds plus a JSON manifest.
2. A Windows x64 portable package of v2rayN seeds a subscription record into v2rayN's SQLite-backed configuration and refreshes it asynchronously. A previously validated snapshot remains available when the network or a source is unavailable.

The initial configured input is:

```text
https://raw.githubusercontent.com/luke-wilsonio96i3/Free-VPN-Config-Pack-2026/main/sub_base64.txt
```

Only add other upstreams after reviewing and explicitly configuring them. Do not assume that a public feed is stable, safe, or operated by this project.

### Target repository layout

The aggregation files below are implemented; `data/` appears only after a successful run. The v2rayN application source/build output remains outside this repository.

```text
.
├── .github/
│   └── workflows/
│       └── update-subscriptions.yml
├── config/
│   └── sources.json
├── data/
│   ├── manifest.json
│   └── subscriptions/
│       ├── global.txt
│       ├── de.txt
│       ├── us.txt
│       ├── nl.txt
│       ├── tr.txt
│       ├── fr.txt
│       ├── uk.txt
│       └── ca.txt
├── scripts/
│   └── aggregate.py
└── README.md
```

Keep generated subscriptions separate from source configuration. The workflow should publish only the reviewed output files; never commit credentials, private keys, or personal subscription tokens.

### Aggregation behavior

The Python 3.12 aggregator should:

1. Read an explicit source list, starting with the URL above. Fetch sources over HTTPS with bounded timeouts and response-size limits.
2. Decode a source as strict UTF-8, then recognize either newline-separated proxy URIs or a Base64-encoded subscription payload. Reject malformed input rather than silently emitting a partial result.
3. Validate supported URI schemes, normalize line endings, remove blank/comment lines, and deduplicate identical node URIs while preserving useful names.
4. Assign a best-effort country label using available node remarks and hostname hints. Support `DE`, `US`, `NL`, `TR`, `FR`, `UK`, `CA`, and `GLOBAL`; use `GLOBAL` for unknown or unclassified nodes. Country assignment is heuristic, not verified geolocation.
5. Optionally test the endpoint's TCP connection with a short timeout. A TCP connection only says that a port accepted a connection at that moment; it does not validate a V2Ray handshake, authentication, TLS, routing, or end-to-end proxy traffic.
6. Write `global.txt` and country-specific text feeds in the URI format accepted by v2rayN. Write to temporary files first and replace final outputs only after the entire run succeeds. Keep a last-known-good snapshot for client-side offline use.
7. Produce a manifest for observability and QA. Do not put secrets or credentials in it.

Example source configuration:

```json
{
  "version": 1,
  "sources": [
    {
      "id": "free-vpn-config-pack-2026",
      "url": "https://raw.githubusercontent.com/luke-wilsonio96i3/Free-VPN-Config-Pack-2026/main/sub_base64.txt",
      "enabled": true
    }
  ]
}
```

Example generated manifest (the sample counts, timestamp, and output URL are illustrative):

```json
{
  "version": 1,
  "generated_at_utc": "2026-01-01T00:00:00Z",
  "source_count": 1,
  "node_count": 42,
  "feeds": {
    "GLOBAL": "subscriptions/global.txt",
    "DE": "subscriptions/de.txt",
    "US": "subscriptions/us.txt",
    "NL": "subscriptions/nl.txt",
    "TR": "subscriptions/tr.txt",
    "FR": "subscriptions/fr.txt",
    "UK": "subscriptions/uk.txt",
    "CA": "subscriptions/ca.txt"
  }
}
```

The manifest is descriptive JSON, **not** a subscription URL. Point v2rayN at the published raw-text feed, for example:

```text
https://raw.githubusercontent.com/<OWNER>/<REPOSITORY>/<BRANCH>/data/subscriptions/global.txt
```

Replace the placeholders with the repository and branch that actually host the generated feed. Do not use this template URL as-is.

### Running the aggregator

The implementation uses only the Python 3.12 standard library.

```bash
python3 -m unittest discover -s tests -v
python3 scripts/aggregate.py --config config/sources.json --output-dir data
```

Options: `--timeout` (per-request seconds, default 15), `--max-bytes` (per-source
limit, default 5 MiB), `--tcp-check` (best-effort TCP probe), `--tcp-timeout`,
`--require-reachable` (drop nodes that fail the probe), and `--verbose`.

A successful run writes `data/subscriptions/*.txt`, `data/snapshot/global.txt`,
and `data/manifest.json`. Files are staged first and published only after every
enabled source was fetched and validated, so a failed run leaves the previous
feeds and snapshot untouched. The process exits non-zero on any failure.

### GitHub Actions deployment

The workflow source is kept at [`ci/update-subscriptions.yml`](ci/update-subscriptions.yml).
Copy it to `.github/workflows/update-subscriptions.yml` (or add it through the
GitHub web UI) to enable scheduled runs; automation integrations that lack the
`workflows` permission cannot publish files under `.github/workflows/` directly.
It is configured to:

- Run on a modest schedule (for example, every six hours) and support `workflow_dispatch` for manual runs.
- Use `actions/checkout`, set up **Python 3.12**, install only pinned/required dependencies, and run the aggregator with a non-zero exit code on failure.
- Grant only the permissions it needs. If it commits generated feeds, limit write access to repository contents and commit only when outputs changed.
- Avoid publishing partial results after a failed fetch/parse. Retain the previous known-good output if a run fails.
- Keep logs free of subscription contents, credentials, and tokens. Review the generated diff before enabling unattended publication.

Scheduled workflows run from the repository's default branch. The scheduled job and published feed do not exist until their implementation and workflow are added.

### v2rayN integration and refresh

Use the upstream v2rayN architecture rather than writing directly to an undocumented database schema:

- `ServiceLib.Models.Entities.SubItem` is the subscription entity. Its fields include `Id`, `Remarks`, `Url`, `Enabled`, `Sort`, and `AutoUpdateInterval`.
- v2rayN uses its own SQLite-backed configuration/data layer. Seed through that application's supported data-access/service path, and make the seed idempotent (for example, check a stable `Id` before inserting). Do not replace or edit a live SQLite database by hand.
- In the cited upstream implementation, `AutoUpdateInterval` is measured in minutes; a value greater than zero participates in v2rayN's periodic subscription update task. Re-check this behavior in the exact version being packaged.
- The current subscription flow is `SubscriptionHandler.UpdateProcess(Config config, string subId, bool blProxy, Func<bool, string, Task> updateFunc)`. Integrate through the application’s existing handler/parser and UI notification path instead of introducing a second, incompatible node parser.
- Keep refresh asynchronous and away from the UI thread. For a custom fetch path, enforce **15 seconds per attempt, at most 2 attempts, a 5 MiB maximum response, and strict UTF-8 decoding**. Validate the complete response before importing it. Do not assume the stock downloader enforces these exact limits without checking the pinned source version.
- On timeout, invalid UTF-8, oversized/empty content, or parse failure, retain the last-known-good subscription/nodes and offline snapshot. Update the snapshot only after a successful validation/import; do not replace working data with an empty or truncated feed.
- Set `SysProxyType = 2` only if the intended behavior is to leave the operating-system proxy setting unchanged. In the current upstream enum, value `2` is `ESysProxyType.Unchanged`—it does **not** enable or force the system proxy. Verify this setting in the UI and on the target Windows image.

Illustrative `SubItem` seed values (persist them through the application's data-access layer, not as a standalone SQL statement):

```csharp
var seed = new SubItem
{
    Id = "community-feed-global",
    Remarks = "Community feed - Global",
    Url = "https://raw.githubusercontent.com/<OWNER>/<REPOSITORY>/<BRANCH>/data/subscriptions/global.txt",
    Enabled = true,
    Sort = 100,
    AutoUpdateInterval = 360
};
```

The URL is a deployment placeholder. In the cited upstream version, `360` means a six-hour update interval; confirm the behavior in the pinned version before relying on it. Seed country feeds as separate records only if users need them independently; otherwise prefer the global feed.

Architecture references checked against upstream v2rayN commit [`1883178`](https://github.com/2dust/v2rayN/tree/1883178b5f1e222b6c6db2782e7a3d989b7cc18f):

- [`SubItem.cs`](https://github.com/2dust/v2rayN/blob/1883178b5f1e222b6c6db2782e7a3d989b7cc18f/v2rayN/ServiceLib/Models/Entities/SubItem.cs)
- [`SubscriptionHandler.cs`](https://github.com/2dust/v2rayN/blob/1883178b5f1e222b6c6db2782e7a3d989b7cc18f/v2rayN/ServiceLib/Handler/SubscriptionHandler.cs)
- [`ESysProxyType.cs`](https://github.com/2dust/v2rayN/blob/1883178b5f1e222b6c6db2782e7a3d989b7cc18f/v2rayN/ServiceLib/Enums/ESysProxyType.cs)
- [`Directory.Build.props`](https://github.com/2dust/v2rayN/blob/1883178b5f1e222b6c6db2782e7a3d989b7cc18f/v2rayN/Directory.Build.props)

Pin and review the upstream v2rayN release/commit that you actually build; re-check its APIs and target framework before applying these notes to another version.

### Build and publish (Windows x64)

Install the .NET 10 SDK and obtain a reviewed/pinned v2rayN source checkout. Run the following **from the root of that v2rayN checkout**:

```powershell
dotnet publish .\v2rayN\v2rayN.Desktop\v2rayN.Desktop.csproj -c Release -r win-x64 --self-contained true -o .\artifacts\publish\win-x64
```

The upstream project targets `net10.0`; the Release build settings at the cited revision enable single-file publishing. The command above publishes a self-contained Windows x64 build into `artifacts\publish\win-x64`. Confirm the project path, SDK, release notes, and license obligations for the exact upstream revision you selected. This command cannot run from the current documentation-only checkout because it does not contain the v2rayN source project.

### Portable packaging

Assemble a fresh staging directory and copy the **entire** publish output before adding portable data:

```text
v2rayN-Portable/
├── v2rayN.exe                 # plus any sidecar files from publish output
├── guiConfigs/                # v2rayN-created settings and SQLite-backed data
├── subscriptions/
│   ├── snapshot/
│   │   └── global.txt         # last-known-good offline feed
│   └── manifest.json
└── logs/                      # optional; do not package secrets or stale logs
```

`guiConfigs` is v2rayN's application configuration directory at the cited upstream revision. Let v2rayN create and migrate its own configuration and database files on first launch. If the chosen release uses a different configuration location or portable-mode behavior, follow that release's documentation; verify that settings remain inside the package and do not silently fall back to a user's roaming profile. Never overwrite a user's existing `guiConfigs` while upgrading: back it up and preserve its database.

For a clean package, copy the publish output, create the data directories, seed the subscription once through the app's data layer, and test the copied package from a different directory or clean Windows account. Do not ship source feed files or database contents containing credentials unless deliberately reviewed.

### Online and offline QA

Before distributing a package, verify:

1. The workflow can be run manually, fetches every enabled source within its limits, and fails without replacing the previous generated feeds when a source is malformed or unavailable.
2. Each text feed is non-empty when expected, strict UTF-8, has no duplicate URI lines, and can be imported by the pinned v2rayN build. The country files are heuristic subsets; `global.txt` should include the complete accepted set.
3. First launch creates the expected `guiConfigs` data locally. The seed appears once after repeated launches, and refresh is asynchronous without freezing the UI.
4. Online refresh succeeds and replaces the snapshot only after a valid import. With network access disabled, refresh reports a visible error while the previously imported nodes and snapshot remain usable.
5. Timeout, 5 MiB limit, invalid UTF-8, empty payload, and parse-failure cases preserve the last-known-good state.
6. With `SysProxyType = 2`, the app leaves the Windows proxy setting unchanged. Check before and after launch; do not infer the setting from a successful TCP test.
7. A TCP reachability result is treated only as a basic endpoint check—not as proof that the node can establish a working proxy tunnel.

### Security and reliability notes

- Subscription sources and the nodes they advertise are **untrusted**. Review source ownership, avoid entering credentials into unknown nodes, and assume endpoints can observe traffic that is not protected end-to-end by the application protocol and destination TLS.
- Public nodes may be malicious, overloaded, misconfigured, or expire without notice. Country labels and TCP reachability are best-effort hints, not guarantees of location, privacy, uptime, or usable proxy service.
- Never commit account tokens, private subscription URLs, authentication headers, or user databases. A public GitHub feed is public to anyone who can access the repository.
- Use the project's licensing and attribution requirements when redistributing v2rayN or derived packages.

---

## راهنمای فارسی

### معرفی

طرح استقرار از دو بخش تشکیل می‌شود:

1. یک پردازشگر با Python 3.12 منابع اشتراک پیکربندی‌شده را دریافت می‌کند، URIها را پاک‌سازی و تکراری‌ها را حذف می‌کند، برچسب کشورِ تقریبی می‌زند، در صورت نیاز دسترسی TCP را می‌سنجد و فید متنی و مانیفست JSON می‌سازد.
2. بسته قابل‌حمل Windows x64 از v2rayN یک اشتراک را در پیکربندی مبتنی بر SQLite برنامه ثبت می‌کند و آن را به‌صورت غیرهم‌زمان به‌روزرسانی می‌کند. در صورت قطع شبکه یا خرابی منبع، آخرین نسخه معتبر باید باقی بماند.

منبع اولیه پیکربندی‌شده:

```text
https://raw.githubusercontent.com/luke-wilsonio96i3/Free-VPN-Config-Pack-2026/main/sub_base64.txt
```

منابع دیگر را فقط پس از بررسی و افزودن صریح در پیکربندی وارد کنید. عمومی‌بودن فید به معنی پایدار، امن یا تحت مدیریت این پروژه بودن آن نیست.

### چیدمان پیشنهادی مخزن

ساختار زیر طرح پیشنهادی است؛ فایل‌های آن در این نسخه مستندمحور وجود ندارند.

```text
.
├── .github/
│   └── workflows/
│       └── update-subscriptions.yml
├── config/
│   └── sources.json
├── data/
│   ├── manifest.json
│   └── subscriptions/
│       ├── global.txt
│       ├── de.txt
│       ├── us.txt
│       ├── nl.txt
│       ├── tr.txt
│       ├── fr.txt
│       ├── uk.txt
│       └── ca.txt
├── scripts/
│   └── aggregate.py
└── README.md
```

فایل‌های تولیدشده را از پیکربندی منابع جدا نگه دارید. گردش‌کار فقط خروجی‌های بررسی‌شده را منتشر کند؛ اعتبارنامه، کلید خصوصی یا توکن اشتراک شخصی را commit نکنید.

### رفتار تجمیع‌کننده

تجمیع‌کننده Python 3.12 باید:

1. فهرست منابع صریح را بخواند و با URL بالا شروع کند. دریافت HTTPS باید timeout و محدودیت اندازه پاسخ داشته باشد.
2. پاسخ را با UTF-8 سخت‌گیرانه بخواند و سپس URIهای پراکسیِ خط‌به‌خط یا محتوای Base64 اشتراک را تشخیص دهد. ورودی خراب را رد کند و خروجی ناقص را بی‌صدا منتشر نکند.
3. schemeهای پشتیبانی‌شده را اعتبارسنجی کند، پایان‌خط‌ها را یکسان کند، خط خالی/توضیح را حذف کند و URIهای یکسان را بدون از دست‌دادن نام مفید حذف تکراری کند.
4. با استفاده از نام گره و نشانه‌های نام میزبان، برچسب تقریبی کشور تعیین کند. کدهای `DE`، `US`، `NL`، `TR`، `FR`، `UK`، `CA` و `GLOBAL` پشتیبانی شوند؛ گره نامشخص در `GLOBAL` قرار گیرد. برچسب کشور، مکان‌یابی تأییدشده نیست.
5. در صورت نیاز اتصال TCP به endpoint را با timeout کوتاه بررسی کند. اتصال TCP فقط پذیرش اتصال به یک پورت را در همان لحظه نشان می‌دهد؛ handshake وی‌تو‌ری، احراز هویت، TLS، مسیریابی یا ترافیک سرتاسری پراکسی را تأیید نمی‌کند.
6. فید متنی `global.txt` و فیدهای کشور را با URIهای قابل‌قبول v2rayN بسازد. ابتدا در فایل موقت بنویسد و فقط پس از موفقیت کل فرایند، خروجی نهایی را جایگزین کند. snapshot معتبر قبلی را برای استفاده آفلاین کلاینت نگه دارد.
7. برای مشاهده‌پذیری و QA مانیفست تولید کند؛ هیچ راز یا اعتبارنامه‌ای در آن قرار ندهد.

نمونه پیکربندی منابع:

```json
{
  "version": 1,
  "sources": [
    {
      "id": "free-vpn-config-pack-2026",
      "url": "https://raw.githubusercontent.com/luke-wilsonio96i3/Free-VPN-Config-Pack-2026/main/sub_base64.txt",
      "enabled": true
    }
  ]
}
```

نمونه مانیفست تولیدشده (تعداد، زمان و مسیرها صرفاً نمونه‌اند):

```json
{
  "version": 1,
  "generated_at_utc": "2026-01-01T00:00:00Z",
  "source_count": 1,
  "node_count": 42,
  "feeds": {
    "GLOBAL": "subscriptions/global.txt",
    "DE": "subscriptions/de.txt",
    "US": "subscriptions/us.txt",
    "NL": "subscriptions/nl.txt",
    "TR": "subscriptions/tr.txt",
    "FR": "subscriptions/fr.txt",
    "UK": "subscriptions/uk.txt",
    "CA": "subscriptions/ca.txt"
  }
}
```

مانیفست، JSON توصیفی است و **خودش URL اشتراک نیست**. در v2rayN باید URL فید متنی منتشرشده را ثبت کنید:

```text
https://raw.githubusercontent.com/<OWNER>/<REPOSITORY>/<BRANCH>/data/subscriptions/global.txt
```

جای‌نگهدارها را با نام واقعی مخزن و branch میزبان فید عوض کنید؛ این URL نمونه را همان‌طور استفاده نکنید.

### اجرای تجمیع‌کننده

پیاده‌سازی فقط از کتابخانه استاندارد Python 3.12 استفاده می‌کند.

```bash
python3 -m unittest discover -s tests -v
python3 scripts/aggregate.py --config config/sources.json --output-dir data
```

گزینه‌ها: `--timeout` (ثانیه برای هر درخواست، پیش‌فرض ۱۵)، `--max-bytes` (سقف هر منبع، پیش‌فرض ۵ MiB)، `--tcp-check` (بررسی ابتدایی TCP)، `--tcp-timeout`، `--require-reachable` (حذف گره‌های ناموفق در بررسی TCP) و `--verbose`.

اجرای موفق `data/subscriptions/*.txt`، `data/snapshot/global.txt` و `data/manifest.json` را می‌نویسد. ابتدا همه فایل‌ها در مسیر موقت ساخته می‌شوند و فقط پس از دریافت و اعتبارسنجی موفق همۀ منابع فعال، جایگزین خروجی نهایی می‌شوند؛ بنابراین اجرای ناموفق فیدها و snapshot قبلی را دست‌نخورده نگه می‌دارد و با کد غیرصفر خارج می‌شود.

### استقرار با GitHub Actions

منبع گردش‌کار در [`ci/update-subscriptions.yml`](ci/update-subscriptions.yml) نگهداری می‌شود. برای فعال‌سازی اجرای زمان‌بندی‌شده، آن را به `.github/workflows/update-subscriptions.yml` کپی کنید (یا از طریق رابط وب GitHub اضافه کنید)؛ ابزارهای خودکاری که مجوز `workflows` ندارند نمی‌توانند مستقیماً فایل زیر `.github/workflows/` را منتشر کنند. گردش‌کار به این صورت پیکربندی شده است:

- طبق برنامه‌ای متعادل (برای نمونه هر شش ساعت) اجرا شود و `workflow_dispatch` برای اجرای دستی داشته باشد.
- از `actions/checkout` استفاده کند، **Python 3.12** را نصب/آماده کند، فقط وابستگی‌های لازم و نسخه‌ثابت را نصب کند و در صورت خطا با کد غیرصفر متوقف شود.
- فقط مجوزهای لازم را بگیرد. اگر خروجی را commit می‌کند، دسترسی نوشتن را به محتوای مخزن محدود کند و فقط هنگام تغییر خروجی commit کند.
- پس از شکست دریافت یا parse، خروجی ناقص منتشر نکند و فید معتبر قبلی را حفظ کند.
- محتوای اشتراک، اعتبارنامه و توکن را در log ننویسد. پیش از فعال‌سازی انتشار خودکار، diff خروجی را بررسی کنید.

گردش‌کار زمان‌بندی‌شده از default branch مخزن اجرا می‌شود.

### اتصال v2rayN و به‌روزرسانی

به‌جای نوشتن مستقیم در ساختار پایگاه‌داده مستندنشدۀ برنامه، از معماری خود v2rayN استفاده کنید:

- `ServiceLib.Models.Entities.SubItem` مدل اشتراک است و فیلدهایی ازجمله `Id`، `Remarks`، `Url`، `Enabled`، `Sort` و `AutoUpdateInterval` دارد.
- v2rayN داده/پیکربندی خود را با SQLite نگه‌داری می‌کند. اشتراک را از مسیر داده یا سرویس پشتیبانی‌شدۀ برنامه seed کنید و این کار را idempotent کنید (برای نمونه پیش از درج، `Id` ثابت را بررسی کنید). پایگاه‌داده زنده را دستی بازنویسی یا ویرایش نکنید.
- در پیاده‌سازی بالادستیِ ارجاع‌شده، واحد `AutoUpdateInterval` دقیقه است؛ مقدار بزرگ‌تر از صفر در job دوره‌ای به‌روزرسانی اشتراک v2rayN شرکت می‌کند. این رفتار را در نسخۀ دقیق بسته‌بندی‌شده دوباره بررسی کنید.
- مسیر فعلی به‌روزرسانی اشتراک `SubscriptionHandler.UpdateProcess(Config config, string subId, bool blProxy, Func<bool, string, Task> updateFunc)` است. از handler/parser موجود و مسیر اعلان UI استفاده کنید و parser جداگانه و ناسازگار برای گره‌ها نسازید.
- refresh را غیرهم‌زمان و خارج از thread رابط کاربری انجام دهید. برای مسیر دریافت سفارشی، محدودیت‌های **۱۵ ثانیه برای هر تلاش، حداکثر ۲ تلاش، حداکثر پاسخ ۵ MiB و رمزگشایی UTF-8 سخت‌گیرانه** را اعمال کنید. کل پاسخ را پیش از import اعتبارسنجی کنید. تا نسخه pin‌شده را بررسی نکرده‌اید، فرض نکنید downloader پیش‌فرض همین محدودیت‌ها را اعمال می‌کند.
- در timeout، UTF-8 نامعتبر، پاسخ بزرگ/خالی یا خطای parse، اشتراک/گره‌های معتبر قبلی و snapshot آفلاین را نگه دارید. snapshot را فقط بعد از اعتبارسنجی و import موفق جایگزین کنید؛ داده فعال را با فید خالی یا ناقص عوض نکنید.
- `SysProxyType = 2` را فقط وقتی تنظیم کنید که قصدتان دست‌نزدن به تنظیم پراکسی سیستم‌عامل باشد. در enum فعلی بالادست، مقدار `2` برابر `ESysProxyType.Unchanged` است؛ این مقدار پراکسی سیستم را فعال یا اجباری **نمی‌کند**. تنظیم را در رابط برنامه و روی Windows مقصد بررسی کنید.

مقادیر نمونه برای seed مدل `SubItem` (آن‌ها را از لایه دسترسی داده برنامه ذخیره کنید، نه با SQL مستقل):

```csharp
var seed = new SubItem
{
    Id = "community-feed-global",
    Remarks = "Community feed - Global",
    Url = "https://raw.githubusercontent.com/<OWNER>/<REPOSITORY>/<BRANCH>/data/subscriptions/global.txt",
    Enabled = true,
    Sort = 100,
    AutoUpdateInterval = 360
};
```

URL بالا جای‌نگهدار است. در نسخۀ بالادستیِ ارجاع‌شده، `360` یعنی به‌روزرسانی هر شش ساعت؛ پیش از اتکا به آن، رفتار نسخه pin‌شده را بررسی کنید. فیدهای کشور را فقط زمانی به‌صورت اشتراک‌های جدا ثبت کنید که کاربر به انتخاب مستقل آن‌ها نیاز داشته باشد؛ در غیر این صورت فید سراسری ساده‌تر است.

ارجاع‌های معماری بر اساس commit [`1883178`](https://github.com/2dust/v2rayN/tree/1883178b5f1e222b6c6db2782e7a3d989b7cc18f) از v2rayN بررسی شده‌اند:

- [`SubItem.cs`](https://github.com/2dust/v2rayN/blob/1883178b5f1e222b6c6db2782e7a3d989b7cc18f/v2rayN/ServiceLib/Models/Entities/SubItem.cs)
- [`SubscriptionHandler.cs`](https://github.com/2dust/v2rayN/blob/1883178b5f1e222b6c6db2782e7a3d989b7cc18f/v2rayN/ServiceLib/Handler/SubscriptionHandler.cs)
- [`ESysProxyType.cs`](https://github.com/2dust/v2rayN/blob/1883178b5f1e222b6c6db2782e7a3d989b7cc18f/v2rayN/ServiceLib/Enums/ESysProxyType.cs)
- [`Directory.Build.props`](https://github.com/2dust/v2rayN/blob/1883178b5f1e222b6c6db2782e7a3d989b7cc18f/v2rayN/Directory.Build.props)

نسخه/commit بالادستی v2rayN را که واقعاً می‌سازید pin و بررسی کنید؛ پیش از استفاده از این راهنما برای نسخه‌ای دیگر، APIها و target framework را دوباره بررسی کنید.

### ساخت و انتشار (Windows x64)

.NET 10 SDK را نصب و checkout بررسی‌شده و pin‌شدۀ کد v2rayN را آماده کنید. دستور زیر را **از ریشۀ همان checkout کد v2rayN** اجرا کنید:

```powershell
dotnet publish .\v2rayN\v2rayN.Desktop\v2rayN.Desktop.csproj -c Release -r win-x64 --self-contained true -o .\artifacts\publish\win-x64
```

پروژه بالادستی `net10.0` را هدف می‌گیرد و در تنظیمات Release مربوط به revision ارجاع‌شده، انتشار تک‌فایلی فعال است. دستور بالا خروجی self-contained ویندوز x64 را در `artifacts\publish\win-x64` می‌سازد. مسیر پروژه، SDK، یادداشت‌های انتشار و شرایط مجوز نسخه دقیق انتخاب‌شده را بررسی کنید. این دستور در checkout مستندمحور فعلی قابل اجرا نیست، چون پروژه v2rayN در آن وجود ندارد.

### بسته‌بندی قابل‌حمل

یک پوشۀ staging تازه بسازید و **تمام** خروجی publish را پیش از افزودن داده‌های قابل‌حمل کپی کنید:

```text
v2rayN-Portable/
├── v2rayN.exe                 # به‌همراه هر فایل جانبی خروجی publish
├── guiConfigs/                # تنظیمات و داده SQLite که v2rayN می‌سازد
├── subscriptions/
│   ├── snapshot/
│   │   └── global.txt         # آخرین فید معتبر برای حالت آفلاین
│   └── manifest.json
└── logs/                      # اختیاری؛ راز یا log قدیمی را بسته‌بندی نکنید
```

در revision بالادستی ارجاع‌شده، `guiConfigs` پوشۀ پیکربندی برنامه است. اجازه دهید خود v2rayN در اولین اجرا فایل‌های پیکربندی و پایگاه‌داده را ایجاد و مهاجرت دهد. اگر نسخه انتخابی محل متفاوتی دارد یا رفتار portable متفاوت است، مستندات همان نسخه را دنبال کنید؛ بررسی کنید داده واقعاً داخل بسته بماند و ناخواسته به پروفایل roaming کاربر برنگردد. هنگام ارتقا، `guiConfigs` موجود کاربر را بازنویسی نکنید؛ از آن نسخه پشتیبان بگیرید و پایگاه‌داده را حفظ کنید.

برای ساخت بسته تمیز، خروجی publish را کپی کنید، پوشه‌های داده را بسازید، اشتراک را فقط یک‌بار از لایه داده برنامه seed کنید و بسته کپی‌شده را از مسیر دیگری یا حساب Windows تمیز اجرا کنید. فایل فید یا پایگاه‌داده حاوی اعتبارنامه را بدون بررسی عمدی توزیع نکنید.

### آزمون آنلاین و آفلاین

پیش از توزیع بسته، موارد زیر را بررسی کنید:

1. workflow به‌صورت دستی اجرا شود، منابع فعال را در محدودیت زمانی دریافت کند و هنگام منبع خراب/غیرقابل‌دسترس، بدون جایگزینی فیدهای قبلی معتبر متوقف شود.
2. فید متنی در صورت انتظار خالی نباشد، UTF-8 معتبر باشد، خط URI تکراری نداشته باشد و در نسخۀ pin‌شدۀ v2rayN import شود. فیدهای کشور زیرمجموعه‌های تقریبی‌اند و `global.txt` باید همۀ موارد پذیرفته‌شده را داشته باشد.
3. اجرای اول داده مورد انتظار را در `guiConfigs` بسازد. seed پس از اجرای چندباره تکراری نشود و refresh رابط کاربری را متوقف نکند.
4. refresh آنلاین موفق شود و فقط بعد از import معتبر snapshot را جایگزین کند. با قطع شبکه، خطا به کاربر نمایش داده شود و گره‌های قبلی و snapshot همچنان در دسترس باشند.
5. timeout، محدودیت ۵ MiB، UTF-8 نامعتبر، payload خالی و خطای parse را بیازمایید؛ در همۀ این موارد وضعیت معتبر قبلی باید باقی بماند.
6. با `SysProxyType = 2`، برنامه تنظیم پراکسی Windows را تغییر ندهد. قبل و بعد از اجرا تنظیم را بررسی کنید؛ از نتیجه آزمون TCP درباره وضعیت پراکسی نتیجه‌گیری نکنید.
7. نتیجه دسترسی TCP را فقط بررسی ابتدایی endpoint تلقی کنید، نه مدرک تونل پراکسی سالم.

### نکات امنیت و پایداری

- منابع اشتراک و گره‌های معرفی‌شده **غیرقابل‌اعتماد** هستند. مالکیت منبع را بررسی کنید، اعتبارنامه را به گره ناشناس ندهید و فرض کنید endpoint می‌تواند ترافیکی را که در سطح برنامه و TLS مقصد رمزگذاری سرتاسری نشده ببیند.
- گره‌های عمومی ممکن است مخرب، شلوغ، بدپیکربندی‌شده یا بدون اطلاع قبلی منقضی شوند. برچسب کشور و دسترسی TCP فقط سرنخ‌های تقریبی‌اند و مکان، حریم خصوصی، uptime یا کارکرد پراکسی را تضمین نمی‌کنند.
- token حساب، URL خصوصی اشتراک، header احراز هویت یا پایگاه‌داده کاربر را commit نکنید. فید GitHub عمومی برای هرکسی که به مخزن دسترسی دارد قابل‌مشاهده است.
- هنگام بازتوزیع v2rayN یا بسته‌های مشتق‌شده، شرایط مجوز و انتساب پروژه را رعایت کنید.
