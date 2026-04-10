# DateScan — Google Play Compliance Changes

## What I changed in `index.html`

### 1. Cookie banner — GDPR compliance
- Added a **Reject** button next to Accept (equal visual weight).
- Rewrote the banner copy: the old version claimed "100% private, on-device AI analysis," which is misleading because the Style Coach chat sends messages and images to your server. New copy distinguishes on-device camera scans from server-side chat.
- Reject now sets `window.dsConsent = { analytics: false, marketing: false }` so the rest of the app can gate non-essential tracking.

### 2. Footer privacy chip
- Changed "100% private — runs in your browser" → "Camera scans run on-device". Same reason as above: the previous claim covered the whole app, which isn't true once the AI chat is in play.

### 3. AI Content Report button (Google Play Gen-AI policy — **mandatory**)
- Every assistant message in the Style Coach chat now has a small "Report" link under the bubble.
- Clicking it opens a new **Report modal** with five reason categories (offensive, sexual, harmful, misinformation, other) plus an optional note.
- Submits to `POST /api/report-ai` — **you need to build this endpoint.** If the network call fails, the report is queued in `localStorage('pendingReports')` (bounded to 20 items) so nothing is lost.

### 4. Content Safety filter (Gen-AI + Child Safety policy — **mandatory**)
- New `window.dsContentSafetyCheck(text)` function runs client-side before every chat submit.
- Blocks three categories:
  - **Minors:** any mention of child/teen/underage, or explicit age numbers under 18 ("15yo", "16 years old", etc.)
  - **Sexual/NSFW:** nude, porn, explicit, etc.
  - **Self-harm:** suicide, self-harm, "kill myself" — returns a crisis-line message (988 US, 116 123 UK, 112 EU) instead of routing to the AI.
- ⚠️ **Client filters are bypassable.** Your backend MUST enforce the same rules. This is a last line of defense, not the only one.

### 5. Data deletion (Google Play Data Deletion policy — **mandatory**)
- New "Delete all my data" section at the bottom of the Privacy modal.
- Wipes: all IndexedDB databases, all Cache API caches, `localStorage`, `sessionStorage`, and unregisters all service workers. Then reloads.
- Explicitly tells the user this does NOT cancel a Pro subscription — they need to use the receipt link or contact support. You also need to offer a **web-based deletion URL that works without an account** (Play Console requires this separately from the in-app option).

### 6. Service Worker registration
- Added `navigator.serviceWorker.register('/service-worker.js')` on `load`. Required for Play's TWA wrapper to recognize the app as installable and offline-capable.

---

## New files you need to deploy

| File | Deploy to | Purpose |
|---|---|---|
| `manifest.webmanifest` | `/manifest.webmanifest` | PWA manifest — replaces whatever you have now. Includes all required fields (`id`, `scope`, `start_url`, `display`, `theme_color`, `background_color`, regular + maskable icons, screenshots, shortcuts). |
| `service-worker.js` | `/service-worker.js` | Offline shell + stale-while-revalidate assets + network-only `/api/*`. Bump `CACHE_VERSION` on every deploy. |
| `offline.html` | `/offline.html` | Fallback page shown when the user is fully offline. |
| `assetlinks.json` | `/.well-known/assetlinks.json` | Digital Asset Links file — **replace the placeholder SHA-256** with your actual app signing key fingerprint (you'll get it from Play Console → Setup → App signing). Without this, the TWA shows a browser URL bar, which is ugly and Play-negative. |

## Assets you still need to produce

These aren't text files I can generate — they're image files you need to create:

- `/icon-192.png`, `/icon-512.png` — regular PWA icons (transparent background OK)
- `/icon-192-maskable.png`, `/icon-512-maskable.png` — **maskable** versions with a safe zone (keep the logo inside the inner 80% circle). Required for a non-ugly Android adaptive icon.
- `/apple-touch-icon.png` — 180×180
- `/screenshots/scan-mobile.png`, `/screenshots/coach-mobile.png` — 1080×1920 portrait
- `/screenshots/desktop.png` — 1920×1080

For the Play Store listing (uploaded in Play Console, not on your domain):
- App icon: 512×512 PNG, 32-bit
- Feature graphic: 1024×500 PNG
- Phone screenshots: at least 2, max 8, 16:9 or 9:16
- Short description: ≤80 chars
- Full description: ≤4000 chars

---

## What's still on you (outside the HTML)

### 🔴 Critical — blockers

1. **Google Play Billing for Pro**
   Your code already has `getDigitalGoodsService("https://play.google.com/billing")` with Lemon Squeezy fallback — good. But for the Play-submitted build you need to:
   - Create matching SKUs in Play Console (`week`, `month`, `year`).
   - Make sure the TWA build forces the Play Billing path and **never** falls back to Lemon Squeezy on Android. Check the `catch` block that currently falls back on billing errors — on the Play build this should show an error, not redirect to Lemon Squeezy, because Lemon Squeezy on Play = instant policy strike.
   - A clean way: check `navigator.userAgent.includes('wv') && document.referrer.startsWith('android-app://')` (or a build-time flag) and short-circuit the fallback.

2. **Backend content safety**
   The client filter I added is easy to bypass. Your `/api/chat` (or whatever powers Style Coach) must run the same checks server-side and refuse to forward disallowed prompts to the LLM. At minimum: minor detection, NSFW, self-harm, and image moderation on uploads (use the moderation API of whichever provider you're using, or a dedicated service).

3. **`/api/report-ai` endpoint**
   Simple POST handler that stores `{reason, note, reportedText, ts, ua}` in a database or logging system. Play doesn't audit the endpoint itself, but if you get reported and have no moderation trail, you're exposed.

4. **Data deletion URL without login**
   Play Console has a required field: "URL where users can request account deletion without installing the app." Add a page at `/delete-account` with a form that takes an email, sends a confirmation email, and triggers server-side deletion. In-app delete (already added) satisfies one half; this URL satisfies the other.

5. **Digital Asset Links**
   `/.well-known/assetlinks.json` must return `200 OK` with `Content-Type: application/json` and the correct SHA-256 fingerprint. Test it with:
   ```
   https://developers.google.com/digital-asset-links/tools/generator
   ```

### 🟡 Important — don't skip

6. **Data Safety form in Play Console**
   Declare honestly:
   - Photos: collected, processed on device for scans, uploaded to your server for AI chat, "processed for this request only and not retained" (match the wording in your privacy modal exactly).
   - Payment info: handled by Google Play Billing (so: not collected by you).
   - Device/other IDs: only if you actually collect them.
   - Purchase history: collected, linked, not shared.

7. **Privacy policy updates**
   Your existing `/privacy.html` needs to mention:
   - That AI chat messages and images are sent to your server and forwarded to a third-party vision-language model provider (name the provider — OpenAI, Anthropic, Google, etc.).
   - Data retention period for chat logs.
   - The account deletion URL.
   - A contact email specifically for privacy/data requests.
   - GDPR rights (access, rectification, erasure, portability) if you have any EU users.

8. **Target SDK level**
   New apps submitted in 2026 must target API 35 (Android 15). Bubblewrap handles this if you use a recent version — run `bubblewrap update` before building.

9. **Content rating questionnaire**
   In Play Console. Answer honestly. A styling/dating-adjacent app usually gets Teen or Mature 17+. Don't try to game this — if Play later disagrees with your rating they'll re-rate and flag you.

10. **Terms of Service**
    You reference `/terms.html` in the footer — make sure it actually exists and covers: subscription terms (billing cycle, auto-renewal, cancellation per Google Play), AI-generated content disclaimer, liability limitation, governing law.

### 🟢 Nice to have

11. **Localized store listing** — Hungarian + English at minimum if you want HU users.
12. **Closed testing track first** — don't go straight to production. Get 12 testers for 14 days (Play's new requirement for personal developer accounts).
13. **Crash reporting** — Firebase Crashlytics or Sentry. Play shows ANR/crash rates on your store page; keep them under 1%.

---

## Packaging steps (once everything above is ready)

```bash
# 1. Install Bubblewrap
npm i -g @bubblewrap/cli

# 2. Initialize from your manifest
bubblewrap init --manifest=https://datescan.app/manifest.webmanifest

# 3. Answer the prompts — package name, app name, signing key, etc.
# Keep the signing key safe; you'll need it forever.

# 4. Build
bubblewrap build

# 5. Get the SHA-256 fingerprint for assetlinks.json
bubblewrap fingerprint

# 6. Put that fingerprint into assetlinks.json and deploy it to
#    https://datescan.app/.well-known/assetlinks.json

# 7. Upload the generated .aab to Play Console → Internal Testing track
```

First submission: **expect at least one rejection**. The most common rejection reasons for PWAs wrapped as TWAs are:
- Missing or broken assetlinks.json (browser URL bar visible)
- Payment policy violation (external payment not using Play Billing)
- Data Safety form doesn't match privacy policy
- "Broken functionality" because the app requires network and the reviewer had spotty WiFi — having a good offline.html helps here

---

## TL;DR

I fixed everything I could inside the HTML: cookie consent, misleading privacy copy, AI report button, content safety filter, in-app data deletion, service worker registration. I also generated the manifest, service worker, offline page, and assetlinks template.

The remaining work is off-HTML: **Play Billing on the Android build, the `/api/report-ai` endpoint, backend content moderation, the no-login deletion URL, updated privacy policy, and the actual TWA packaging + Play Console submission.**

The billing issue is the one that will sink the submission if you don't handle it. Everything else is standard paperwork.
