import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { promisify } from 'node:util';
import zlib from 'node:zlib';

const execFileAsync = promisify(execFile);

import { ApifyRuntimeAdapter } from '../dist/apifyRuntime.js';
import { coerceUrlCandidate, normalizeAuditInput, runBatchAudit } from '../dist/auditor.js';
import { BillingManager } from '../dist/billing.js';
import { checkEgressAndExportInterfaces } from '../dist/detectors.js';
import { decodeHtmlEntities, parseHtmlDocument } from '../dist/htmlParser.js';
import { DEFAULT_MAX_RESPONSE_BYTES, fetchSafeHttp } from '../dist/httpClient.js';
import { escapeHtml, generateRemediationPack } from '../dist/remediation.js';
import { evaluateRobotsRules, parseRobotsTxt } from '../dist/robots.js';
import { startStandbyServer } from '../dist/server.js';
import { classifyIpAddress, validateUrlAgainstSsrf } from '../dist/ssrf.js';
import { LEGAL_DISCLAIMER } from '../dist/types.js';

const NON_COMPLIANT_SAAS_HOME_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>CloudPulse CRM — Enterprise B2B Revenue SaaS Platform</title>
  <script src="/_next/static/chunks/main.js"></script>
  <script src="https://js.stripe.com/v3/"></script>
  <script src="https://cdn.auth0.com/js/auth0-spa-js/2.1/auth0-spa-js.production.js"></script>
  <script src="https://static.vanta.com/trust-badge.js"></script>
  <script src="https://cloudpulse.statuspage.io/embed/script.js"></script>
</head>
<body>
  <header>
    <nav>
      <a href="https://app.cloudpulse.example.com/login">Sign In</a>
      <a href="/pricing">Pricing &amp; Plans</a>
      <a href="/terms">Master Subscription Agreement &amp; Terms</a>
      <a href="/trust">Security &amp; Trust Center</a>
      <a href="/docs/export">Export &amp; API Docs</a>
    </nav>
  </header>
  <main>
    <h1>Multi-Tenant B2B SaaS CRM for Financial Services &amp; Enterprise Teams</h1>
    <p>Start your free trial or book an Enterprise demo. SOC 2 Type II &amp; ISO 27001 certified via Vanta Trust Center.</p>
  </main>
  <footer>
    <a href="/pricing">Pricing</a>
    <a href="/terms">Terms of Service</a>
    <a href="/trust">Trust Center</a>
    <a href="/docs/export">Export Docs</a>
  </footer>
</body>
</html>`;

const NON_COMPLIANT_SAAS_PRICING_HTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Pricing — CloudPulse CRM</title></head>
<body>
  <h1>Subscription Plans</h1>
  <div>
    <h2>Starter Plan — $49/month per seat</h2>
    <p>Core CRM pipelines. CSV/JSON export: Enterprise plan only.</p>
  </div>
  <div>
    <h2>Enterprise Plan — $199/month per seat (Billed Annually)</h2>
    <p>Includes REST API access &amp; bulk exports. Assisted migration offboarding carries a $750 offboarding data extraction fee plus a data egress fee of $0.12/GB.</p>
  </div>
</body>
</html>`;

const NON_COMPLIANT_SAAS_TERMS_HTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Master Subscription Agreement — CloudPulse CRM</title></head>
<body>
  <h1>Master Subscription Agreement &amp; Terms of Service</h1>
  <p>1. Term &amp; Renewal: Annual subscriptions are non-cancellable and non-refundable during the fixed term. Customer must provide at least 90 days prior written notice before renewal to terminate or switch providers.</p>
  <p>2. Post-Termination Deletion: Upon expiration or cancellation, all customer data deleted within 7 days of termination without exception.</p>
</body>
</html>`;

const NON_COMPLIANT_SAAS_TRUST_HTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Trust Center — CloudPulse CRM</title></head>
<body>
  <h1>Security &amp; GDPR Privacy Overview</h1>
  <p>We maintain SOC 2 Type II compliance via Vanta and sign GDPR Standard Contractual Clauses (SCCs) for personal data transfers.</p>
</body>
</html>`;

const NON_COMPLIANT_SAAS_DOCS_HTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Data Export — CloudPulse Docs</title></head>
<body>
  <h1>Exporting Workspace Records</h1>
  <p>API &amp; data export requires Enterprise upgrade. Contact your account executive for paid migration export quotes.</p>
</body>
</html>`;

const COMPLIANT_SAAS_HOME_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>EuroStack Analytics — EU Data Act Compliant B2B SaaS</title>
  <script src="https://cdn.paddle.com/paddle/v2/paddle.js"></script>
  <script src="https://workos.com/authkit.js"></script>
  <script src="https://trust.drata.com/widget.js"></script>
</head>
<body>
  <header>
    <nav>
      <a href="/login">Sign In</a>
      <a href="/pricing">Pricing</a>
      <a href="/data-act">EU Data Act Switching Addendum</a>
      <a href="/portability-register">Art. 26(b) Portability Register &amp; Art. 28 Notice</a>
    </nav>
  </header>
  <main>
    <h1>Privacy-First European B2B Analytics SaaS Platform</h1>
    <!-- Self-closed iframe before status iframe must never swallow sibling iframes -->
    <iframe src="/metrics-preview" title="Live Preview" />
    <iframe src="https://eurostack.betteruptime.com/badge" title="System Status"></iframe>
    <p>€0 switching &amp; €0 data egress fees across all plans under EU Data Act Art. 29(1), with free self-serve JSON/CSV/OpenAPI bulk export on all tiers (Art. 30(2)).</p>
  </main>
  <footer>
    <a href="/data-act">EU Data Act Addendum</a>
    <a href="/portability-register">Online Portability Register</a>
    <a href="/pricing">Pricing</a>
  </footer>
</body>
</html>`;

const COMPLIANT_SAAS_DATA_ACT_HTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>EU Data Act Cloud Switching Addendum — EuroStack</title></head>
<body>
  <h1>EU Data Act Cloud Switching Addendum (Regulation (EU) 2023/2854 &amp; Commission Recommendation (EU) 2026/2394)</h1>
  <p>1. Initiation Notice (Art. 25(2)(d)): Customers may initiate switching to another provider or on-premises ICT infrastructure with a maximum notice period not exceeding 2 months.</p>
  <p>2. Transitional Period (Art. 25(2)(a) &amp; (4)): EuroStack completes porting within a 30-calendar-day transitional period while maintaining full service continuity and security.</p>
  <p>3. Zero Switching &amp; Egress Charges (Art. 29(1) &amp; Art. 30(2)): EuroStack shall not impose any switching charges or data egress fees (€0 switching fee, €0/GB egress). Open interfaces (JSON, CSV, Parquet, OpenAPI) are available free of charge across all plans. Continuous in-parallel multi-cloud egress pass-through at cost is governed separately by Art. 34(2).</p>
  <p>4. Retrieval &amp; Erasure (Art. 25(2)(g)–(h)): Following the transitional period, EuroStack provides a minimum 30-calendar-day data retrieval period, after which customer data is permanently deleted after the 30-day retrieval period.</p>
  <p>5. Fixed-Term Early Termination &amp; DORA Exit Strategy (Art. 29(4)–(5) &amp; Reg. (EU) 2022/2554 Art. 30(2)(h)): Monthly plans cancel at any time without penalty; optional discounted annual contracts apply only a transparent proportionate early termination fee equal to the unearned discount differential. Regulated financial entities receive documented ICT exit strategy and transition testing support under EU DORA Art. 28(8) &amp; Art. 30(2)(h).</p>
</body>
</html>`;

const COMPLIANT_SAAS_PORTABILITY_REGISTER_HTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Art. 26(b) Online Portability Register &amp; Art. 28 Jurisdiction Notice</title></head>
<body>
  <h1>Article 26(b) Online Register of Data Structures &amp; Formats</h1>
  <p>Exportable data categories (Art. 25(2)(e)): All analytics events, dashboards, user permissions, webhooks, and audit logs are exportable via free OpenAPI 3.1 REST endpoints in structured JSON, NDJSON, CSV, and Apache Parquet schemas. Exempted trade-secret categories (Art. 25(2)(f)) are strictly limited to internal cluster autoscaling heuristics.</p>
  <h2>Article 28(1)(a) ICT Infrastructure Jurisdiction</h2>
  <p>All ICT infrastructure deployed for data processing is hosted in Frankfurt, Germany and Dublin, Ireland and is subject to the jurisdiction of the European Union and Germany/Ireland.</p>
  <h2>Article 28(1)(b) &amp; Article 32 Non-Personal Data Governmental-Access Safeguards</h2>
  <p>EuroStack maintains AES-256-GCM encryption, EU-resident HSM keys, zero-trust organisational access controls, and contractual subprocessor commitments to prevent unlawful international governmental access to or transfer of non-personal data held in the Union.</p>
</body>
</html>`;

const COMPLIANT_SAAS_PRICING_HTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Pricing — EuroStack Analytics</title></head>
<body>
  <h1>Simple Transparent SaaS Pricing</h1>
  <p>Starter €29/month &middot; Growth €99/month. Free data export on all plans (JSON, CSV, Parquet &amp; OpenAPI). $0 egress fee and no offboarding fee.</p>
</body>
</html>`;

const CLEAN_BAKERY_BROCHURE_HTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Maison Levain Artisan Sourdough Bakery — Lyon &amp; Brussels</title></head>
<body>
  <main>
    <h1>Handcrafted Organic Sourdough Breads &amp; Viennoiseries</h1>
    <p>Baked fresh every morning at 05:30 using stone-milled organic flour. Visit our neighbourhood bakery or view our seasonal pastry menu.</p>
  </main>
  <footer><a href="/contact">Bakery Hours &amp; Directions</a></footer>
</body>
</html>`;

const RETAIL_SHOPIFY_STORE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>VelvetBean Specialty Coffee Roasters — Subscribe &amp; Save</title>
  <link rel="stylesheet" href="https://cdn.shopify.com/s/files/1/0888/coffee/theme.css">
  <script src="https://js.stripe.com/v3/"></script>
  <script src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js"></script>
  <script src="https://widget.intercom.io/widget/shop123"></script>
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "Product",
    "name": "Single-Origin Espresso Beans (1kg)",
    "offers": { "@type": "Offer", "price": "29.00", "priceCurrency": "EUR" }
  }
  </script>
</head>
<body>
  <nav>
    <a href="/collections/espresso">Shop Beans</a>
    <a href="/account/login">Customer Sign In</a>
    <a href="/cart">Shopping Cart</a>
  </nav>
  <main>
    <h1>Organic Coffee Subscription — €29/month (Billed Monthly)</h1>
    <button type="button">Add to Cart</button>
    <p>Our GDPR privacy notice lists payment and shipping subprocessors.</p>
  </main>
</body>
</html>`;

function listenLocalServer(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      res.setHeader('Connection', 'close');
      handler(req, res);
    });
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      resolve({
        server: srv,
        baseUrl: `http://127.0.0.1:${addr.port}`,
        close: () =>
          new Promise((r) => {
            srv.close(() => r());
            srv.closeAllConnections?.();
          }),
      });
    });
  });
}

describe('EU Data Act SaaS Switching & Zero-Egress Fee Auditor — Full Offline E2E & Red-Team Suite', () => {
  const servers = [];
  let nonCompliantSaasUrl = '';
  let compliantSaasUrl = '';
  let cleanBakeryUrl = '';
  let retailShopifyUrl = '';
  let robotsBlockedUrl = '';
  let tempStorageDir = '';
  let previousStorageEnv;

  before(async () => {
    process.env.ALLOW_LOCALHOST_FOR_TESTS = '1';
    previousStorageEnv = process.env.APIFY_LOCAL_STORAGE_DIR;
    tempStorageDir = fs.mkdtempSync(path.join(os.tmpdir(), 'eu-data-act-e2e-'));
    process.env.APIFY_LOCAL_STORAGE_DIR = tempStorageDir;

    // 1. Non-compliant SaaS platform
    const badSrv = await listenLocalServer((req, res) => {
      const urlPath = (req.url || '/').split('?')[0];
      if (urlPath === '/robots.txt') {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('User-agent: *\nAllow: /\n');
        return;
      }
      if (urlPath === '/') {
        const gz = zlib.gzipSync(Buffer.from(NON_COMPLIANT_SAAS_HOME_HTML, 'utf8'));
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Encoding': 'gzip',
        });
        res.end(gz);
        return;
      }
      if (urlPath === '/pricing') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(NON_COMPLIANT_SAAS_PRICING_HTML);
        return;
      }
      if (urlPath === '/terms') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(NON_COMPLIANT_SAAS_TERMS_HTML);
        return;
      }
      if (urlPath === '/trust') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(NON_COMPLIANT_SAAS_TRUST_HTML);
        return;
      }
      if (urlPath === '/docs/export') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(NON_COMPLIANT_SAAS_DOCS_HTML);
        return;
      }
      if (urlPath === '/whitepaper.pdf') {
        res.writeHead(200, { 'Content-Type': 'application/pdf' });
        res.end(Buffer.from('%PDF-1.4 mock security whitepaper'));
        return;
      }
      if (urlPath === '/redirect-imds') {
        res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
        res.end();
        return;
      }
      if (urlPath === '/oversized') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<html><body>' + 'A'.repeat(3.1 * 1024 * 1024) + '</body></html>');
        return;
      }
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
    });
    servers.push(badSrv);
    nonCompliantSaasUrl = badSrv.baseUrl;

    // 2. Compliant EU Data Act SaaS platform
    const okSrv = await listenLocalServer((req, res) => {
      const urlPath = (req.url || '/').split('?')[0];
      if (urlPath === '/robots.txt') {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('User-agent: *\nAllow: /\n');
        return;
      }
      if (urlPath === '/') {
        const br = zlib.brotliCompressSync(Buffer.from(COMPLIANT_SAAS_HOME_HTML, 'utf8'));
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Encoding': 'br',
        });
        res.end(br);
        return;
      }
      if (urlPath === '/data-act') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(COMPLIANT_SAAS_DATA_ACT_HTML);
        return;
      }
      if (urlPath === '/portability-register') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(COMPLIANT_SAAS_PORTABILITY_REGISTER_HTML);
        return;
      }
      if (urlPath === '/pricing') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(COMPLIANT_SAAS_PRICING_HTML);
        return;
      }
      res.writeHead(404);
      res.end();
    });
    servers.push(okSrv);
    compliantSaasUrl = okSrv.baseUrl;

    // 3. Clean brochure/bakery site + Shopify retail e-commerce store (F-02)
    const bakerySrv = await listenLocalServer((req, res) => {
      const urlPath = (req.url || '/').split('?')[0];
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      if (urlPath === '/shopify-coffee') {
        res.end(RETAIL_SHOPIFY_STORE_HTML);
        return;
      }
      if (urlPath === '/single-donation-stripe') {
        res.end(`<!DOCTYPE html><html lang="en"><head><title>Civic Choir Society</title>
          <script src="https://js.stripe.com/v3/"></script>
        </head><body><h1>Support Our Autumn Concert</h1></body></html>`);
        return;
      }
      res.end(CLEAN_BAKERY_BROCHURE_HTML);
    });
    servers.push(bakerySrv);
    cleanBakeryUrl = bakerySrv.baseUrl;
    retailShopifyUrl = `${bakerySrv.baseUrl}/shopify-coffee`;

    // 4. robots.txt Disallow: / site
    const robotsSrv = await listenLocalServer((req, res) => {
      const urlPath = (req.url || '/').split('?')[0];
      if (urlPath === '/robots.txt') {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('User-agent: *\nDisallow: /\n');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<html><body>Blocked</body></html>');
    });
    servers.push(robotsSrv);
    robotsBlockedUrl = robotsSrv.baseUrl;
  });

  after(async () => {
    for (const s of servers) {
      await s.close();
    }
    if (previousStorageEnv === undefined) {
      delete process.env.APIFY_LOCAL_STORAGE_DIR;
    } else {
      process.env.APIFY_LOCAL_STORAGE_DIR = previousStorageEnv;
    }
    if (tempStorageDir) {
      fs.rmSync(tempStorageDir, { recursive: true, force: true });
    }
  });

  it('1. Bare domain normalization, F-01 ReDoS/length/attr bounds, SSRF / IPv6 / trailing-dot guard, 2MB cap, and linear O(N) hostile robots.txt wildcard matching', async () => {
    assert.equal(coerceUrlCandidate('acmecloud.io'), 'https://acmecloud.io');
    assert.equal(
      coerceUrlCandidate('https://acmecloud.io/data-act'),
      'https://acmecloud.io/data-act',
    );
    assert.equal(coerceUrlCandidate('file:///etc/passwd'), 'file:///etc/passwd');
    assert.equal(coerceUrlCandidate(''), null);
    assert.equal(coerceUrlCandidate('a'.repeat(2049) + '.com'), null);

    // F-01: Linear O(N) bare-domain coercion on pathological dotted input
    const tDomain = performance.now();
    const weirdDomain = 'a.'.repeat(500) + '1';
    coerceUrlCandidate(weirdDomain);
    assert.ok(performance.now() - tDomain < 25, 'coerceUrlCandidate must execute in O(N) < 25ms');

    // F-01: ReDoS regression on EGRESS_FEE_LABEL_FIRST_RE ("data egress fee 0." + "1".repeat(200_000) + "!")
    const hostileDecimalDoc = parseHtmlDocument(
      `<html><body>data egress fee 0.${'1'.repeat(200_000)}!</body></html>`,
      'https://redos.example.com/',
    );
    const tEgress = performance.now();
    const egressRedosCheck = checkEgressAndExportInterfaces({
      pages: [
        {
          requestedUrl: 'https://redos.example.com/',
          finalUrl: 'https://redos.example.com/',
          redirectChain: [],
          doc: hostileDecimalDoc,
        },
      ],
      isSaasOrCloudServiceDetected: true,
      enabled: true,
    });
    const egressElapsed = performance.now() - tEgress;
    assert.ok(
      egressElapsed < 50,
      `Disjoint 0\\.0*[1-9]\\d{0,5} must finish in < 50ms, got ${egressElapsed.toFixed(1)}ms`,
    );
    assert.equal(egressRedosCheck.egressOrSwitchingFeeFound, false);

    // F-01: Bounded decodeHtmlEntities and 8192-char rawAttrs cap in scanPairedElementsLinear
    assert.equal(decodeHtmlEntities('&euro;0 &amp; &#x3bb; &' + 'a'.repeat(5000) + ';'), '€0 & λ &' + 'a'.repeat(5000) + ';');
    const hugeAttrDoc = parseHtmlDocument(
      `<html><head><script src="https://js.stripe.com/v3/" data-blob="${'x'.repeat(25_000)}"></script></head><body></body></html>`,
      'https://attrcap.example.com/',
    );
    assert.equal(hugeAttrDoc.scripts.length, 1);
    assert.ok(hugeAttrDoc.scripts[0].rawAttrs.length <= 600);

    for (const blockedTarget of [
      'http://169.254.169.254/latest/meta-data/',
      'http://10.0.0.1/admin',
      'http://192.168.1.1/',
      'http://172.16.5.4/',
      'http://[::ffff:169.254.169.254]/latest/meta-data/',
      'http://[0:0:0:0:0:ffff:169.254.169.254]/',
      'http://metadata.google.internal/computeMetadata/v1/',
      'http://metadata.google.internal./computeMetadata/v1/',
      'http://127.0.0.1:8080/',
      'http://localhost:3000/',
      'http://[::1]:4321/',
      'file:///etc/passwd',
    ]) {
      const check = await validateUrlAgainstSsrf(blockedTarget, { allowLocalhost: false });
      assert.equal(check.allowed, false, `Expected SSRF guard to block ${blockedTarget}`);
    }

    assert.equal(classifyIpAddress('93.184.216.34', false).allowed, true);
    assert.equal(classifyIpAddress('2606:4700:4700::1111', false).allowed, true);

    const rebind = await validateUrlAgainstSsrf('https://evil-rebind.example.com', {
      allowLocalhost: false,
      dnsLookup: async () => [
        { address: '93.184.216.34', family: 4 },
        { address: '169.254.169.254', family: 4 },
      ],
    });
    assert.equal(rebind.allowed, false);

    const oversized = await fetchSafeHttp(`${nonCompliantSaasUrl}/oversized`, {
      allowLocalhost: true,
    });
    assert.equal(oversized.ok, true);
    assert.equal(oversized.truncated, true);
    assert.equal(oversized.byteLength, DEFAULT_MAX_RESPONSE_BYTES);

    const hostileRobots = parseRobotsTxt(
      'User-agent: *\nDisallow: /*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b$\n',
    );
    const t0 = Date.now();
    const robEval = evaluateRobotsRules('/' + 'a'.repeat(160) + 'c', hostileRobots.rules);
    assert.equal(robEval.allowed, true);
    assert.ok(Date.now() - t0 < 50, 'Hostile wildcard robots.txt must evaluate in <50ms');
  });

  it('2. Non-compliant SaaS platform (Stripe Billing + Auth0 + Vanta + Statuspage + "CSV/JSON export: Enterprise plan only" + "$750 offboarding data extraction fee" + "90 days prior written notice" + "all customer data deleted within 7 days of termination" + missing Art. 26(b) register & Art. 28 notice) -> flags all 6 rules, generates 3-part remediation pack, links all 5 sister Actors, bills exact $0.03 PPE', async () => {
    const runtime = new ApifyRuntimeAdapter();
    const res = await runBatchAudit(
      {
        urls: [nonCompliantSaasUrl],
        includeRemediationPack: true,
        maxLegalPagesPerDomain: 4,
        domainDelayMs: 0,
      },
      { runtime, allowLocalhost: true },
    );

    assert.equal(res.items.length, 1);
    const item = res.items[0];
    assert.equal(item.status, 'audited');
    assert.equal(item.isSaasOrCloudServiceDetected, true);
    assert.equal(item.sitePlatform, 'nextjs');
    assert.equal(item.siteCategory, 'b2b_or_b2c_saas');
    assert.equal(item.pagesFetchedCount, 5, 'Should inspect homepage + /docs/export + /pricing + /trust + /terms');

    assert.deepEqual(item.billingSdkVendors, ['stripe-billing']);
    assert.deepEqual(item.authIdentityVendors, ['auth0']);
    assert.deepEqual(item.trustCenterGrcVendors, ['vanta']);
    assert.deepEqual(item.docsStatusSupportVendors, ['statuspage']);

    assert.equal(item.egressOrSwitchingFeeFound, true);
    assert.equal(item.exportPaywallOrTierLockFound, true);
    assert.equal(item.shortPostTerminationRetentionFound, true);
    assert.equal(item.excessiveNoticePeriodLockInFound, true);
    assert.equal(item.switchingAddendumFound, false);
    assert.equal(item.art26bOnlinePortabilityRegisterFound, false);
    assert.equal(item.art28IctJurisdictionDisclosed, false);
    assert.equal(item.art28NonPersonalGovAccessSafeguardsDisclosed, false);
    assert.equal(item.art26bAndArt28TransparencyCheck.gdprPersonalDataOnlyNoticeWithoutArt28, true);
    assert.equal(item.nonCancellableFixedTermFound, true);
    assert.equal(item.art29EarlyTerminationAndDoraExitGapFound, true);

    const ruleIds = item.findings.map((f) => f.ruleId);
    assert.equal(item.findingsCount, 6);
    assert.deepEqual(ruleIds, [
      'DATA-ACT-ART-29-30-EGRESS-FEE-OR-EXPORT-PAYWALL',
      'DATA-ACT-ART-25-RETENTION-OR-NOTICE-LOCKIN',
      'DATA-ACT-ART-25-MISSING-SWITCHING-ADDENDUM',
      'DATA-ACT-ART-26B-MISSING-ONLINE-PORTABILITY-REGISTER',
      'DATA-ACT-ART-28-32-MISSING-JURISDICTION-GOV-ACCESS-NOTICE',
      'DATA-ACT-ART-29-4-DORA-EXIT-TRANSPARENCY-GAP',
    ]);

    assert.equal(item.complianceScore, 0);
    assert.equal(item.riskTier, 'CRITICAL');

    // Verify 3-part HTML/JS remediation pack + F-06 configurable ICT jurisdiction placeholder
    assert.equal(item.remediationPackGenerated, true);
    assert.ok(item.remediationPack);
    assert.match(item.remediationPack.euDataActSwitchingAddendumHtml, /2026\/2394/);
    assert.match(item.remediationPack.euDataActSwitchingAddendumHtml, /30-calendar-day transitional period/);
    assert.match(item.remediationPack.euDataActSwitchingAddendumHtml, /30-calendar-day data retrieval period/);
    assert.match(item.remediationPack.onlinePortabilityRegisterAndArt28Html, /Article 26\(b\)/);
    assert.match(item.remediationPack.onlinePortabilityRegisterAndArt28Html, /Article 28\(1\)\(a\)/);
    assert.match(
      item.remediationPack.onlinePortabilityRegisterAndArt28Html,
      /data-template-placeholder="configure-ict-jurisdiction"/,
    );
    assert.match(item.remediationPack.onlinePortabilityRegisterAndArt28Html, /non-personal data/i);
    assert.match(item.remediationPack.pricingZeroEgressDisclosureWidgetHtmlJs, /€0 Switching &amp; €0 Data Egress/);

    // Verify ALL FIVE live sister Actors in recommendedNextAudits
    const nextSlugs = item.recommendedNextAudits.map((a) => a.actorSlug);
    assert.deepEqual(nextSlugs, [
      'healthy_addax/us-click-to-cancel-auditor',
      'healthy_addax/cipa-vppa-wiretap-pixel-auditor',
      'healthy_addax/wcag-eaa-ada-auditor',
      'healthy_addax/eu-withdrawal-omnibus-auditor',
      'healthy_addax/fake-reviews-dmcc-drip-pricing-auditor',
    ]);
    assert.equal(item.disclaimer, LEGAL_DISCLAIMER);

    // Exact PPE billing: $0.005 + $0.015 + $0.01 = $0.03
    assert.equal(res.billing.chargedCounts['actor-start'], 1);
    assert.equal(res.billing.chargedCounts['url-audited'], 1);
    assert.equal(res.billing.chargedCounts['remediation-pack-generated'], 1);
    assert.equal(res.billing.estimatedTotalUsd, 0.03);
  });

  it('3. Compliant SaaS platform (published /data-act addendum + /portability-register with JSON/CSV/OpenAPI schemas + Art. 28(1)/Art. 32 EU jurisdiction & non-personal data gov-access safeguards + €0 egress on all plans + 30-day retrieval) -> complianceScore: 100, LOW risk, $0 remediation charge', async () => {
    const runtime = new ApifyRuntimeAdapter();
    const res = await runBatchAudit(
      {
        urls: [compliantSaasUrl],
        includeRemediationPack: true,
        maxLegalPagesPerDomain: 4,
        domainDelayMs: 0,
      },
      { runtime, allowLocalhost: true },
    );

    assert.equal(res.items.length, 1);
    const okItem = res.items[0];
    assert.equal(okItem.status, 'audited');
    assert.equal(okItem.isSaasOrCloudServiceDetected, true);
    assert.deepEqual(okItem.billingSdkVendors, ['paddle']);
    assert.deepEqual(okItem.authIdentityVendors, ['workos']);
    assert.deepEqual(okItem.trustCenterGrcVendors, ['drata']);
    assert.deepEqual(okItem.docsStatusSupportVendors, ['betterstack']);

    assert.equal(okItem.egressOrSwitchingFeeFound, false);
    assert.equal(okItem.exportPaywallOrTierLockFound, false);
    assert.equal(okItem.shortPostTerminationRetentionFound, false);
    assert.equal(okItem.excessiveNoticePeriodLockInFound, false);
    assert.equal(okItem.switchingAddendumFound, true);
    assert.equal(okItem.art26bOnlinePortabilityRegisterFound, true);
    assert.equal(okItem.art28IctJurisdictionDisclosed, true);
    assert.equal(okItem.art28NonPersonalGovAccessSafeguardsDisclosed, true);
    assert.equal(okItem.art29EarlyTerminationAndDoraExitGapFound, false);

    assert.equal(okItem.complianceScore, 100);
    assert.equal(okItem.riskTier, 'LOW');
    assert.equal(okItem.findingsCount, 0);
    assert.equal(okItem.remediationPackGenerated, false);
    assert.equal(okItem.remediationPack, null);
    assert.equal(res.billing.chargedCounts['remediation-pack-generated'], 0);
  });

  it('4. Clean brochure/bakery site AND F-02 Shopify retail store (js.stripe.com + OneTrust + Intercom + /account/login + €29/month coffee + subprocessors) -> isSaasOrCloudServiceDetected: false, complianceScore: 100, LOW risk, $0 remediation charge', async () => {
    const runtime = new ApifyRuntimeAdapter();
    const res = await runBatchAudit(
      {
        urls: [
          cleanBakeryUrl,
          retailShopifyUrl,
          `${cleanBakeryUrl}/single-donation-stripe`,
        ],
        includeRemediationPack: true,
        maxLegalPagesPerDomain: 4,
        domainDelayMs: 0,
      },
      { runtime, allowLocalhost: true },
    );

    assert.equal(res.items.length, 3);

    const clean = res.items[0];
    assert.equal(clean.status, 'audited');
    assert.equal(clean.isSaasOrCloudServiceDetected, false);
    assert.equal(clean.siteCategory, 'brochure_or_content');
    assert.equal(clean.complianceScore, 100);
    assert.equal(clean.riskTier, 'LOW');
    assert.equal(clean.findingsCount, 0);
    assert.equal(clean.remediationPackGenerated, false);

    // F-02: Retail Shopify store with js.stripe.com, OneTrust, Intercom, /account/login, €29/mo coffee & "subprocessors"
    const shopify = res.items[1];
    assert.equal(shopify.status, 'audited');
    assert.equal(shopify.sitePlatform, 'shopify');
    assert.equal(shopify.siteCategory, 'ecommerce_or_marketplace');
    assert.equal(shopify.isSaasOrCloudServiceDetected, false);
    assert.deepEqual(shopify.billingSdkVendors, []);
    assert.deepEqual(shopify.trustCenterGrcVendors, ['onetrust']);
    assert.deepEqual(shopify.docsStatusSupportVendors, ['intercom']);
    assert.equal(shopify.complianceScore, 100);
    assert.equal(shopify.riskTier, 'LOW');
    assert.equal(shopify.findingsCount, 0);
    assert.equal(shopify.remediationPackGenerated, false);

    // F-02: Single weak signal (js.stripe.com alone on non-SaaS choir page)
    const choir = res.items[2];
    assert.equal(choir.isSaasOrCloudServiceDetected, false);
    assert.deepEqual(choir.billingSdkVendors, []);
    assert.equal(choir.complianceScore, 100);
    assert.equal(choir.findingsCount, 0);

    assert.equal(res.billing.chargedCounts['remediation-pack-generated'], 0);
  });

  it('5. robots.txt disallow, binary PDF, SSRF & 302 IMDS redirect -> $0 url-audited charge', async () => {
    const runtime = new ApifyRuntimeAdapter();
    const res = await runBatchAudit(
      {
        urls: [
          robotsBlockedUrl,
          `${nonCompliantSaasUrl}/whitepaper.pdf`,
          'http://169.254.169.254/latest/meta-data/',
          `${nonCompliantSaasUrl}/redirect-imds`,
        ],
        respectRobotsTxt: true,
        domainDelayMs: 0,
      },
      { runtime, allowLocalhost: true },
    );

    assert.equal(res.items.length, 4);
    assert.equal(res.items[0].status, 'blocked_robots');
    assert.equal(res.items[1].status, 'error');
    assert.match(res.items[1].errorMessage || '', /application\/pdf/i);
    assert.equal(res.items[2].status, 'blocked_ssrf');
    assert.equal(res.items[3].status, 'blocked_ssrf');

    assert.equal(res.billing.chargedCounts['url-audited'], 0);
    assert.equal(res.billing.chargedCounts['remediation-pack-generated'], 0);
  });

  it('6. datasetId chaining, ".." path-traversal rejection, maxBudgetUsd + ACTOR_MAX_TOTAL_CHARGE_USD ceiling (F-07), and creator $0 run compatibility', async () => {
    const runtime = new ApifyRuntimeAdapter();

    // 6a. Exact $0.03 budget ($0.005 actor-start + $0.015 url-audited + $0.01 remediation-pack = 1 SaaS domain max)
    const capped = await runBatchAudit(
      {
        urls: [nonCompliantSaasUrl, compliantSaasUrl, cleanBakeryUrl],
        includeRemediationPack: true,
        maxBudgetUsd: 0.03,
        maxConcurrency: 1,
        domainDelayMs: 0,
      },
      { runtime, allowLocalhost: true },
    );
    assert.equal(capped.items.length, 1);
    assert.equal(capped.stoppedDueToBudgetCap, true);
    assert.ok(capped.billing.estimatedTotalUsd <= 0.03 + 1e-6);

    // 6b. F-07: Math.min(explicitMaxBudgetUsd, ACTOR_MAX_TOTAL_CHARGE_USD) & Infinity rejection
    const prevEnvCap = process.env.ACTOR_MAX_TOTAL_CHARGE_USD;
    process.env.ACTOR_MAX_TOTAL_CHARGE_USD = '0.015';
    try {
      const bmMin = new BillingManager(runtime, 50);
      assert.equal(bmMin.getSummary().maxBudgetUsd, 0.015);
      const bmInf = normalizeAuditInput({ maxBudgetUsd: Number.POSITIVE_INFINITY });
      assert.equal(bmInf.maxBudgetUsd, undefined);
    } finally {
      if (prevEnvCap === undefined) {
        delete process.env.ACTOR_MAX_TOTAL_CHARGE_USD;
      } else {
        process.env.ACTOR_MAX_TOTAL_CHARGE_USD = prevEnvCap;
      }
    }

    // 6c. Creator $0 test run ({ eventChargeLimitReached: false, chargedCount: 0 })
    const creatorRuntime = new ApifyRuntimeAdapter();
    creatorRuntime.sdkCharge = async () => ({ eventChargeLimitReached: false, chargedCount: 0 });
    const creatorRun = await runBatchAudit(
      {
        urls: [nonCompliantSaasUrl, compliantSaasUrl],
        includeRemediationPack: true,
        domainDelayMs: 0,
      },
      { runtime: creatorRuntime, allowLocalhost: true },
    );
    assert.equal(creatorRun.items.length, 2);
    assert.equal(creatorRun.stoppedDueToBudgetCap, false);

    // 6d. datasetId chaining from local storage
    const leadsDir = path.join(tempStorageDir, 'datasets', 'saas-vendor-leads');
    fs.mkdirSync(leadsDir, { recursive: true });
    fs.writeFileSync(
      path.join(leadsDir, '000000001.json'),
      JSON.stringify([
        { vendor: 'EuroStack', saasUrl: compliantSaasUrl },
        { vendor: 'Duplicate', url: compliantSaasUrl },
      ]),
      'utf8',
    );
    const chainedRun = await runBatchAudit(
      { datasetId: 'saas-vendor-leads', domainDelayMs: 0 },
      { runtime, allowLocalhost: true },
    );
    assert.equal(chainedRun.items.length, 1);
    assert.equal(chainedRun.items[0].complianceScore, 100);

    // 6e. datasetId traversal attempts must be strictly rejected
    assert.deepEqual(await runtime.loadUrlsFromDataset('..'), []);
    assert.deepEqual(await runtime.loadUrlsFromDataset('../default'), []);
    assert.deepEqual(await runtime.loadUrlsFromDataset('bad/slash'), []);
  });

  it('7. Standby /health, ACTOR_STANDBY_PORT priority, F-07 rate-slot poisoning clamp in /scan & /mcp (audit_eu_data_act_saas_switching) + CLI node dist/main.js', async () => {
    const probeSrv = await listenLocalServer((_req, res) => res.end());
    const freePort = Number(new URL(probeSrv.baseUrl).port);
    await probeSrv.close();

    const prevStandbyPort = process.env.ACTOR_STANDBY_PORT;
    process.env.ACTOR_STANDBY_PORT = String(freePort);
    let standby;
    try {
      standby = await startStandbyServer({
        host: '127.0.0.1',
        allowLocalhost: true,
      });
      assert.equal(standby.port, freePort, 'Must bind to ACTOR_STANDBY_PORT when set');
    } finally {
      if (prevStandbyPort === undefined) {
        delete process.env.ACTOR_STANDBY_PORT;
      } else {
        process.env.ACTOR_STANDBY_PORT = prevStandbyPort;
      }
    }

    const standbyBase = `http://127.0.0.1:${standby.port}`;

    try {
      // 7a. GET /health with Apify readiness probe header
      const healthRes = await fetch(`${standbyBase}/health`, {
        headers: { 'x-apify-container-server-readiness-probe': '1' },
      });
      assert.equal(healthRes.status, 200);
      const healthJson = await healthRes.json();
      assert.equal(healthJson.status, 'ok');
      assert.equal(healthJson.service, 'eu-data-act-saas-switching-auditor');
      assert.equal(healthJson.endpoints.mcp, '/mcp');

      // 7b. POST /scan enforces datasetId: undefined AND F-07 domainDelayMs <= 1000ms clamp (prevents 25-minute slot poisoning)
      const tScanStart = performance.now();
      const scanRes = await fetch(`${standbyBase}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: cleanBakeryUrl,
          datasetId: 'saas-vendor-leads',
          maxUrls: 999999,
          maxConcurrency: -50,
          domainDelayMs: 1_500_000,
          requestTimeoutMs: 60_000,
        }),
      });
      assert.equal(scanRes.status, 200);
      const scanBody = await scanRes.json();
      assert.equal(scanBody.count, 1);
      assert.equal(scanBody.items[0].complianceScore, 100);

      // Immediate second request to the SAME domain must NOT stall for 25 minutes (clamped to <= 1000ms)
      const secondScanRes = await fetch(`${standbyBase}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: cleanBakeryUrl, domainDelayMs: 0 }),
      });
      assert.equal(secondScanRes.status, 200);
      assert.ok(
        performance.now() - tScanStart < 3_000,
        'F-07 Standby domainDelayMs clamp must prevent multi-minute rate-slot poisoning',
      );

      // 7c. MCP initialize + notifications/initialized + tools/list
      const initRes = await fetch(`${standbyBase}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-03-26',
            capabilities: {},
            clientInfo: { name: 'e2e-mcp-client', version: '1.0.0' },
          },
        }),
      });
      assert.equal(initRes.status, 200);
      const initBody = await initRes.json();
      assert.equal(initBody.result.serverInfo.name, 'eu-data-act-saas-switching-auditor');

      const notifRes = await fetch(`${standbyBase}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
      });
      assert.equal(notifRes.status, 202);

      const listRes = await fetch(`${standbyBase}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }),
      });
      const listBody = await listRes.json();
      assert.deepEqual(
        listBody.result.tools.map((t) => t.name),
        ['audit_eu_data_act_saas_switching'],
      );

      // 7d. MCP tools/call rejects datasetId-only calls without url/urls
      const missingUrlRes = await fetch(`${standbyBase}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 3,
          method: 'tools/call',
          params: {
            name: 'audit_eu_data_act_saas_switching',
            arguments: { datasetId: 'saas-vendor-leads' },
          },
        }),
      });
      const missingUrlBody = await missingUrlRes.json();
      assert.equal(missingUrlBody.result.isError, true);

      // 7e. MCP tools/call (audit_eu_data_act_saas_switching) on non-compliant SaaS
      const callRes = await fetch(`${standbyBase}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 4,
          method: 'tools/call',
          params: {
            name: 'audit_eu_data_act_saas_switching',
            arguments: {
              url: nonCompliantSaasUrl,
              includeRemediationPack: true,
              maxLegalPagesPerDomain: 4,
              domainDelayMs: 0,
            },
          },
        }),
      });
      assert.equal(callRes.status, 200);
      const callBody = await callRes.json();
      assert.equal(callBody.result.isError, false);
      const report = JSON.parse(callBody.result.content[0].text);
      assert.equal(report.status, 'audited');
      assert.equal(report.egressOrSwitchingFeeFound, true);
      assert.equal(report.exportPaywallOrTierLockFound, true);
      assert.equal(report.remediationPackGenerated, true);

      // 7f. CLI Entrypoint (node dist/main.js)
      const cliDir = fs.mkdtempSync(path.join(os.tmpdir(), 'eu-data-act-cli-test-'));
      try {
        const kvsDefault = path.join(cliDir, 'key_value_stores', 'default');
        fs.mkdirSync(kvsDefault, { recursive: true });
        fs.writeFileSync(
          path.join(kvsDefault, 'INPUT.json'),
          JSON.stringify({
            urls: [compliantSaasUrl],
            domainDelayMs: 0,
          }),
          'utf8',
        );

        const { stdout } = await execFileAsync(process.execPath, ['dist/main.js'], {
          cwd: process.cwd(),
          env: {
            ...process.env,
            ALLOW_LOCALHOST_FOR_TESTS: '1',
            APIFY_LOCAL_STORAGE_DIR: cliDir,
          },
          timeout: 15_000,
        });

        assert.match(stdout, /Completed batch audit/);
        const dsFiles = fs
          .readdirSync(path.join(cliDir, 'datasets', 'default'))
          .filter((f) => f.endsWith('.json'));
        assert.equal(dsFiles.length, 1);
      } finally {
        fs.rmSync(cliDir, { recursive: true, force: true });
      }
    } finally {
      await standby.close();
    }
  });

  it('8. .actor/* schemas, pinned package.json & .dockerignore (F-10), statutory Art. 29(5)/Art. 1(5) citations (F-08), and Apify UI character limits (<=58, <=235, <=135)', async () => {
    const actorJson = JSON.parse(fs.readFileSync('.actor/actor.json', 'utf8'));
    const inputSchema = JSON.parse(fs.readFileSync('.actor/input_schema.json', 'utf8'));
    const datasetSchema = JSON.parse(fs.readFileSync('.actor/dataset_schema.json', 'utf8'));
    const ppeJson = JSON.parse(fs.readFileSync('.actor/pay_per_event.json', 'utf8'));
    const pkgJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
    const dockerignore = fs.readFileSync('.dockerignore', 'utf8');

    // F-10: Exact pinned dependency versions, scripts in .dockerignore, and complianceScore=0 note
    assert.equal(pkgJson.dependencies.apify, '3.3.2');
    assert.equal(pkgJson.devDependencies['@types/node'], '22.10.5');
    assert.equal(pkgJson.devDependencies.typescript, '5.7.3');
    assert.match(dockerignore, /^scripts$/m);
    assert.match(datasetSchema.fields.properties.complianceScore.description, /status !== "audited"/);

    assert.equal(actorJson.name, 'eu-data-act-saas-switching-auditor');
    assert.equal(actorJson.title, 'EU Data Act SaaS Switching & Zero-Egress Fee Auditor');
    assert.ok(
      actorJson.title.length <= 58,
      `actor.json title length (${actorJson.title.length}) must be <= 58`,
    );
    assert.ok(
      actorJson.description.length <= 235,
      `actor.json description length (${actorJson.description.length}) must be <= 235`,
    );
    assert.equal(actorJson.minMemoryMbytes, 256);
    assert.equal(actorJson.maxMemoryMbytes, 1024);
    assert.equal(actorJson.usesStandbyMode, true);
    assert.equal(actorJson.webServerMcpPath, '/mcp');

    assert.equal(ppeJson['actor-start'].eventPriceUsd, 0.005);
    assert.equal(ppeJson['url-audited'].eventPriceUsd, 0.015);
    assert.equal(ppeJson['remediation-pack-generated'].eventPriceUsd, 0.01);

    for (const [evKey, evDef] of Object.entries(ppeJson)) {
      assert.ok(
        evDef.eventDescription.length <= 135,
        `PPE "${evKey}" eventDescription (${evDef.eventDescription.length} chars) must be <= 135`,
      );
    }

    const defaults = normalizeAuditInput({});
    for (const [propName, propDef] of Object.entries(inputSchema.properties)) {
      if ('default' in propDef) {
        assert.equal(
          defaults[propName],
          propDef.default,
          `Default mismatch for input property "${propName}"`,
        );
      }
    }

    const runtime = new ApifyRuntimeAdapter();
    const sampleRun = await runBatchAudit(
      { urls: [nonCompliantSaasUrl], domainDelayMs: 0 },
      { runtime, allowLocalhost: true },
    );
    const liveItem = sampleRun.items[0];

    // F-08: Verify Art. 29(4)–(5), Art. 25(2)(i), Art. 40(1)–(3), and Art. 1(5) statutory precision
    const rule6 = liveItem.findings.find(
      (f) => f.ruleId === 'DATA-ACT-ART-29-4-DORA-EXIT-TRANSPARENCY-GAP',
    );
    assert.ok(rule6);
    assert.match(rule6.regulation, /Art\. 29\(4\)–\(5\)/);
    assert.match(rule6.regulation, /Art\. 25\(2\)\(i\)/);
    assert.doesNotMatch(rule6.regulation, /Art\. 26\(a\)/);
    assert.match(liveItem.remediationPack.regulatoryCoverageSummary, /Art\. 1\(5\)/);
    assert.match(liveItem.remediationPack.regulatoryCoverageSummary, /Art\. 40\(1\)–\(3\)/);

    for (const key of Object.keys(datasetSchema.fields.properties)) {
      assert.equal(
        key in liveItem,
        true,
        `Dataset schema property "${key}" must exist on EuDataActAuditReportItem`,
      );
    }
    for (const key of Object.keys(liveItem)) {
      assert.equal(
        key in datasetSchema.fields.properties,
        true,
        `EuDataActAuditReportItem property "${key}" must be documented in .actor/dataset_schema.json`,
      );
    }
  });

  it('9. Full 36-SDK matrix fingerprinting (8 billing, 8 auth, 8 trust-center, 12 docs/status/support), data-lazy-src detection & singular/plural outreach hook grammar', async () => {
    const runtime = new ApifyRuntimeAdapter();
    const matrixSrv = await listenLocalServer((req, res) => {
      const p = (req.url || '/').split('?')[0];
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      if (p === '/single-sdk') {
        res.end(`<!DOCTYPE html><html lang="en"><head><title>Single SDK SaaS</title>
          <script data-lazy-src="https://js.stripe.com/v3/"></script>
        </head><body><h1>Starter Plan SaaS $19/month</h1></body></html>`);
        return;
      }
      if (p === '/dual-sdk') {
        res.end(`<!DOCTYPE html><html lang="en"><head><title>Dual SDK SaaS</title>
          <script src="https://js.stripe.com/v3/"></script>
          <script src="https://cdn.auth0.com/js/auth0-spa-js.js"></script>
        </head><body><h1>Pro SaaS $49/month</h1></body></html>`);
        return;
      }
      res.end(`<!DOCTYPE html><html lang="en"><head><title>Full 36-SDK Matrix SaaS</title>
        <!-- 8 Billing SDKs -->
        <script src="https://js.stripe.com/v3/"></script>
        <script src="https://cdn.paddle.com/paddle/v2/paddle.js"></script>
        <script src="https://js.chargebee.com/v2/chargebee.js"></script>
        <script src="https://js.recurly.com/v4/recurly.js"></script>
        <script src="https://assets.lemonsqueezy.com/lemon.js"></script>
        <script src="https://static.zuora.com/Resources/libs/hosted/1.3.1/zuora-min.js"></script>
        <script src="https://fastspring.com/builder.js"></script>
        <script src="https://js.braintreegateway.com/web/3.97.0/js/client.min.js"></script>

        <!-- 8 Auth / Identity SDKs -->
        <script src="https://cdn.auth0.com/js/auth0.js"></script>
        <script src="https://clerk.com/npm/@clerk/clerk-js/dist/clerk.browser.js"></script>
        <script src="https://workos.com/sso.js"></script>
        <script src="https://oktacdn.com/assets/js/sdk/okta-signin-widget.js"></script>
        <script src="https://js.stytch.com/stytch.js"></script>
        <script src="https://project.supabase.co/auth/v1/client.js"></script>
        <script src="https://www.gstatic.com/firebasejs/10.7.0/firebase-auth.js"></script>
        <script src="https://myapp.auth.eu-central-1.amazoncognito.com/sdk.js"></script>

        <!-- 8 Trust Center & GRC SDKs -->
        <script src="https://trust.vanta.com/widget.js"></script>
        <script src="https://trust.drata.com/embed.js"></script>
        <script src="https://trust.safebase.io/badge.js"></script>
        <script src="https://conveyor.com/trust-widget.js"></script>
        <script src="https://whistic.com/profile.js"></script>
        <script src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js"></script>
        <script src="https://trust.secureframe.com/embed.js"></script>
        <script src="https://trust.sprinto.com/badge.js"></script>

        <!-- 12 Developer Docs, Status & Support Markers -->
        <script src="https://acme.statuspage.io/embed/script.js"></script>
        <script src="https://betterstack.com/status-widget.js"></script>
        <script src="https://acme.instatus.com/en/789/widget/script.js"></script>
        <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
        <script src="https://acme.mintlify.app/_mintlify/loader.js"></script>
        <script src="https://docs.readme.io/scripts/embed.js"></script>
        <script src="https://acme.gitbook.io/docs/embed.js"></script>
        <script src="https://docs.example.com/docusaurus.js"></script>
        <script src="https://widget.intercom.io/widget/abc123"></script>
        <script src="https://static.zdassets.com/ekr/snippet.js"></script>
        <script src="https://client.crisp.chat/l.js"></script>
        <script src="https://js.hs-scripts.com/123456.js"></script>
      </head><body>
        <h1>Enterprise Cloud Platform</h1>
      </body></html>`);
    });

    try {
      const res = await runBatchAudit(
        {
          urls: [
            `${matrixSrv.baseUrl}/`,
            `${matrixSrv.baseUrl}/single-sdk`,
            `${matrixSrv.baseUrl}/dual-sdk`,
          ],
          includeRemediationPack: false,
          maxLegalPagesPerDomain: 0,
          domainDelayMs: 0,
        },
        { runtime, allowLocalhost: true },
      );

      assert.equal(res.items.length, 3);
      const full = res.items[0];
      assert.equal(full.billingSdkVendors.length, 8);
      assert.equal(full.authIdentityVendors.length, 8);
      assert.equal(full.trustCenterGrcVendors.length, 8);
      assert.equal(full.docsStatusSupportVendors.length, 12);

      const single = res.items[1];
      assert.deepEqual(single.billingSdkVendors, ['stripe-billing']);
      assert.match(single.coldOutreachHook, /Stripe Billing powers your SaaS stack/);

      const dual = res.items[2];
      assert.deepEqual(dual.billingSdkVendors, ['stripe-billing']);
      assert.deepEqual(dual.authIdentityVendors, ['auth0']);
      assert.match(dual.coldOutreachHook, /Stripe Billing \+ Auth0 power your SaaS stack/);
    } finally {
      await matrixSrv.close();
    }
  });

  it('10. Red-team regression suite (F-03..F-09): O(N) unclosed HTML (<250ms), cross-sentence + sub-$1/GB egress + clause-initial deletion catches, provider-notice / adjacent-card / trial / DSAR false-positive suppression, HTML escaping, first-party subdomain + off-domain redirect guard, DORA financial gate, self-remediation round-trip 100/100, 302 $0 billing & /mcp batch >20 HTTP 400', async () => {
    // 10a. Adversarial unclosed HTML (`<a>` x 200k + `<!--` x 50k + `<` x 200k) parses in < 250ms
    const adversarialHtml =
      '<a>'.repeat(200_000) +
      '<!--'.repeat(50_000) +
      '<'.repeat(200_000) +
      '<div ' +
      'role="switch" '.repeat(15_000) +
      '>';
    const t0 = performance.now();
    const parsedAdv = parseHtmlDocument(adversarialHtml, 'https://adversarial.example.com/');
    const elapsedMs = performance.now() - t0;
    assert.ok(elapsedMs < 250, `Expected O(N) parse < 250ms, got ${elapsedMs.toFixed(1)}ms`);
    assert.equal(parsedAdv.anchors.length, 0);

    // 10b. F-06: HTML escaping on untrusted domain string
    assert.equal(escapeHtml('evil"><script>alert(1)</script>'), 'evil&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;');
    const escapedPack = generateRemediationPack({
      domain: 'evil.example.com"><script>alert(1)</script>',
      sitePlatform: 'custom',
      siteCategory: 'b2b_or_b2c_saas',
      billingSdkVendors: ['paddle'],
      authIdentityVendors: [],
      trustCenterGrcVendors: [],
    });
    assert.doesNotMatch(escapedPack.euDataActSwitchingAddendumHtml, /<script>alert\(1\)<\/script>/);
    assert.doesNotMatch(escapedPack.onlinePortabilityRegisterAndArt28Html, /<script>alert\(1\)<\/script>/);
    assert.match(escapedPack.euDataActSwitchingAddendumHtml, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);

    const runtime = new ApifyRuntimeAdapter();

    // Generate real RemediationPack from non-compliant SaaS for round-trip verification
    const badRun = await runBatchAudit(
      { urls: [nonCompliantSaasUrl], includeRemediationPack: true, domainDelayMs: 0 },
      { runtime, allowLocalhost: true },
    );
    const pack = badRun.items[0].remediationPack;
    assert.ok(pack);

    let subdomainPort = 0;
    const edgeSrv = await listenLocalServer((req, res) => {
      const hostHeader = (req.headers.host || '').split(':')[0].toLowerCase();
      const p = (req.url || '/').split('?')[0];

      // F-09: First-party subdomain `trust.saas-f09.example.com` vs off-domain redirect target `external-vendor.org`
      if (hostHeader === 'saas-f09.example.com' && p === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<!DOCTYPE html><html lang="en"><head><title>F09 DevTools SaaS</title>
          <script src="https://cdn.paddle.com/paddle/v2/paddle.js"></script>
          <script src="https://trust.vanta.com/widget.js"></script>
        </head><body>
          <h1>Developer Productivity SaaS — €19 per seat (Cancel at any time without penalty)</h1>
          <p>EU Data Act Addendum (Regulation (EU) 2023/2854): ≤2-month notice (Art. 25(2)(d)), 30-calendar-day transitional period (Art. 25(2)(a)), 30-calendar-day data retrieval period (Art. 25(2)(g)), €0 switching &amp; €0 egress charges across all plans.</p>
          <p>Article 26(b) Online Portability Register: All exportable data categories (Art. 25(2)(e)) are available via free OpenAPI 3.1 endpoints in JSON and CSV formats.</p>
          <footer>
            <a href="http://trust.saas-f09.example.com:${subdomainPort}/security">Security &amp; Jurisdiction</a>
            <a href="http://legal.saas-f09.example.com:${subdomainPort}/terms">Terms (Redirects Off-Domain)</a>
          </footer>
        </body></html>`);
        return;
      }
      if (hostHeader === 'trust.saas-f09.example.com' && p === '/security') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<!DOCTYPE html><html lang="en"><head><title>Trust Subdomain</title></head><body>
          <h1>Cloud Hosting Jurisdiction &amp; Non-Personal Data Safeguards</h1>
          <p>Our cloud infrastructure is subject to the laws and jurisdiction of the United States and Ireland (Art. 28(1)(a)). We apply AES-256-GCM encryption and strict legal-challenge controls to prevent unlawful international governmental access to non-personal data held in the Union (Art. 28(1)(b) &amp; Art. 32).</p>
        </body></html>`);
        return;
      }
      if (hostHeader === 'legal.saas-f09.example.com' && p === '/terms') {
        res.writeHead(302, {
          Location: `http://external-vendor.org:${subdomainPort}/poisoned-terms`,
        });
        res.end();
        return;
      }
      if (hostHeader === 'external-vendor.org' && p === '/poisoned-terms') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<!DOCTYPE html><html><body><p>Data export: Enterprise only. $900 offboarding fee.</p></body></html>`);
        return;
      }

      if (p === '/empty-302') {
        res.writeHead(302, { 'Content-Type': 'text/html' });
        res.end('');
        return;
      }
      if (p === '/cross-sentence-paywall') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<!DOCTYPE html><html lang="en"><head><title>Cross-Sentence Paywall SaaS</title>
          <script src="https://cdn.paddle.com/paddle/v2/paddle.js"></script>
        </head><body>
          <p>Don't wait! Data export requires Enterprise plan ($500 offboarding fee).</p>
        </body></html>`);
        return;
      }
      if (p === '/sub-dollar-egress-and-clause-initial-deletion') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<!DOCTYPE html><html lang="en"><head><title>Sub-Dollar Egress &amp; Clause-Initial Deletion</title>
          <script src="https://cdn.paddle.com/paddle/v2/paddle.js"></script>
        </head><body>
          <p>Outbound transfers incur a $0.09/GB data egress fee and €0.12 per GB outbound data transfer charge.</p>
          <p>Upon subscription cancellation, all customer workspace data will be permanently deleted within 14 days.</p>
        </body></html>`);
        return;
      }
      if (p === '/compliant-edge') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<!DOCTYPE html><html lang="en"><head><title>Compliant Edge SaaS</title>
          <script src="https://cdn.paddle.com/paddle/v2/paddle.js"></script>
          <script src="https://trust.vanta.com/widget.js"></script>
        </head><body>
          <h1>Transparent SaaS Pricing &amp; EU Data Act Compliance</h1>
          <!-- F-04: Adjacent pricing cards must NEVER trigger EXPORT_PAYWALL_RE -->
          <p>Starter Plan: Full CSV/JSON data export. Enterprise Plan: SAML SSO &amp; Dedicated CSM.</p>
          <p>$0 egress fee / no offboarding fee / deleted after 30-day retrieval period. Data egress fee of $0.00/GB across all plans, and free data export on all plans via OpenAPI JSON/CSV.</p>
          <!-- F-03: Provider-given notices & pen-test notices must NEVER trigger EXCESSIVE_NOTICE_PERIOD_RE -->
          <p>We will provide at least 90 days prior written notice before terminating a legacy API endpoint or updating subscription prices. Customer must provide 90 days advance written notice prior to conducting a penetration test.</p>
          <!-- F-05: Ephemeral tokens, free trials & GDPR Art. 17 DSAR erasure must NEVER trigger short retention -->
          <p>Session tokens and temporary cache files are deleted within 24 hours of session expiration. Free trial workspaces are deleted within 7 days of trial expiration. Upon written request by the customer under a GDPR Art. 17 erasure request, personal data is deleted within 14 days.</p>
          ${pack.euDataActSwitchingAddendumHtml}
          ${pack.onlinePortabilityRegisterAndArt28Html}
        </body></html>`);
        return;
      }
      if (p === '/remediated-home') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<!DOCTYPE html><html lang="en"><head><title>Remediated CloudPulse SaaS</title>
          <script src="https://js.stripe.com/v3/"></script>
          <script src="https://cdn.auth0.com/js/auth0-spa-js.js"></script>
          <script src="https://static.vanta.com/trust-badge.js"></script>
          <script src="https://cloudpulse.statuspage.io/embed/script.js"></script>
        </head><body>
          <h1>CloudPulse SaaS — Starter $49/month per seat &amp; Enterprise $199/month per seat</h1>
          ${pack.pricingZeroEgressDisclosureWidgetHtmlJs}
          <footer>
            <a href="/data-act">EU Data Act Switching Addendum</a>
            <a href="/portability-register">Art. 26(b) Online Portability Register &amp; Art. 28 Notice</a>
          </footer>
        </body></html>`);
        return;
      }
      if (p === '/data-act') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<!DOCTYPE html><html lang="en"><head><title>EU Data Act Addendum</title></head><body>${pack.euDataActSwitchingAddendumHtml}</body></html>`);
        return;
      }
      if (p === '/portability-register') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<!DOCTYPE html><html lang="en"><head><title>Online Portability Register</title></head><body>${pack.onlinePortabilityRegisterAndArt28Html}</body></html>`);
        return;
      }
      res.writeHead(404);
      res.end();
    });
    subdomainPort = Number(new URL(edgeSrv.baseUrl).port);

    try {
      // 10c. Cross-sentence "Don't wait! Data export requires Enterprise plan ($500 offboarding fee)" MUST be caught
      const crossRes = await runBatchAudit(
        {
          urls: [`${edgeSrv.baseUrl}/cross-sentence-paywall`],
          includeRemediationPack: false,
          maxLegalPagesPerDomain: 0,
          domainDelayMs: 0,
        },
        { runtime, allowLocalhost: true },
      );
      const crossItem = crossRes.items[0];
      assert.equal(crossItem.egressOrSwitchingFeeFound, true);
      assert.equal(crossItem.exportPaywallOrTierLockFound, true);
      assert.ok(
        crossItem.findings.some(
          (f) => f.ruleId === 'DATA-ACT-ART-29-30-EGRESS-FEE-OR-EXPORT-PAYWALL',
        ),
      );

      // 10d. F-04 & F-05: Sub-$1/GB currency-first egress fee ("$0.09/GB data egress fee") & clause-initial deletion ("Upon subscription cancellation, all customer workspace data will be permanently deleted within 14 days.") MUST be caught
      const subDollarRes = await runBatchAudit(
        {
          urls: [`${edgeSrv.baseUrl}/sub-dollar-egress-and-clause-initial-deletion`],
          includeRemediationPack: false,
          maxLegalPagesPerDomain: 0,
          domainDelayMs: 0,
        },
        { runtime, allowLocalhost: true },
      );
      const subDollarItem = subDollarRes.items[0];
      assert.equal(subDollarItem.egressOrSwitchingFeeFound, true);
      assert.ok(subDollarItem.egressAndExportInterfaceCheck.egressFeeMatches.length >= 2);
      assert.equal(subDollarItem.shortPostTerminationRetentionFound, true);

      // 10e. F-03, F-04, F-05: Compliant edge page (adjacent cards, provider 90-day notice, pen-test notice, session tokens, free trials, GDPR Art. 17 DSAR erasure, $0 egress) -> 0 false positives!
      const compRes = await runBatchAudit(
        {
          urls: [`${edgeSrv.baseUrl}/compliant-edge`],
          includeRemediationPack: true,
          maxLegalPagesPerDomain: 0,
          domainDelayMs: 0,
        },
        { runtime, allowLocalhost: true },
      );
      const compItem = compRes.items[0];
      assert.equal(compItem.status, 'audited');
      assert.equal(compItem.egressOrSwitchingFeeFound, false);
      assert.equal(compItem.exportPaywallOrTierLockFound, false);
      assert.equal(compItem.shortPostTerminationRetentionFound, false);
      assert.equal(compItem.excessiveNoticePeriodLockInFound, false);
      assert.equal(
        compItem.findingsCount,
        0,
        `Unexpected findings on compliant-edge: ${JSON.stringify(compItem.findings)}`,
      );
      assert.equal(compItem.complianceScore, 100);
      assert.equal(compItem.remediationPackGenerated, false);

      // 10f. F-09: First-party `trust.saas-f09.example.com` subdomain fetched + off-domain redirect discarded + non-financial Vanta SaaS skips DORA gap -> 100/100!
      const f09Res = await runBatchAudit(
        {
          urls: [`http://saas-f09.example.com:${subdomainPort}/`],
          includeRemediationPack: true,
          maxLegalPagesPerDomain: 4,
          domainDelayMs: 0,
        },
        {
          runtime,
          allowLocalhost: true,
          dnsLookup: async () => [{ address: '127.0.0.1', family: 4 }],
        },
      );
      const f09Item = f09Res.items[0];
      assert.equal(f09Item.status, 'audited');
      assert.ok(
        f09Item.pagesFetched.some((u) => u.includes('trust.saas-f09.example.com')),
        'Must discover and fetch first-party trust.<domain> subdomain',
      );
      assert.ok(
        !f09Item.pagesFetched.some((u) => u.includes('external-vendor.org')),
        'Must discard subpages redirecting to an external registrable domain',
      );
      assert.equal(f09Item.art28IctJurisdictionDisclosed, true);
      assert.equal(f09Item.art29EarlyTerminationAndDoraExitGapFound, false);
      assert.equal(
        f09Item.findingsCount,
        0,
        `Unexpected findings on F-09 SaaS: ${JSON.stringify(f09Item.findings)}`,
      );
      assert.equal(f09Item.complianceScore, 100);

      // 10g. Self-remediation round-trip scores 100, findingsCount: 0, remediationPackGenerated: false
      const remRes = await runBatchAudit(
        {
          urls: [`${edgeSrv.baseUrl}/remediated-home`],
          includeRemediationPack: true,
          maxLegalPagesPerDomain: 4,
          domainDelayMs: 0,
        },
        { runtime, allowLocalhost: true },
      );
      const remItem = remRes.items[0];
      assert.equal(
        remItem.findingsCount,
        0,
        `Self-remediation must produce 0 findings, got: ${JSON.stringify(remItem.findings)}`,
      );
      assert.equal(remItem.complianceScore, 100);
      assert.equal(remItem.riskTier, 'LOW');
      assert.equal(remItem.remediationPackGenerated, false);

      // 10h. Unredirected 302 empty Location charges $0 url-audited
      const redirectRuntime = new ApifyRuntimeAdapter();
      const redirRes = await runBatchAudit(
        {
          urls: [`${edgeSrv.baseUrl}/empty-302`],
          includeRemediationPack: true,
          domainDelayMs: 0,
        },
        { runtime: redirectRuntime, allowLocalhost: true },
      );
      assert.equal(redirRes.items[0].status, 'error');
      assert.equal(redirRes.billing.chargedCounts['url-audited'], 0);
      assert.equal(redirRes.billing.chargedCounts['remediation-pack-generated'], 0);

      // 10i. /mcp batch > 20 returns HTTP 400 (-32600)
      const standby = await startStandbyServer({
        port: 0,
        host: '127.0.0.1',
        allowLocalhost: true,
      });
      try {
        const oversizedBatch = Array.from({ length: 21 }, (_, idx) => ({
          jsonrpc: '2.0',
          id: idx + 1,
          method: 'ping',
        }));
        const batchRes = await fetch(`http://127.0.0.1:${standby.port}/mcp`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(oversizedBatch),
        });
        assert.equal(batchRes.status, 400);
        const batchErr = await batchRes.json();
        assert.equal(batchErr.error.code, -32600);
      } finally {
        await standby.close();
      }
    } finally {
      await edgeSrv.close();
    }
  });
});
