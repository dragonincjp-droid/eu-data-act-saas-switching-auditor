# EU Data Act SaaS Switching & Zero-Egress Fee Auditor (API + MCP Server)

**Bulk-audit 1,000+ B2B/B2C SaaS platforms, PaaS/IaaS cloud services, developer APIs, and hosted AI sites in minutes via ultra-fast, zero-browser HTTP for the binding `12 January 2027` EU Data Act (`Regulation (EU) 2023/2854`, Chapter VI: Articles 23–32) `€0` switching & data egress fee cliff, `Art. 30(2)` free open export interfaces, `Art. 25` switching contracts, `Art. 26(b)` online portability registers, `Art. 28/32` ICT jurisdiction & non-personal gov-access disclosures, and EU DORA exit readiness.**

Outputs a deterministic `complianceScore` (`0–100`), prioritized `findings[]`, **36-SDK SaaS/Billing/Auth/Trust-Center/Docs fingerprint** (`billingSdkVendors`, `authIdentityVendors`, `trustCenterGrcVendors`, `docsStatusSupportVendors`), neutral B2B `coldOutreachHook`, and 3 ready-to-paste HTML/JS compliance artifacts:
1. **`euDataActSwitchingAddendumHtml`** — Complete EU Data Act Chapter VI Cloud/SaaS Switching Addendum aligned with **`Commission Recommendation (EU) 2026/2394`** (adopted 29 October 2026, OJ 6 November 2026) & **EU DORA `Art. 30(2)(h)`**
2. **`onlinePortabilityRegisterAndArt28Html`** — **`Art. 26(b)`** Online Exportable Data Structures & Formats Register + **`Art. 28(1)` / `Art. 32`** ICT Hosting Jurisdiction & Non-Personal Data Governmental-Access Safeguards page
3. **`pricingZeroEgressDisclosureWidgetHtmlJs`** — Zero-dependency `/pricing` & checkout `€0` switching/egress & `Art. 29(4)` fixed-term transparency widget

Zero OpenAI/LLM keys required. Built for **EU/UK Tech & Data-Privacy Law Firms**, **GRC & Trust-Center Platforms (`Vanta`, `Drata`, `SafeBase`, `Conveyor`, `OneTrust`, `Secureframe`, `Sprinto`)**, **Cloud Migration & FinOps Consultancies**, **Enterprise Procurement / DORA Vendor Risk Teams**, **Clay**, **n8n**, **Apify Dataset Chaining**, and **AI Agents via MCP (`Claude Desktop`, `Cursor`, `Windsurf`)**.

---

## Late-2026 EU Data Act & Cloud Switching Enforcement Landscape (Verified Statutory Accuracy)

1. **EU Data Act (`Regulation (EU) 2023/2854`, Chapter VI: Articles 23–32 — Applicable since 12 September 2025 under `Art. 50`)**
   - **Extraterritorial Scope (`Art. 1(3)(f)` & `Art. 2(8)`)**: Applies to all providers of *"data processing services"* (SaaS, PaaS, IaaS, cloud APIs, hosted AI/LLM workspaces) serving customers in the EU, regardless of whether the SaaS company is headquartered in the US, UK, EU, or APAC.
   - **`Article 29(1)` Mandatory `€0` Switching & Data Egress Fee Cliff on `12 January 2027`**:
     - From **12 January 2027**, providers *"shall not impose any switching charges on the customer for the switching process"*.
     - Under **`Art. 2(35)–(36)`**, switching charges explicitly include **data egress charges** (network extraction/transfer fees), excluding only standard ongoing subscription fees and proportionate early-termination penalties for fixed-term contracts (`Art. 29(4)`). Transitional reduced at-cost switching fees (`Art. 29(2)–(3)`) expire permanently on 12 January 2027 (continuous multi-cloud *in-parallel* egress pass-through at cost remains governed separately by **`Art. 34(2)`**).
   - **`Article 30(1)–(2)` Technical Switching Duties & Ban on `"Enterprise-Only"` Export Paywalls**:
     - While `Art. 30(1)` governs IaaS functional equivalence, **`Art. 30(2)`** mandates that **PaaS and SaaS providers make open interfaces (`APIs` / structured, commonly used, machine-readable bulk export) publicly available and free of charge** to facilitate switching. Locking `CSV`/`JSON`/`API` customer data export behind `"Enterprise Plan Only"` violates `Art. 23`, `Art. 29(1)`, and `Art. 30(2)`.
   - **`Article 25(1)–(5)` Mandatory Written Switching Contract Clauses**:
     - **`Art. 25(2)(d)`**: Maximum notice period to initiate switching **≤ 2 months** (flags legacy `90-day` prior written notice lock-ins lacking an EU Data Act override).
     - **`Art. 25(2)(a)` & `(4)`**: Maximum **≤ 30 calendar days** transitional period to port exportable data and digital assets while maintaining business continuity and high security (provider may extend up to 7 months *only* if technically unfeasible and notified with reasoned justification within 14 working days; customer may extend once freely under `Art. 25(5)`).
     - **`Art. 25(2)(e)–(f)`**: Exhaustive specification of all exportable data & digital asset categories AND exempted provider internal trade-secret categories.
     - **`Art. 25(2)(g)–(h)`**: Minimum **≥ 30 calendar days** post-transition data retrieval period, followed by **guaranteed full erasure** (flags SaaS Terms stating customer data is *"deleted immediately upon termination"* or *"erased within 7 / 14 days of cancellation"*).
   - **`Article 26(b)` Provider-Hosted Online Portability Register** *(strictly distinct from `Art. 28`)*:
     - Providers must maintain and reference an **up-to-date online register hosted by the provider** detailing **all data structures and data formats as well as relevant standards and open interoperability specifications** in which exportable data (`Art. 25(2)(e)`) are available.
   - **`Article 28(1)(a)–(b)` & `Article 32` Website Transparency on ICT Jurisdiction & Non-Personal Data Governmental Access**:
     - **`Art. 28(1)(a)`**: Publish on the website the **jurisdiction** to which the ICT infrastructure deployed for data processing is subject.
     - **`Art. 28(1)(b)` & `Art. 32`**: Publish on the website a general description of technical, organisational, and contractual measures adopted to prevent unlawful international governmental access to or transfer of **non-personal data** held in the Union *(standard GDPR privacy policies covering only personal data do NOT satisfy `Art. 28(1)(b)` for non-personal B2B SaaS data!)*.
   - **`Article 41` & `Commission Recommendation (EU) 2026/2394` (Adopted 29 October 2026, OJ 6 November 2026)**:
     - Official European Commission non-binding Standard Contractual Clauses (6 cloud switching clause sets) referenced by `Art. 10` dispute settlement bodies and national competent authorities.
   - **`Article 37` & `Article 40` Penalties + `Article 1(5)` Parallel GDPR Exposure**:
     - Chapter VI is enforced by designated competent authorities (`Art. 37`) under Member State **`Art. 40(1)–(3)`** penalty laws (e.g. Germany draft Data Act Implementation Act up to **€5M or 4% of annual global turnover**, France SREN/DDADUE up to **3%–5% of global turnover**), while **`Art. 1(5)`** preserves parallel **GDPR `Art. 83(5)` fines up to €20M or 4% of global turnover** where personal data portability/erasure intersects (`Art. 40(4)` directly cross-references Chapters II, III & V), alongside civil unenforceability of unfair B2B switching barriers. *(Note: the Nov 2025 Digital Omnibus proposal remains unadopted as of late 2026, so the enacted 2023 Regulation applies in full.)*
2. **Complementary Cloud/SaaS Exit Regimes**:
   - **EU DORA (`Regulation (EU) 2022/2554`, `Art. 28(8)` & `Art. 30(2)(h)`, applicable since 17 Jan 2025)**: Mandatory documented ICT exit strategies, transition periods, and guaranteed machine-readable data return for SaaS vendors serving financial-sector clients.
   - **UK CMA Cloud Services Market Investigation (2025–2026 switching/egress remedies)** & **US FTC Section 5 B2B SaaS Lock-In scrutiny**.

### B2B Legal, GRC & Cloud Consultancy Lead-Gen ROI Math

| Metric | Manual SaaS MSA / Trust-Center / Pricing Audit | Bulk HTTP Audit (`healthy_addax/eu-data-act-saas-switching-auditor`) |
| :--- | :--- | :--- |
| **1,000 SaaS / Cloud Vendors Audited** | ~180 hours of legal & DevOps review | **~3–6 minutes (zero-Playwright HTTP engine)** |
| **Cost for 1,000 Domains** | $9,000+ legal/GRC analyst time | **`$15.005`** (audit + hooks) or **`$25.005`** (with 3-part HTML/JS packs) |
| **Deliverables Included** | Manual spreadsheet notes | **36-SDK stack + 6 EU Data Act/DORA checks + outreach hook + Art. 25 Addendum + Art. 26(b)/28 Register + €0 Egress JS** |
| **Apify Free Tier (`$5.00/mo` credit)** | — | **Audit ~199 to ~333 SaaS domains every month for `$0`** |

> **Fair Pay-Per-Event Billing & Zero False-Positive Guarantee:**
> - Invalid URLs, unreachable hosts, non-HTML binary files (`application/pdf`), `robots.txt`-disallowed pages, unredirected `302` errors, and SSRF-blocked targets are **never billed (`$0`)**.
> - Clean non-SaaS brochure, bakery, restaurant, and personal blog sites return **`complianceScore: 100` (`LOW` risk, `0` findings)** and are **never billed for remediation packs (`$0`)**.

---

## Core Deterministic Rules & 36-SDK Fingerprinting

For every domain (full URLs or bare domains like `acmecloud.io`), the Actor inspects the homepage plus up to `maxLegalPagesPerDomain` (default `4`, max `6`) auto-discovered internal subpages (`/data-act`, `/cloud-switching`, `/portability`, `/terms`, `/tos`, `/msa`, `/legal`, `/dpa`, `/pricing`, `/plans`, `/trust`, `/security`, `/subprocessors`, `/compliance`, `/docs/export`, `/api`):

- **36 Fingerprinted SaaS / Cloud / GRC / Docs SDKs**:
  - **Billing (8)**: `stripe-billing`, `paddle`, `chargebee`, `recurly`, `lemon-squeezy`, `zuora`, `fastspring`, `braintree`
  - **Auth / B2B Identity (8)**: `auth0`, `clerk`, `workos`, `okta`, `stytch`, `supabase-auth`, `firebase-auth`, `cognito`
  - **Trust Center & GRC (8)**: `vanta`, `drata`, `safebase`, `conveyor`, `whistic`, `onetrust`, `secureframe`, `sprinto`
  - **Docs, Status & Support (12)**: `statuspage`, `betterstack`, `instatus`, `swagger-openapi`, `mintlify`, `readme-io`, `gitbook`, `docusaurus`, `intercom`, `zendesk`, `crisp`, `hubspot`
- **6 Statutory Rules**:
  1. `DATA-ACT-ART-29-30-EGRESS-FEE-OR-EXPORT-PAYWALL` (`CRITICAL`, `-32` pts): Explicit egress/offboarding/extraction fee or `"Enterprise-only"` CSV/JSON/API export paywall without an `Art. 29(1)` `€0` switching & `Art. 30(2)` free open-interface guarantee.
  2. `DATA-ACT-ART-25-RETENTION-OR-NOTICE-LOCKIN` (`CRITICAL`, `-28` pts): Immediate or `< 30-day` post-termination data deletion (`Art. 25(2)(g)`) or `> 2-month` (`65–365 day`) prior written notice lock-in (`Art. 25(2)(d)`).
  3. `DATA-ACT-ART-25-MISSING-SWITCHING-ADDENDUM` (`HIGH`, `-22` pts): Active SaaS/cloud platform lacks a published Chapter VI Cloud Switching Addendum (`Art. 25` & `Rec. (EU) 2026/2394`).
  4. `DATA-ACT-ART-26B-MISSING-ONLINE-PORTABILITY-REGISTER` (`HIGH`, `-16` pts): Missing `Art. 26(b)` provider-hosted Online Register of exportable data structures, machine-readable formats (`JSON`/`CSV`/`Parquet`/`OpenAPI`), and trade-secret exemptions (`Art. 25(2)(e)–(f)`).
  5. `DATA-ACT-ART-28-32-MISSING-JURISDICTION-GOV-ACCESS-NOTICE` (`MEDIUM`, `-14` pts): Missing `Art. 28(1)(a)` ICT hosting jurisdiction or `Art. 28(1)(b)` / `Art. 32` safeguards preventing unlawful foreign governmental access to **non-personal** EU data.
  6. `DATA-ACT-ART-29-4-DORA-EXIT-TRANSPARENCY-GAP` (`MEDIUM`, `-10` pts): Fixed-term non-cancellable contracts or enterprise/SOC 2/fintech SaaS offerings lacking `Art. 29(4)` proportionate early-termination methodology or EU DORA (`Art. 30(2)(h)`) documented exit-strategy terms.

---

## Connect as an AI Agent MCP Tool (`Claude Desktop`, `Cursor`, `Windsurf`)

This Actor natively runs an **Apify Standby Streamable HTTP MCP Server** (`/mcp`) exposing `audit_eu_data_act_saas_switching`:

- **Hosted Apify MCP URL**: `https://mcp.apify.com/?tools=healthy_addax/eu-data-act-saas-switching-auditor`

```json
{
  "mcpServers": {
    "eu-data-act-saas-switching-auditor": {
      "url": "https://mcp.apify.com/?tools=healthy_addax/eu-data-act-saas-switching-auditor",
      "headers": {
        "Authorization": "Bearer <YOUR_APIFY_TOKEN>"
      }
    }
  }
}
```

---

## Complete 6-Actor US + UK + EU + ADA + Privacy + Cloud SaaS Compliance Suite

| Compliance Layer | Actor | Engine & Speed |
| :--- | :--- | :--- |
| **EU Data Act (`Reg. 2023/2854`) Jan 2027 `€0` SaaS/Cloud Egress, `Art. 25` Switching, `Art. 26(b)` Register, `Art. 28` Jurisdiction & `DORA`** | **`healthy_addax/eu-data-act-saas-switching-auditor`** *(This Actor)* | **Zero-Playwright Pinned HTTP** (~150–400ms/domain, `$0.015`/domain) |
| **US Click-to-Cancel, Auto-Renewal Laws (`CA AB 2863`, `NY/NYC ARL`, `CO SB 25-145 B2B SaaS`), `ROSCA` & `CA SB 478` Drip Fees** | **[`healthy_addax/us-click-to-cancel-auditor`](https://apify.com/healthy_addax/us-click-to-cancel-auditor)** | **Zero-Playwright Pinned HTTP** (~150–400ms/site, `$0.015`/site) |
| **CIPA Wiretap (`§§ 631/632`), VPPA Video Pixels (`18 U.S.C. § 2710`), HIPAA/MHMDA Intake Trackers & `GPC`/`CCPA` Opt-Outs** | **[`healthy_addax/cipa-vppa-wiretap-pixel-auditor`](https://apify.com/healthy_addax/cipa-vppa-wiretap-pixel-auditor)** | **Zero-Playwright Pinned HTTP** (~150–400ms/site, `$0.015`/site) |
| **ADA Title III / WCAG 2.2 Level AA, European Accessibility Act (`EAA`) & Overlay Widgets (`accessiBe`/`UserWay`)** | **[`healthy_addax/wcag-eaa-ada-auditor`](https://apify.com/healthy_addax/wcag-eaa-ada-auditor)** | **Headless Chromium + `axe-core`** (Red-box PNG visual proof + HTML diffs) |
| **EU Withdrawal Button (`Directive 2023/2673 Art. 11a`), Dead EU ODR Links, `EmpCo` Green Claims & `Omnibus` 30-Day Pricing** | **[`healthy_addax/eu-withdrawal-omnibus-auditor`](https://apify.com/healthy_addax/eu-withdrawal-omnibus-auditor)** | **Zero-Playwright Pinned HTTP** (~150–400ms/store, `$0.015`/store) |
| **US FTC `16 CFR Part 465` Fake Reviews, UK `DMCC` Review Policy & Drip Pricing, EU `Omnibus Art. 7(6)` & Pre-Checked Add-Ons** | **[`healthy_addax/fake-reviews-dmcc-drip-pricing-auditor`](https://apify.com/healthy_addax/fake-reviews-dmcc-drip-pricing-auditor)** | **Zero-Playwright Pinned HTTP** (~150–400ms/store, `$0.015`/store) |

---

## Legal Disclaimer

> **Automated technical heuristic signals for human review only; does not constitute legal advice or formal regulatory certification.**
>
> Static HTTP HTML inspection identifies publicly visible SaaS/cloud SDKs, pricing tables, Terms/MSA switching clauses, Online Portability Registers, and ICT jurisdiction notices on inspected pages. Private enterprise MSAs, bespoke custom-built cloud architectures (`Art. 31` exemptions), authenticated customer admin consoles, or Member State penalty determinations require review by qualified EU technology and regulatory counsel.
