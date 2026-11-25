import type {
  Art25SwitchingContractCheckResult,
  Art26bAndArt28TransparencyCheckResult,
  Art29TerminationAndDoraExitCheckResult,
  AuthIdentityVendor,
  BillingSdkVendor,
  ComplianceFinding,
  DiscoveredSaasComplianceLinks,
  EgressAndExportInterfaceCheckResult,
  RecommendedNextAudit,
  RemediationPack,
  RiskTier,
  SiteCategory,
  SitePlatform,
  TrustCenterGrcVendor,
} from './types.js';

export function escapeHtml(raw: string): string {
  return raw
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export const EU_DATA_ACT_STATUTORY_SUMMARY =
  'Late-2026 EU cloud & SaaS switching enforcement spans two binding EU regulations plus UK/US lock-in scrutiny: (1) EU Data Act (Regulation (EU) 2023/2854, Chapter VI: Articles 23–32, applicable since 12 September 2025 under Art. 50; extraterritorial under Art. 1(3)(f) to all SaaS, PaaS, IaaS, cloud API, and hosted AI providers serving EU customers regardless of establishment) — enforcing the 12 January 2027 mandatory €0 switching & data egress fee cliff (Art. 29(1) & Art. 2(35)–(36), permanently ending transitional at-cost switching fees under Art. 29(2)–(3), while continuous in-parallel multi-cloud pass-through remains governed by Art. 34(2)), pre-contractual disclosure of standard service fees & proportionate fixed-term early-termination penalties (Art. 29(4)–(5) & Art. 25(2)(i)), free-of-charge open interfaces / machine-readable bulk export across all SaaS/PaaS tiers (Art. 30(2)), mandatory written switching contracts (Art. 25(2): ≤2-month initiation notice [Art. 25(2)(d)], ≤30-calendar-day transitional period with service continuity [Art. 25(2)(a) & (4)], exhaustive exportable data & trade-secret exemption lists [Art. 25(2)(e)–(f)], and ≥30-calendar-day post-transition data retrieval followed by guaranteed full erasure [Art. 25(2)(g)–(h)]), provider-hosted online registers of exportable data structures, formats & open interoperability specs (Art. 26(b)), website disclosures of ICT infrastructure jurisdiction & safeguards preventing unlawful international governmental access to non-personal data held in the Union (Art. 28(1)(a)–(b) & Art. 32), official European Commission Cloud Switching Standard Contractual Clauses (Commission Recommendation (EU) 2026/2394, adopted 29 October 2026, OJ 6 November 2026), and competent-authority enforcement (Art. 37) under national Art. 40(1)–(3) penalty laws (e.g. Germany draft Data Act Implementation Act up to €5M or 4% of global turnover, France SREN/DDADUE up to 3%–5% of global turnover), while Art. 1(5) preserves parallel GDPR Art. 83(5) (€20M or 4% of global turnover) supervisory enforcement where personal data portability/erasure intersects (Art. 40(4) directly cross-references Chapters II, III & V; note also that the Nov 2025 Digital Omnibus proposal remains unadopted as of late 2026); and (2) EU DORA (Regulation (EU) 2022/2554, Art. 28(8) & Art. 30(2)(h), applicable since 17 January 2025) requiring documented ICT exit strategies and guaranteed machine-readable data return for SaaS vendors serving financial entities, alongside UK CMA Cloud Services Market Investigation switching scrutiny and US FTC Section 5 B2B lock-in enforcement.';

export function buildFindingsAndScore(params: {
  homeUrl: string;
  isSaasOrCloudServiceDetected: boolean;
  discoveredLinks: DiscoveredSaasComplianceLinks;
  egressCheck: EgressAndExportInterfaceCheckResult;
  art25Check: Art25SwitchingContractCheckResult;
  art26b28Check: Art26bAndArt28TransparencyCheckResult;
  art29DoraCheck: Art29TerminationAndDoraExitCheckResult;
}): {
  findings: ComplianceFinding[];
  complianceScore: number;
  riskTier: RiskTier;
} {
  const {
    homeUrl,
    isSaasOrCloudServiceDetected,
    discoveredLinks,
    egressCheck,
    art25Check,
    art26b28Check,
    art29DoraCheck,
  } = params;

  // Clean non-SaaS brochure / retail e-commerce / personal blog sites with zero SaaS/cloud markers return 100 / LOW / 0 findings
  if (
    !isSaasOrCloudServiceDetected &&
    !egressCheck.egressOrSwitchingFeeFound &&
    !egressCheck.exportPaywallOrTierLockFound &&
    !art25Check.shortPostTerminationRetentionFound &&
    !art25Check.excessiveNoticePeriodLockInFound
  ) {
    return {
      findings: [],
      complianceScore: 100,
      riskTier: 'LOW',
    };
  }

  const findings: ComplianceFinding[] = [];
  let deductions = 0;

  // Rule 1: DATA-ACT-ART-29-30-EGRESS-FEE-OR-EXPORT-PAYWALL (CRITICAL, -32 pts)
  if (
    egressCheck.checked &&
    (egressCheck.egressOrSwitchingFeeFound || egressCheck.exportPaywallOrTierLockFound)
  ) {
    deductions += 32;
    const triggers: string[] = [];
    if (egressCheck.egressOrSwitchingFeeFound) {
      triggers.push(`explicit switching/egress/offboarding fee ("${egressCheck.egressFeeMatches[0]}")`);
    }
    if (egressCheck.exportPaywallOrTierLockFound) {
      triggers.push(`Enterprise-only data/API export paywall ("${egressCheck.exportPaywallMatches[0]}")`);
    }
    findings.push({
      ruleId: 'DATA-ACT-ART-29-30-EGRESS-FEE-OR-EXPORT-PAYWALL',
      title: 'Explicit Data Egress / Offboarding Fee or Enterprise-Only Data Export Paywall Violating Jan 12, 2027 €0 Cliff',
      regulation:
        'EU Data Act (Regulation (EU) 2023/2854) Art. 29(1) (€0 Switching & Data Egress Charges from 12 Jan 2027), Art. 2(35)–(36), Art. 23, & Art. 30(2) (Free Open Interfaces for SaaS/PaaS)',
      severity: 'CRITICAL',
      deductionPoints: 32,
      pageUrl: egressCheck.foundOnPages[0] || discoveredLinks.pricingOrPlansUrl || homeUrl,
      evidence: `Detected ${triggers.join(' and ')} without an EU Data Act Art. 29(1) €0 switching & Art. 30(2) free open-interface guarantee.`,
      recommendation:
        'Eliminate all switching, offboarding, and data-egress fees by 12 January 2027 (Art. 29(1)), unlock structured machine-readable bulk export (JSON/CSV/REST API) free of charge across all subscription tiers including Starter/Pro plans (Art. 30(2)), and publish a clear €0 egress & switching guarantee on /pricing.',
    });
  }

  // Rule 2: DATA-ACT-ART-25-RETENTION-OR-NOTICE-LOCKIN (CRITICAL, -28 pts)
  if (
    art25Check.checked &&
    (art25Check.shortPostTerminationRetentionFound || art25Check.excessiveNoticePeriodLockInFound)
  ) {
    deductions += 28;
    const lockParts: string[] = [];
    if (art25Check.shortPostTerminationRetentionFound) {
      lockParts.push(
        `sub-30-day or immediate post-termination data deletion ("${art25Check.shortRetentionMatches[0]}") conflicting with Art. 25(2)(g) (≥30 calendar days retrieval)`,
      );
    }
    if (art25Check.excessiveNoticePeriodLockInFound) {
      lockParts.push(
        `notice period exceeding 2 months ("${art25Check.excessiveNoticeMatches[0]}") conflicting with Art. 25(2)(d) (≤2 months initiation notice)`,
      );
    }
    findings.push({
      ruleId: 'DATA-ACT-ART-25-RETENTION-OR-NOTICE-LOCKIN',
      title: 'Post-Termination <30-Day Data Deletion or >2-Month Notice Lock-In Violating Art. 25(2) Timelines',
      regulation:
        'EU Data Act (Regulation (EU) 2023/2854) Art. 25(2)(d) (≤2-Month Initiation Notice), Art. 25(2)(g)–(h) (≥30-Calendar-Day Retrieval Period Before Erasure), & Art. 40(1)–(3)',
      severity: 'CRITICAL',
      deductionPoints: 28,
      pageUrl: art25Check.foundOnPages[0] || discoveredLinks.termsOrMsaUrl || homeUrl,
      evidence: `Detected ${lockParts.join('; ')}.`,
      recommendation:
        'Amend your Terms of Service / MSA and adopt an EU Data Act Switching Addendum capping switching initiation notice at ≤2 months (Art. 25(2)(d)), providing a ≤30-calendar-day transitional period (Art. 25(2)(a)), and guaranteeing a minimum ≥30-calendar-day post-transition data retrieval window before full erasure (Art. 25(2)(g)–(h)).',
    });
  }

  // Rule 3: DATA-ACT-ART-25-MISSING-SWITCHING-ADDENDUM (HIGH, -22 pts)
  if (isSaasOrCloudServiceDetected && art25Check.checked && !art25Check.switchingAddendumFound) {
    deductions += 22;
    findings.push({
      ruleId: 'DATA-ACT-ART-25-MISSING-SWITCHING-ADDENDUM',
      title: 'Missing EU Data Act Chapter VI Written Cloud/SaaS Switching Addendum (Art. 25 & Rec. (EU) 2026/2394)',
      regulation:
        'EU Data Act (Regulation (EU) 2023/2854) Art. 25(1)–(5), Art. 41, & European Commission Recommendation (EU) 2026/2394 (Cloud Switching SCCs of 29 Oct 2026)',
      severity: 'HIGH',
      deductionPoints: 22,
      pageUrl: discoveredLinks.termsOrMsaUrl || homeUrl,
      evidence:
        'Active SaaS/cloud platform has no publicly linked EU Data Act Switching Addendum setting out mandatory Art. 25(2) clauses (≤2-month notice, ≤30-day transition with continuity/security, ≥30-day retrieval, guaranteed erasure, and €0 switching charges).',
      recommendation:
        'Publish a dedicated EU Data Act Cloud Switching Addendum at `/data-act` aligned with Regulation (EU) 2023/2854 Arts. 23–32 and Commission Recommendation (EU) 2026/2394, incorporated automatically into your Terms/MSA.',
    });
  }

  // Rule 4: DATA-ACT-ART-26B-MISSING-ONLINE-PORTABILITY-REGISTER (HIGH, -16 pts)
  if (
    isSaasOrCloudServiceDetected &&
    art26b28Check.checked &&
    !art26b28Check.art26bOnlinePortabilityRegisterFound
  ) {
    deductions += 16;
    findings.push({
      ruleId: 'DATA-ACT-ART-26B-MISSING-ONLINE-PORTABILITY-REGISTER',
      title: 'Missing Art. 26(b) Provider-Hosted Online Register of Exportable Data Structures & Formats',
      regulation:
        'EU Data Act (Regulation (EU) 2023/2854) Art. 26(b) & Art. 25(2)(e)–(f) (Mandatory Online Register of Data Structures, Formats & Open Interoperability Specifications)',
      severity: 'HIGH',
      deductionPoints: 16,
      pageUrl: discoveredLinks.portabilityRegisterUrl || discoveredLinks.docsOrApiUrl || homeUrl,
      evidence:
        'Inspected pages lack an up-to-date provider-hosted Art. 26(b) online register detailing exportable data categories, machine-readable schemas/formats (JSON, CSV, Parquet, OpenAPI), interoperability standards, and exempted trade-secret categories.',
      recommendation:
        'Host a public Online Portability Register (`/portability-register`) referencing all exportable customer data structures, schemas, machine-readable export formats (`JSON`, `CSV`, `Parquet`, `OpenAPI 3.1`), and narrow internal trade-secret exemptions under Art. 25(2)(f).',
    });
  }

  // Rule 5: DATA-ACT-ART-28-32-MISSING-JURISDICTION-GOV-ACCESS-NOTICE (MEDIUM, -14 pts)
  if (
    isSaasOrCloudServiceDetected &&
    art26b28Check.checked &&
    (!art26b28Check.art28IctJurisdictionDisclosed ||
      !art26b28Check.art28NonPersonalGovAccessSafeguardsDisclosed)
  ) {
    deductions += 14;
    const missingParts: string[] = [];
    if (!art26b28Check.art28IctJurisdictionDisclosed) {
      missingParts.push('ICT infrastructure processing jurisdiction (Art. 28(1)(a))');
    }
    if (!art26b28Check.art28NonPersonalGovAccessSafeguardsDisclosed) {
      missingParts.push(
        'technical, organisational, and contractual measures preventing unlawful international governmental access to non-personal data held in the EU (Art. 28(1)(b) & Art. 32)',
      );
    }
    const gdprNote = art26b28Check.gdprPersonalDataOnlyNoticeWithoutArt28
      ? ' (Note: GDPR personal-data privacy notices alone do not satisfy Art. 28(1)(b) for non-personal B2B SaaS data.)'
      : '';

    findings.push({
      ruleId: 'DATA-ACT-ART-28-32-MISSING-JURISDICTION-GOV-ACCESS-NOTICE',
      title: 'Missing Art. 28(1) & Art. 32 Website Disclosure of ICT Jurisdiction & Non-Personal Data Gov-Access Safeguards',
      regulation:
        'EU Data Act (Regulation (EU) 2023/2854) Art. 28(1)(a)–(b) & Art. 32 (International Governmental Access & Transfer Safeguards for Non-Personal EU Data)',
      severity: 'MEDIUM',
      deductionPoints: 14,
      pageUrl: discoveredLinks.trustOrJurisdictionUrl || homeUrl,
      evidence: `Website lacks mandatory public disclosure of ${missingParts.join(' and ')}${gdprNote}`,
      recommendation:
        'Publish an Art. 28(1) & Art. 32 transparency section on your Trust Center or `/portability-register` listing the exact legal jurisdiction(s) of your ICT cloud regions and the encryption, access-control, and legal-challenge safeguards protecting non-personal Union data from unlawful third-country governmental orders.',
    });
  }

  // Rule 6: DATA-ACT-ART-29-4-DORA-EXIT-TRANSPARENCY-GAP (MEDIUM, -10 pts — F-08 Art. 29(5) & F-09 DORA gate)
  if (
    isSaasOrCloudServiceDetected &&
    art29DoraCheck.checked &&
    art29DoraCheck.art29EarlyTerminationAndDoraExitGapFound
  ) {
    deductions += 10;
    findings.push({
      ruleId: 'DATA-ACT-ART-29-4-DORA-EXIT-TRANSPARENCY-GAP',
      title: 'Fixed-Term / Financial-Sector SaaS Lacks Clear Art. 29(4)–(5) Early-Termination Methodology or EU DORA Exit Support',
      regulation:
        'EU Data Act Art. 29(4)–(5) & Art. 25(2)(i) (Pre-Contractual Disclosure of Standard Service Fees & Proportionate Fixed-Term Early Termination Penalties) & EU DORA (Regulation (EU) 2022/2554) Art. 28(8) & Art. 30(2)(h)',
      severity: 'MEDIUM',
      deductionPoints: 10,
      pageUrl:
        art29DoraCheck.foundOnPages[0] ||
        discoveredLinks.pricingOrPlansUrl ||
        discoveredLinks.trustOrJurisdictionUrl ||
        homeUrl,
      evidence:
        art29DoraCheck.evidence[0] ||
        'Fixed-term or financial-sector SaaS offering lacks transparent Art. 29(4)–(5) early-termination calculation terms and/or EU DORA Art. 30(2)(h) documented exit-strategy disclosures.',
      recommendation:
        'Disclose any proportionate fixed-term early-termination fee formula upfront under Art. 29(4)–(5) & Art. 25(2)(i) (confirming €0 switching/egress fee), and document EU DORA Art. 30(2)(h) ICT exit-plan and transition-continuity support where serving regulated financial entities.',
    });
  }

  const severityOrder: Record<ComplianceFinding['severity'], number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
  };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  const complianceScore = Math.max(0, Math.min(100, 100 - deductions));

  let riskTier: RiskTier;
  if (findings.some((f) => f.severity === 'CRITICAL') || complianceScore <= 40) {
    riskTier = 'CRITICAL';
  } else if (findings.some((f) => f.severity === 'HIGH') || complianceScore <= 70) {
    riskTier = 'HIGH';
  } else if (findings.length > 0 || complianceScore <= 88) {
    riskTier = 'MEDIUM';
  } else {
    riskTier = 'LOW';
  }

  return { findings, complianceScore, riskTier };
}

function prettyVendor(slug: string): string {
  const names: Record<string, string> = {
    'stripe-billing': 'Stripe Billing',
    paddle: 'Paddle',
    chargebee: 'Chargebee',
    recurly: 'Recurly',
    'lemon-squeezy': 'Lemon Squeezy',
    zuora: 'Zuora',
    fastspring: 'FastSpring',
    braintree: 'Braintree',
    auth0: 'Auth0',
    clerk: 'Clerk',
    workos: 'WorkOS',
    okta: 'Okta',
    stytch: 'Stytch',
    'supabase-auth': 'Supabase Auth',
    'firebase-auth': 'Firebase Auth',
    cognito: 'AWS Cognito',
    vanta: 'Vanta',
    drata: 'Drata',
    safebase: 'SafeBase',
    conveyor: 'Conveyor',
    whistic: 'Whistic',
    onetrust: 'OneTrust',
    secureframe: 'Secureframe',
    sprinto: 'Sprinto',
    statuspage: 'Atlassian Statuspage',
    betterstack: 'Better Stack',
    instatus: 'Instatus',
    'swagger-openapi': 'OpenAPI / Swagger',
    mintlify: 'Mintlify',
    'readme-io': 'ReadMe',
    gitbook: 'GitBook',
    docusaurus: 'Docusaurus',
    intercom: 'Intercom',
    zendesk: 'Zendesk',
    crisp: 'Crisp',
    hubspot: 'HubSpot',
  };
  return names[slug] || slug;
}

/**
 * Generates a neutral, factual 1-2 sentence B2B outreach observation with strict
 * singular/plural verb agreement for EU Data Act Legal, GRC/Trust-Center & Cloud Migration Agencies.
 */
export function generateColdOutreachHook(params: {
  domain: string;
  isSaasOrCloudServiceDetected: boolean;
  billingSdkVendors: BillingSdkVendor[];
  authIdentityVendors: AuthIdentityVendor[];
  trustCenterGrcVendors: TrustCenterGrcVendor[];
  egressCheck: EgressAndExportInterfaceCheckResult;
  art25Check: Art25SwitchingContractCheckResult;
  art26b28Check: Art26bAndArt28TransparencyCheckResult;
  art29DoraCheck: Art29TerminationAndDoraExitCheckResult;
  findings: ComplianceFinding[];
}): string {
  const {
    domain,
    isSaasOrCloudServiceDetected,
    billingSdkVendors,
    authIdentityVendors,
    trustCenterGrcVendors,
    egressCheck,
    art25Check,
    art26b28Check,
    art29DoraCheck,
    findings,
  } = params;

  const stackVendors = [
    ...billingSdkVendors.slice(0, 1),
    ...authIdentityVendors.slice(0, 1),
    ...trustCenterGrcVendors.slice(0, 1),
  ].map(prettyVendor);

  if (findings.length === 0) {
    if (isSaasOrCloudServiceDetected) {
      const stackNote = stackVendors.length > 0 ? ` (${stackVendors.join(' + ')})` : '';
      return `An automated EU Data Act (Reg. 2023/2854) & DORA readiness scan of ${domain}${stackNote} confirmed a published Art. 25 Cloud Switching Addendum, Art. 26(b) Online Portability Register, Art. 28/32 ICT jurisdiction & non-personal gov-access disclosures, and €0 switching/egress terms.`;
    }
    return `An automated technical scan of ${domain} found zero SaaS/cloud switching paywalls, data-egress surcharges, or EU Data Act Chapter VI compliance triggers on inspected public pages.`;
  }

  const observations: string[] = [];

  if (egressCheck.egressOrSwitchingFeeFound || egressCheck.exportPaywallOrTierLockFound) {
    if (egressCheck.egressOrSwitchingFeeFound && egressCheck.exportPaywallOrTierLockFound) {
      observations.push(
        `public pricing/terms impose an offboarding/egress fee alongside an Enterprise-only data export paywall ahead of the 12 Jan 2027 EU Data Act Art. 29(1) €0 switching cliff & Art. 30(2) free open-interface mandate`,
      );
    } else if (egressCheck.exportPaywallOrTierLockFound) {
      observations.push(
        `bulk CSV/JSON/API data export is gated behind higher/Enterprise plans in conflict with EU Data Act Art. 29(1) & Art. 30(2)`,
      );
    } else {
      observations.push(
        `on-page terms reference a switching, data-egress, or offboarding fee prohibited from 12 Jan 2027 under EU Data Act Art. 29(1)`,
      );
    }
  }

  if (art25Check.shortPostTerminationRetentionFound || art25Check.excessiveNoticePeriodLockInFound) {
    if (art25Check.shortPostTerminationRetentionFound && art25Check.excessiveNoticePeriodLockInFound) {
      observations.push(
        `contractual terms combine a >2-month notice lock-in with sub-30-day post-termination data deletion (conflicting with Art. 25(2)(d) & (g))`,
      );
    } else if (art25Check.shortPostTerminationRetentionFound) {
      observations.push(
        `contractual terms state customer data is deleted in under 30 calendar days upon termination (conflicting with the mandatory Art. 25(2)(g) ≥30-day retrieval window)`,
      );
    } else {
      observations.push(
        `contractual terms require >2 months prior written notice to terminate/switch without an EU Data Act Art. 25(2)(d) override`,
      );
    }
  }

  if (!art25Check.switchingAddendumFound) {
    if (stackVendors.length > 0) {
      const label = stackVendors.slice(0, 2).join(' + ');
      const verb = stackVendors.slice(0, 2).length > 1 ? 'power' : 'powers';
      observations.push(
        `${label} ${verb} your SaaS stack without a linked EU Data Act Art. 25 Switching Addendum (Commission Rec. (EU) 2026/2394)`,
      );
    } else {
      observations.push(
        `public legal pages lack an EU Data Act Chapter VI Cloud Switching Addendum (Art. 25)`,
      );
    }
  }

  if (!art26b28Check.art26bOnlinePortabilityRegisterFound) {
    observations.push(
      `inspected pages lack the mandatory Art. 26(b) Online Portability Register of exportable data structures and machine-readable formats`,
    );
  }

  if (
    !art26b28Check.art28IctJurisdictionDisclosed ||
    !art26b28Check.art28NonPersonalGovAccessSafeguardsDisclosed
  ) {
    observations.push(
      `website disclosures omit Art. 28(1)/Art. 32 ICT hosting jurisdiction and non-personal data governmental-access safeguards`,
    );
  }

  if (art29DoraCheck.art29EarlyTerminationAndDoraExitGapFound && observations.length < 2) {
    observations.push(
      `fixed-term/financial pages omit clear Art. 29(4)–(5) early-termination methodology and EU DORA Art. 30(2)(h) exit-strategy terms`,
    );
  }

  const topTwo = observations.slice(0, 2).join(', and ');
  const extraCount = Math.max(0, findings.length - 2);
  const suffix =
    extraCount > 0
      ? ` (plus ${extraCount} additional EU Data Act / DORA readiness gap${extraCount > 1 ? 's' : ''})`
      : '';

  return `While running an EU Data Act (12 Jan 2027 €0 egress cliff) & Cloud Switching check on ${domain}, we noticed ${topTwo}${suffix} — happy to share the audit report and ready-to-paste Art. 25 Switching Addendum HTML, Art. 26(b)/28 Portability Register, and /pricing €0 Egress widget snippets if helpful for your legal & engineering teams.`;
}

/**
 * Generates 3 production-ready, HTML-escaped (`escapeHtml(domain)`), domain-customized HTML/JS artifacts:
 * 1) `euDataActSwitchingAddendumHtml` — Complete EU Data Act Chapter VI Addendum (Reg. 2023/2854 Arts. 23–32 & Rec. (EU) 2026/2394 + DORA Art. 30(2)(h))
 * 2) `onlinePortabilityRegisterAndArt28Html` — Art. 26(b) Online Exportable Data Structures & Formats Register + Configurable Art. 28(1) / Art. 32 ICT Jurisdiction & Non-Personal Data Gov-Access Safeguards
 * 3) `pricingZeroEgressDisclosureWidgetHtmlJs` — Accessible <aside>/<details> widget + JS helper for /pricing & checkout
 */
export function generateRemediationPack(params: {
  domain: string;
  sitePlatform: SitePlatform;
  siteCategory: SiteCategory;
  billingSdkVendors: BillingSdkVendor[];
  authIdentityVendors: AuthIdentityVendor[];
  trustCenterGrcVendors: TrustCenterGrcVendor[];
}): RemediationPack {
  const {
    domain,
    sitePlatform,
    siteCategory,
    billingSdkVendors,
    authIdentityVendors,
    trustCenterGrcVendors,
  } = params;

  const safeDomain = escapeHtml(domain);
  const billingLabel = escapeHtml(
    billingSdkVendors.length > 0
      ? billingSdkVendors.map(prettyVendor).join(' / ')
      : 'our subscription billing portal',
  );
  const trustLabel = escapeHtml(
    trustCenterGrcVendors.length > 0
      ? trustCenterGrcVendors.map(prettyVendor).join(' / ')
      : 'our Security & Trust Center',
  );
  const todayIso = new Date().toISOString().slice(0, 10);

  const euDataActSwitchingAddendumHtml = `<!-- EU Data Act (Regulation (EU) 2023/2854, Chapter VI: Arts. 23–32) & Commission Recommendation (EU) 2026/2394 Cloud/SaaS Switching Addendum (${safeDomain}) -->
<section id="eu-data-act-switching-addendum" aria-labelledby="eda-addendum-heading"
  style="max-width:860px;margin:28px auto;padding:28px;border:1px solid #e2e8f0;border-radius:12px;background:#ffffff;color:#0f172a;font-family:system-ui,-apple-system,sans-serif;line-height:1.65;">
  <h1 id="eda-addendum-heading" style="margin:0 0 10px;font-size:1.45rem;">EU Data Act Cloud &amp; SaaS Switching Addendum</h1>
  <p style="margin:0 0 16px;font-size:0.92rem;color:#334155;">
    <strong>Effective &amp; Last Updated:</strong> ${todayIso} &middot; Aligned with <strong>Regulation (EU) 2023/2854 (EU Data Act, Chapter VI: Articles 23–32)</strong>, <strong>European Commission Recommendation (EU) 2026/2394</strong> of 29 October 2026 (Standard Contractual Clauses for Cloud Computing Switching), and <strong>EU DORA (Regulation (EU) 2022/2554, Articles 28(8) &amp; 30(2)(h))</strong> for customers of <strong>${safeDomain}</strong>.
  </p>

  <h2 style="margin:18px 0 8px;font-size:1.1rem;">1. Right to Switch &amp; Maximum Initiation Notice Period (Article 25(2)(d))</h2>
  <p style="margin:0 0 12px;font-size:0.92rem;">
    Notwithstanding any longer legacy notice clause in the Master Subscription Agreement or Terms of Service, the Customer may initiate switching to another data processing service provider or to an on-premises ICT infrastructure upon a maximum notice period not exceeding <strong>two (2) months</strong> (≤ 2 months) pursuant to EU Data Act Article 25(2)(d).
  </p>

  <h2 style="margin:18px 0 8px;font-size:1.1rem;">2. Mandatory 30-Calendar-Day Transitional Period &amp; Continuity (Article 25(2)(a), (4) &amp; (5))</h2>
  <p style="margin:0 0 12px;font-size:0.92rem;">
    Upon expiry of the initiation notice, ${safeDomain} shall complete the switching and porting of all exportable data and digital assets within a mandatory <strong>30-calendar-day transitional period</strong> while maintaining full business continuity, service-level security, and reasonable migration assistance. Where technically unfeasible, ${safeDomain} may notify the Customer within 14 working days with duly substantiated technical justification to extend the transitional period up to seven (7) months (Article 25(4)). The Customer may freely extend the transitional period once for a period it considers appropriate (Article 25(5)).
  </p>

  <h2 style="margin:18px 0 8px;font-size:1.1rem;">3. €0 Switching &amp; Data Egress Charges + Free Open Interfaces (Articles 29(1) &amp; 30(2))</h2>
  <p style="margin:0 0 12px;font-size:0.92rem;">
    In full compliance with <strong>EU Data Act Article 29(1)</strong> (mandatory €0 switching &amp; egress fee rule in force across the Union by 12 January 2027), ${safeDomain} shall not impose any switching charges, offboarding fees, or data egress charges on the Customer for the switching process. Open interfaces and self-serve bulk export tools (<code>JSON</code>, <code>CSV</code>, <code>Parquet</code>, and <code>OpenAPI</code> REST endpoints) are available free of charge across all plans under <strong>Article 30(2)</strong>. Continuous in-parallel multi-cloud data egress not forming part of a switching exit remains governed by Article 34(2).
  </p>

  <h2 style="margin:18px 0 8px;font-size:1.1rem;">4. Minimum 30-Calendar-Day Data Retrieval Period &amp; Guaranteed Erasure (Article 25(2)(g)–(h))</h2>
  <p style="margin:0 0 12px;font-size:0.92rem;">
    Following completion of the 30-calendar-day transitional period, ${safeDomain} guarantees a minimum <strong>30-calendar-day data retrieval period</strong> during which the Customer may retrieve all exportable data and digital assets. Customer data is never deleted immediately upon cancellation. Upon expiry of the 30-calendar-day data retrieval period (provided the switching process has completed successfully), ${safeDomain} guarantees complete and irreversible erasure of all exportable data and digital assets generated by or relating directly to the Customer (Article 25(2)(h)).
  </p>

  <h2 style="margin:18px 0 8px;font-size:1.1rem;">5. Fixed-Term Proportionate Early Termination &amp; EU DORA Exit Strategy (Articles 29(4)–(5) &amp; DORA Art. 30(2)(h))</h2>
  <p style="margin:0;font-size:0.92rem;">
    Month-to-month subscriptions via ${billingLabel} may cancel at any time without penalty (€0 early termination fee). Where the Customer has elected an optional discounted fixed-term annual or multi-year contract and terminates prior to term expiry pursuant to switching, any proportionate early termination penalty disclosed pre-contractually under <strong>Articles 29(4)–(5) &amp; 25(2)(i)</strong> is strictly capped at the pro-rata discount differential actually granted for the elapsed term, with €0 data egress or switching surcharge. For regulated financial entities subject to <strong>EU DORA (Regulation (EU) 2022/2554, Articles 28(8) &amp; 30(2)(h))</strong>, ${safeDomain} supports documented ICT exit strategies, non-disruptive exit testing, and machine-readable data return as detailed in our <a href="/portability-register" style="color:#2563eb;text-decoration:underline;">Article 26(b) Online Portability Register &amp; Article 28 Jurisdiction Notice</a>.
  </p>
</section>`;

  const onlinePortabilityRegisterAndArt28Html = `<!-- EU Data Act Article 26(b) Online Portability Register + Article 28(1) & Article 32 ICT Jurisdiction & Non-Personal Data Governmental-Access Safeguards (${safeDomain}) -->
<section id="eu-data-act-portability-register-and-art28" aria-labelledby="eda-reg-heading"
  style="max-width:860px;margin:28px auto;padding:28px;border:1px solid #e2e8f0;border-radius:12px;background:#ffffff;color:#0f172a;font-family:system-ui,-apple-system,sans-serif;line-height:1.65;">
  <h1 id="eda-reg-heading" style="margin:0 0 10px;font-size:1.45rem;">Online Portability Register (Art. 26(b)) &amp; ICT Jurisdiction Transparency (Arts. 28 &amp; 32)</h1>
  <p style="margin:0 0 16px;font-size:0.92rem;color:#334155;">
    <strong>Provider-Hosted Register for ${safeDomain}</strong> &middot; Maintained pursuant to <strong>Regulation (EU) 2023/2854 Articles 25(2)(e)–(f), 26(b), 28(1)(a)–(b), and 32</strong> (Last updated: ${todayIso}; cross-referenced in ${trustLabel}).
  </p>

  <h2 style="margin:18px 0 10px;font-size:1.12rem;">Part A — Article 26(b) Online Register of Exportable Data Structures, Formats &amp; Interoperability Standards</h2>
  <div style="overflow-x:auto;margin-bottom:14px;">
    <table style="width:100%;border-collapse:collapse;font-size:0.88rem;text-align:left;">
      <thead>
        <tr style="background:#f8fafc;border-bottom:2px solid #cbd5e1;">
          <th style="padding:10px;">Exportable Data / Digital Asset Category (Art. 25(2)(e))</th>
          <th style="padding:10px;">Data Structures, Formats &amp; Open Standards (Art. 26(b))</th>
          <th style="padding:10px;">Free Open Interface (Art. 30(2))</th>
        </tr>
      </thead>
      <tbody>
        <tr style="border-bottom:1px solid #e2e8f0;">
          <td style="padding:10px;">Customer Primary Records, Projects, Metadata &amp; Custom Fields</td>
          <td style="padding:10px;">UTF-8 <code>JSON</code> (RFC 8259), <code>NDJSON</code>, <code>CSV</code> (RFC 4180), &amp; <code>Apache Parquet</code></td>
          <td style="padding:10px;">Self-serve Workspace Export &amp; <code>OpenAPI 3.1</code> REST API (All Plans, €0 fee)</td>
        </tr>
        <tr style="border-bottom:1px solid #e2e8f0;">
          <td style="padding:10px;">User Roles, Configurations, Webhooks, Workflows &amp; Audit Logs</td>
          <td style="padding:10px;">Structured <code>JSON</code> Schema (Draft 2020-12) &amp; <code>CSV</code></td>
          <td style="padding:10px;"><code>GET /api/v1/export/configurations</code> &amp; Admin Dashboard (€0 fee)</td>
        </tr>
        <tr style="border-bottom:1px solid #e2e8f0;">
          <td style="padding:10px;">Uploaded Attachments, Object Blobs &amp; Generated Digital Assets</td>
          <td style="padding:10px;">Original binary MIME formats + signed <code>JSON</code> manifest checksums (SHA-256)</td>
          <td style="padding:10px;">Pre-signed TLS 1.3 bulk archive stream (€0 data egress charge)</td>
        </tr>
      </tbody>
    </table>
  </div>
  <p style="margin:0 0 18px;font-size:0.88rem;color:#334155;">
    <strong>Exempted Provider Trade-Secret Categories (Article 25(2)(f)):</strong> Strictly limited to proprietary multi-tenant infrastructure telemetry, internal anomaly-scoring weights, and underlying source code specific to the internal functioning of ${safeDomain} whose disclosure would breach provider trade secrets. No Customer-inputted or Customer-generated operational data is ever exempted.
  </p>

  <h2 style="margin:18px 0 8px;font-size:1.12rem;">Part B — Article 28(1)(a) ICT Infrastructure Jurisdiction Disclosure</h2>
  <p data-template-placeholder="configure-ict-jurisdiction" style="margin:0 0 10px;padding:8px 12px;border-left:4px solid #f59e0b;background:#fffbeb;color:#92400e;font-size:0.85rem;">
    <strong>[TEMPLATE — CONFIGURE ACTUAL PRODUCTION REGIONS &amp; JURISDICTIONS BEFORE PUBLISHING]:</strong> Replace the bracketed cloud region and jurisdiction placeholders below with your verified production &amp; backup infrastructure locations before publishing.
  </p>
  <p style="margin:0 0 12px;font-size:0.92rem;">
    Pursuant to Article 28(1)(a), the ICT infrastructure deployed by ${safeDomain} for primary production data processing and encrypted backups is hosted in <strong>[CONFIGURE PRIMARY &amp; BACKUP CLOUD REGIONS — e.g., AWS eu-central-1 / GCP europe-west1 / US-East]</strong> and is subject to the jurisdiction of <strong>[CONFIGURE APPLICABLE JURISDICTION(S) — e.g., European Union &amp; Federal Republic of Germany / Ireland / United States]</strong>.
  </p>

  <h2 style="margin:18px 0 8px;font-size:1.12rem;">Part C — Article 28(1)(b) &amp; Article 32 Safeguards Against Unlawful International Governmental Access to Non-Personal Data</h2>
  <ul style="margin:0;padding-left:20px;font-size:0.9rem;color:#1e293b;">
    <li><strong>Technical Measures:</strong> All Customer <strong>non-personal data</strong> held in the Union is protected in transit via TLS 1.3 and at rest via AES-256-GCM encryption with isolated tenant key hierarchies and strict key-management boundaries <em>[verify encryption &amp; KMS/HSM configuration before publishing]</em>.</li>
    <li><strong>Organisational Measures:</strong> Strict role-based access controls, mandatory judicial-order legality review under EU Data Act Article 32(2)–(3), data-minimisation principles, and prior Customer notification unless prohibited by Union or Member State criminal law.</li>
    <li><strong>Contractual Measures:</strong> Binding subprocessor commitments prohibiting unlawful direct, backdoor, or bulk international governmental access to or transfer of non-personal data held in the Union where such access would conflict with Union law or relevant Member State national law (Articles 28(1)(b) &amp; 32).</li>
  </ul>
</section>`;

  const pricingZeroEgressDisclosureWidgetHtmlJs = `<!-- EU Data Act Art. 29(1), Art. 30(2) & Art. 29(4)–(5) /pricing & Checkout Zero-Egress Transparency Widget (${safeDomain}) -->
<aside id="eu-data-act-zero-egress-widget" data-eu-data-act-zero-egress="true" aria-label="EU Data Act Zero Switching and Egress Fee Guarantee"
  style="margin:16px 0;padding:14px 18px;border:1px solid #cbd5e1;border-radius:10px;background:#f8fafc;color:#0f172a;font-family:system-ui,-apple-system,sans-serif;font-size:0.88rem;line-height:1.55;">
  <div style="display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:10px;">
    <div>
      <strong>&#127466;&#127482; EU Data Act Guarantee: €0 Switching &amp; €0 Data Egress Fees Across All Plans</strong>
      <span style="color:#475569;"> &middot; Free self-serve <code>JSON</code> / <code>CSV</code> / <code>OpenAPI</code> bulk export on every tier (Art. 29(1) &amp; Art. 30(2)).</span>
    </div>
    <span style="padding:3px 10px;border-radius:999px;background:#dcfce7;color:#166534;font-weight:600;font-size:0.8rem;">&#10003; ≥30-Day Data Retrieval</span>
  </div>
  <details style="margin-top:8px;">
    <summary style="cursor:pointer;color:#2563eb;font-weight:600;">View Switching Timelines, Export Formats &amp; Fixed-Term Early-Termination Terms</summary>
    <p style="margin:8px 0 0;color:#334155;">
      Under Regulation (EU) 2023/2854, customers on ${safeDomain} enjoy ≤2-month initiation notice (Art. 25(2)(d)), a ≤30-calendar-day transitional period with service continuity (Art. 25(2)(a)), at least 30 calendar days post-transition data retrieval before erasure (Art. 25(2)(g)–(h)), zero switching or egress charges (Art. 29(1)), and transparent proportionate early-termination calculation on optional discounted annual plans (Art. 29(4)–(5)). Review our <a href="/data-act" style="color:#2563eb;text-decoration:underline;">EU Data Act Switching Addendum</a> and <a href="/portability-register" style="color:#2563eb;text-decoration:underline;">Art. 26(b) Online Portability Register &amp; Art. 28 Jurisdiction Notice</a>.
    </p>
  </details>
</aside>
<script>
(function () {
  // Ensure pricing comparison tables mark bulk data export as unlocked on all tiers (EU Data Act Art. 30(2))
  document.querySelectorAll('[data-feature="data-export"],[data-export-tier-lock]').forEach(function (el) {
    el.removeAttribute('data-export-tier-lock');
    el.setAttribute('data-eu-data-act-all-plans', 'true');
  });
})();
</script>`;

  return {
    domain,
    sitePlatform,
    siteCategory,
    detectedBillingVendors: billingSdkVendors,
    detectedAuthVendors: authIdentityVendors,
    detectedTrustCenterVendors: trustCenterGrcVendors,
    euDataActSwitchingAddendumHtml,
    onlinePortabilityRegisterAndArt28Html,
    pricingZeroEgressDisclosureWidgetHtmlJs,
    regulatoryCoverageSummary: EU_DATA_ACT_STATUTORY_SUMMARY,
    implementationNotes: [
      `Publish \`euDataActSwitchingAddendumHtml\` at \`https://${domain}/data-act\` and link it in your global footer and MSA/Terms of Service (mandatory under EU Data Act Art. 25 & aligned with Commission Recommendation (EU) 2026/2394 of 29 Oct 2026).`,
      `IMPORTANT — Before publishing \`onlinePortabilityRegisterAndArt28Html\` at \`https://${domain}/portability-register\` (and cross-linking from ${trustLabel}), replace the \`[TEMPLATE — CONFIGURE ACTUAL PRODUCTION REGIONS & JURISDICTIONS BEFORE PUBLISHING]\` placeholders in Part B & Part C with your verified production cloud regions, ICT hosting jurisdictions (Art. 28(1)(a)), and actual encryption/KMS controls (Art. 28(1)(b) & Art. 32).`,
      `Embed \`pricingZeroEgressDisclosureWidgetHtmlJs\` on \`https://${domain}/pricing\` and remove any Enterprise-only paywalls on CSV/JSON/API bulk customer data export before the 12 January 2027 Art. 29(1) €0 switching/egress cliff & Art. 30(2) open-interface rule.`,
      'Verify in your backend offboarding cron jobs that cancelled/terminated workspaces retain exportable data for at least 30 calendar days after the transitional period before executing guaranteed Art. 25(2)(h) erasure.',
    ],
  };
}

export function buildRecommendedNextAudits(domain: string): RecommendedNextAudit[] {
  return [
    {
      actorSlug: 'healthy_addax/us-click-to-cancel-auditor',
      actorUrl: 'https://apify.com/healthy_addax/us-click-to-cancel-auditor',
      mcpEndpointUrl: 'https://mcp.apify.com/?tools=healthy_addax/us-click-to-cancel-auditor',
      reason: `Pair your EU Data Act SaaS Switching check on ${domain} with a US Click-to-Cancel & B2B/B2C Auto-Renewal audit (Colorado SB 25-145 B2B SaaS ARL, CA AB 2863, NY/NYC Oct 2026 ARL & ROSCA).`,
    },
    {
      actorSlug: 'healthy_addax/cipa-vppa-wiretap-pixel-auditor',
      actorUrl: 'https://apify.com/healthy_addax/cipa-vppa-wiretap-pixel-auditor',
      mcpEndpointUrl: 'https://mcp.apify.com/?tools=healthy_addax/cipa-vppa-wiretap-pixel-auditor',
      reason: `Audit ${domain} via fast HTTP for US CIPA §§ 631/632 ungated Intercom/Zendesk/Crisp live-chat & session-replay wiretap exposure, VPPA video pixels, and Global Privacy Control (/.well-known/gpc.json).`,
    },
    {
      actorSlug: 'healthy_addax/wcag-eaa-ada-auditor',
      actorUrl: 'https://apify.com/healthy_addax/wcag-eaa-ada-auditor',
      mcpEndpointUrl: 'https://mcp.apify.com/?tools=healthy_addax/wcag-eaa-ada-auditor',
      reason: `Run a headless Chromium WCAG 2.2 Level AA & European Accessibility Act (EAA) visual red-box PNG audit across ${domain}'s SaaS marketing & login flows.`,
    },
    {
      actorSlug: 'healthy_addax/eu-withdrawal-omnibus-auditor',
      actorUrl: 'https://apify.com/healthy_addax/eu-withdrawal-omnibus-auditor',
      mcpEndpointUrl: 'https://mcp.apify.com/?tools=healthy_addax/eu-withdrawal-omnibus-auditor',
      reason: `If ${domain} offers self-serve B2C/prosumer plans in the EU, audit it for the mandatory EU 2-Step Electronic Withdrawal Button (Directive 2023/2673 Art. 11a), abolished EU ODR links, and Omnibus pricing.`,
    },
    {
      actorSlug: 'healthy_addax/fake-reviews-dmcc-drip-pricing-auditor',
      actorUrl: 'https://apify.com/healthy_addax/fake-reviews-dmcc-drip-pricing-auditor',
      mcpEndpointUrl: 'https://mcp.apify.com/?tools=healthy_addax/fake-reviews-dmcc-drip-pricing-auditor',
      reason: `Audit ${domain}'s Trustpilot/G2 testimonial badges and checkout pricing for US FTC 16 CFR Part 465 review rules, UK DMCC CMA review-policy & drip-pricing bans, and EU Omnibus Art. 7(6) disclosures.`,
    },
  ];
}
