import { ApifyRuntimeAdapter } from './apifyRuntime.js';
import { BillingManager, type BillingSummary } from './billing.js';
import {
  checkArt25SwitchingContract,
  checkArt26bAndArt28Transparency,
  checkArt29TerminationAndDoraExit,
  checkEgressAndExportInterfaces,
  detectSiteLanguage,
  discoverSaasComplianceLinks,
  extractRegistrableDomain,
  fingerprintSaasAndCloudApplicability,
  selectPriorityInternalSubpages,
  type InspectedPageBundle,
} from './detectors.js';
import { parseHtmlDocument } from './htmlParser.js';
import { DEFAULT_MAX_RESPONSE_BYTES, fetchSafeHttp } from './httpClient.js';
import {
  buildFindingsAndScore,
  buildRecommendedNextAudits,
  generateColdOutreachHook,
  generateRemediationPack,
} from './remediation.js';
import { RobotsAndRateGuard } from './robots.js';
import { validateUrlAgainstSsrf, type DnsLookupFn } from './ssrf.js';
import {
  LEGAL_DISCLAIMER,
  PPE_EVENTS,
  type AuditStatus,
  type EuDataActAuditReportItem,
  type NormalizedAuditInput,
  type RawActorInput,
  type UrlRequestObject,
} from './types.js';

function clampInt(val: unknown, fallback: number, min: number, max: number): number {
  const num = typeof val === 'number' ? val : Number(val);
  if (Number.isNaN(num) || !Number.isFinite(num)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(num)));
}

/**
 * Normalizes both full URLs (`https://acmecloud.io`) and bare domains
 * (`acmecloud.io` -> `https://acmecloud.io`), while preserving non-HTTP schemes
 * (`file://`, `ftp://`) so SSRF validation explicitly rejects them.
 * Returns `null` if empty or exceeding 2048 chars, with linear O(N) domain label matching.
 */
export function coerceUrlCandidate(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 2048) return null;
  if (trimmed.startsWith('//')) {
    return `https:${trimmed}`;
  }
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)) {
    return trimmed;
  }
  if (
    /^(?:\[[0-9a-fA-F:]+\]|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}|localhost)(?::\d{1,5})?(?:[/?#].*)?$/i.test(
      trimmed,
    )
  ) {
    return `https://${trimmed}`;
  }
  return trimmed;
}

function extractRawUrlStrings(
  rawInput: RawActorInput | null | undefined,
  extraDatasetUrls: string[] = [],
): string[] {
  const collected: string[] = [];

  const appendSingle = (candidate: string) => {
    const coerced = coerceUrlCandidate(candidate);
    if (coerced) collected.push(coerced);
  };

  const appendList = (list?: Array<string | UrlRequestObject>) => {
    if (!Array.isArray(list)) return;
    for (const item of list) {
      if (typeof item === 'string') {
        appendSingle(item);
      } else if (item && typeof item === 'object' && typeof item.url === 'string') {
        appendSingle(item.url);
      }
    }
  };

  if (rawInput) {
    appendList(rawInput.urls);
    appendList(rawInput.startUrls);
    if (typeof rawInput.url === 'string') {
      appendSingle(rawInput.url);
    }
  }

  for (const dsUrl of extraDatasetUrls) {
    appendSingle(dsUrl);
  }

  return Array.from(new Set(collected));
}

export function normalizeAuditInput(
  rawInput: RawActorInput | null | undefined,
  extraDatasetUrls: string[] = [],
  maxUrlsHardCap = 5000,
): NormalizedAuditInput {
  const input = rawInput ?? {};
  const maxUrls = clampInt(input.maxUrls, 100, 1, maxUrlsHardCap);
  const dedupedUrls = extractRawUrlStrings(input, extraDatasetUrls).slice(0, maxUrls);

  const rawBudget = input.maxBudgetUsd ?? input.maxTotalChargeUsd;
  const parsedBudget =
    typeof rawBudget === 'number' && Number.isFinite(rawBudget) && rawBudget >= 0
      ? rawBudget
      : undefined;

  return {
    urls: dedupedUrls,
    datasetId:
      typeof input.datasetId === 'string' && input.datasetId.trim()
        ? input.datasetId.trim()
        : undefined,
    datasetUrlField:
      typeof input.datasetUrlField === 'string' && input.datasetUrlField.trim()
        ? input.datasetUrlField.trim()
        : undefined,
    maxLegalPagesPerDomain: clampInt(input.maxLegalPagesPerDomain, 4, 0, 6),
    includeRemediationPack: input.includeRemediationPack ?? true,
    checkEgressFeesAndExportPaywalls: input.checkEgressFeesAndExportPaywalls ?? true,
    checkArt25SwitchingTermsAndLockIn: input.checkArt25SwitchingTermsAndLockIn ?? true,
    checkArt26bRegisterAndArt28Notice: input.checkArt26bRegisterAndArt28Notice ?? true,
    checkArt29TerminationAndDoraExit: input.checkArt29TerminationAndDoraExit ?? true,
    respectRobotsTxt: input.respectRobotsTxt ?? true,
    maxUrls,
    maxConcurrency: clampInt(input.maxConcurrency, 5, 1, 20),
    domainDelayMs: clampInt(input.domainDelayMs, 300, 0, 30_000),
    requestTimeoutMs: clampInt(input.requestTimeoutMs, 12_000, 2_000, 60_000),
    maxBudgetUsd: parsedBudget,
  };
}

function safeExtractHostname(rawUrl: string): string {
  try {
    return new URL(rawUrl).hostname.toLowerCase();
  } catch {
    return 'invalid-host';
  }
}

function isBinaryContentType(contentType: string): boolean {
  const lowerCt = (contentType || '').toLowerCase();
  return (
    /^(?:image|video|audio|font)\//.test(lowerCt) ||
    /\bapplication\/(?:pdf|zip|x-gzip|gzip|octet-stream|msword|vnd\.)\b/.test(lowerCt)
  );
}

function buildBlockedOrErrorItem(params: {
  rawUrl: string;
  normalizedInputUrl: string;
  status: Exclude<AuditStatus, 'audited'>;
  httpStatus?: number | null;
  reason: string;
  loadTimeMs: number;
}): EuDataActAuditReportItem {
  const domain = safeExtractHostname(params.normalizedInputUrl || params.rawUrl);
  return {
    url: params.rawUrl,
    normalizedInputUrl: params.normalizedInputUrl,
    finalUrl: null,
    domain,
    auditedAt: new Date().toISOString(),
    status: params.status,
    httpStatus: params.httpStatus ?? null,
    pageTitle: null,
    detectedLanguage: null,
    sitePlatform: 'custom',
    siteCategory: 'brochure_or_content',
    loadTimeMs: params.loadTimeMs,
    pagesFetchedCount: 0,
    pagesFetched: [],
    errorMessage: params.reason,

    isSaasOrCloudServiceDetected: false,
    complianceScore: 0,
    riskTier: 'LOW',

    billingSdkVendors: [],
    authIdentityVendors: [],
    trustCenterGrcVendors: [],
    docsStatusSupportVendors: [],
    saasApplicabilitySignals: [],

    egressOrSwitchingFeeFound: false,
    exportPaywallOrTierLockFound: false,
    egressAndExportInterfaceCheck: {
      checked: false,
      egressOrSwitchingFeeFound: false,
      egressFeeMatches: [],
      exportPaywallOrTierLockFound: false,
      exportPaywallMatches: [],
      zeroEgressGuaranteeFound: false,
      freeOpenExportAllPlansFound: false,
      art34ParallelMultiCloudCarveOutFound: false,
      evidence: [],
      foundOnPages: [],
    },

    shortPostTerminationRetentionFound: false,
    excessiveNoticePeriodLockInFound: false,
    switchingAddendumFound: false,
    art25SwitchingContractCheck: {
      checked: false,
      switchingAddendumFound: false,
      commissionRec20262394Referenced: false,
      shortPostTerminationRetentionFound: false,
      shortRetentionMatches: [],
      excessiveNoticePeriodLockInFound: false,
      excessiveNoticeMatches: [],
      art25NoticeOverrideFound: false,
      maxTwoMonthNoticeFound: false,
      thirtyDayTransitionFound: false,
      thirtyDayRetrievalAndErasureFound: false,
      evidence: [],
      foundOnPages: [],
    },

    art26bOnlinePortabilityRegisterFound: false,
    art28IctJurisdictionDisclosed: false,
    art28NonPersonalGovAccessSafeguardsDisclosed: false,
    art26bAndArt28TransparencyCheck: {
      checked: false,
      art26bOnlinePortabilityRegisterFound: false,
      exportFormatsDisclosed: [],
      exemptedTradeSecretCategoriesSpecified: false,
      art28IctJurisdictionDisclosed: false,
      jurisdictionSignals: [],
      art28NonPersonalGovAccessSafeguardsDisclosed: false,
      govAccessSafeguardSignals: [],
      gdprPersonalDataOnlyNoticeWithoutArt28: false,
      evidence: [],
      foundOnPages: [],
    },

    nonCancellableFixedTermFound: false,
    art29EarlyTerminationAndDoraExitGapFound: false,
    art29TerminationAndDoraExitCheck: {
      checked: false,
      nonCancellableFixedTermFound: false,
      fixedTermMatches: [],
      enterpriseOrRegulatedTargetSignalsFound: false,
      enterpriseTargetSignals: [],
      art29EarlyTerminationMethodologyFound: false,
      doraOrDocumentedExitStrategyFound: false,
      art29EarlyTerminationAndDoraExitGapFound: false,
      evidence: [],
      foundOnPages: [],
    },

    dataActAddendumUrl: null,
    portabilityRegisterUrl: null,
    trustOrJurisdictionUrl: null,
    pricingOrPlansUrl: null,
    termsOrMsaUrl: null,
    discoveredLinks: {
      dataActAddendumUrl: null,
      portabilityRegisterUrl: null,
      trustOrJurisdictionUrl: null,
      pricingOrPlansUrl: null,
      termsOrMsaUrl: null,
      docsOrApiUrl: null,
    },

    findingsCount: 0,
    findings: [],
    coldOutreachHook: '',
    remediationPackGenerated: false,
    remediationPack: null,
    recommendedNextAudits: buildRecommendedNextAudits(domain),
    disclaimer: LEGAL_DISCLAIMER,
  };
}

export interface AuditExecutionDependencies {
  runtime?: ApifyRuntimeAdapter;
  robotsGuard?: RobotsAndRateGuard;
  billing?: BillingManager;
  allowLocalhost?: boolean;
  dnsLookup?: DnsLookupFn;
  pushToDataset?: boolean;
  chargeActorStart?: boolean;
}

export interface BatchAuditResult {
  items: EuDataActAuditReportItem[];
  billing: BillingSummary;
  stoppedDueToBudgetCap: boolean;
  engineName: string;
}

export async function auditSingleSite(params: {
  rawUrl: string;
  config: NormalizedAuditInput;
  billing: BillingManager;
  robotsGuard: RobotsAndRateGuard;
  allowLocalhost?: boolean;
  dnsLookup?: DnsLookupFn;
}): Promise<{ item: EuDataActAuditReportItem | null; budgetStopped: boolean }> {
  const { rawUrl, config, billing, robotsGuard, allowLocalhost, dnsLookup } = params;
  const startedMs = Date.now();
  const coercedUrl = coerceUrlCandidate(rawUrl);
  const normalizedInputUrl = coercedUrl ?? rawUrl.trim().slice(0, 256);

  if (!coercedUrl) {
    return {
      item: buildBlockedOrErrorItem({
        rawUrl,
        normalizedInputUrl,
        status: 'blocked_ssrf',
        reason: 'URL is empty or exceeds the 2048-character maximum length.',
        loadTimeMs: Date.now() - startedMs,
      }),
      budgetStopped: false,
    };
  }

  // 1. Strict SSRF Pre-Flight Validation
  const ssrf = await validateUrlAgainstSsrf(coercedUrl, { allowLocalhost, dnsLookup });
  if (!ssrf.allowed || !ssrf.normalizedUrl || !ssrf.hostname) {
    return {
      item: buildBlockedOrErrorItem({
        rawUrl,
        normalizedInputUrl,
        status: 'blocked_ssrf',
        reason: ssrf.reason || 'Blocked by SSRF security policy.',
        loadTimeMs: Date.now() - startedMs,
      }),
      budgetStopped: false,
    };
  }

  const targetUrl = ssrf.normalizedUrl;
  const hostname = ssrf.hostname;

  // 2. Budget Ceiling Pre-Check before making network calls
  if (!billing.canAfford(PPE_EVENTS.URL_AUDITED, 1)) {
    return { item: null, budgetStopped: true };
  }

  // 3. Polite robots.txt check for homepage
  let effectiveDelayMs = config.domainDelayMs;
  if (config.respectRobotsTxt) {
    const robots = await robotsGuard.checkUrlAllowed(targetUrl, { allowLocalhost, dnsLookup });
    if (!robots.allowed) {
      return {
        item: buildBlockedOrErrorItem({
          rawUrl,
          normalizedInputUrl,
          status: 'blocked_robots',
          reason: `Disallowed by domain robots.txt (${robots.matchedRule || 'Disallow rule'}).`,
          loadTimeMs: Date.now() - startedMs,
        }),
        budgetStopped: false,
      };
    }
    if (robots.crawlDelayMs > effectiveDelayMs) {
      effectiveDelayMs = robots.crawlDelayMs;
    }
  }

  // 4. Polite per-domain delay
  await robotsGuard.waitForDomainSlot(hostname, effectiveDelayMs);

  // Re-check budget after waiting in queue
  if (!billing.canAfford(PPE_EVENTS.URL_AUDITED, 1)) {
    return { item: null, budgetStopped: true };
  }

  // 5. Fetch homepage via anti-DNS-rebinding pinned HTTP client
  const homeRes = await fetchSafeHttp(targetUrl, {
    maxBytes: DEFAULT_MAX_RESPONSE_BYTES,
    timeoutMs: config.requestTimeoutMs,
    maxRedirects: 5,
    allowLocalhost,
    dnsLookup,
    checkRedirectAllowed: config.respectRobotsTxt
      ? async (redirectUrl) => {
          const r = await robotsGuard.checkUrlAllowed(redirectUrl, { allowLocalhost, dnsLookup });
          return {
            allowed: r.allowed,
            reason: r.allowed
              ? undefined
              : `Redirect disallowed by robots.txt (${r.matchedRule || 'Disallow'}).`,
          };
        }
      : undefined,
  });

  if (homeRes.blockedBySsrf) {
    return {
      item: buildBlockedOrErrorItem({
        rawUrl,
        normalizedInputUrl,
        status: 'blocked_ssrf',
        reason: homeRes.errorMessage || 'Blocked by SSRF redirect policy.',
        loadTimeMs: Date.now() - startedMs,
      }),
      budgetStopped: false,
    };
  }

  if (homeRes.blockedByRobots) {
    return {
      item: buildBlockedOrErrorItem({
        rawUrl,
        normalizedInputUrl,
        status: 'blocked_robots',
        reason: homeRes.errorMessage || 'Blocked by domain robots.txt during redirect.',
        loadTimeMs: Date.now() - startedMs,
      }),
      budgetStopped: false,
    };
  }

  if (!homeRes.ok || homeRes.statusCode === null) {
    return {
      item: buildBlockedOrErrorItem({
        rawUrl,
        normalizedInputUrl,
        status: 'error',
        httpStatus: homeRes.statusCode,
        reason:
          homeRes.errorMessage ||
          'Target domain returned an unreachable or non-2xx HTTP status.',
        loadTimeMs: Date.now() - startedMs,
      }),
      budgetStopped: false,
    };
  }

  if (isBinaryContentType(homeRes.contentType)) {
    return {
      item: buildBlockedOrErrorItem({
        rawUrl,
        normalizedInputUrl,
        status: 'error',
        httpStatus: homeRes.statusCode,
        reason: `Skipped non-HTML binary resource (Content-Type: ${homeRes.contentType}); $0 billed.`,
        loadTimeMs: Date.now() - startedMs,
      }),
      budgetStopped: false,
    };
  }

  const homeDoc = parseHtmlDocument(homeRes.bodyText, homeRes.finalUrl);
  const inspectedPages: InspectedPageBundle[] = [
    {
      requestedUrl: targetUrl,
      finalUrl: homeRes.finalUrl,
      redirectChain: homeRes.redirectChain,
      doc: homeDoc,
    },
  ];
  const pagesFetched: string[] = [homeRes.finalUrl];

  // 6. Discover and fetch up to `maxLegalPagesPerDomain` internal same-origin pages
  const candidateSubpages = selectPriorityInternalSubpages(
    homeDoc,
    homeRes.finalUrl,
    config.maxLegalPagesPerDomain,
  );

  const finalHomeHost = safeExtractHostname(homeRes.finalUrl);
  const homeRegistrableRoot = extractRegistrableDomain(finalHomeHost);

  for (const subUrl of candidateSubpages) {
    if (config.respectRobotsTxt) {
      const subRobots = await robotsGuard.checkUrlAllowed(subUrl, { allowLocalhost, dnsLookup });
      if (!subRobots.allowed) {
        continue;
      }
    }

    const subHost = safeExtractHostname(subUrl);
    await robotsGuard.waitForDomainSlot(subHost, effectiveDelayMs);

    const subRes = await fetchSafeHttp(subUrl, {
      maxBytes: DEFAULT_MAX_RESPONSE_BYTES,
      timeoutMs: config.requestTimeoutMs,
      maxRedirects: 5,
      allowLocalhost,
      dnsLookup,
      checkRedirectAllowed: config.respectRobotsTxt
        ? async (redirectUrl) => {
            const r = await robotsGuard.checkUrlAllowed(redirectUrl, { allowLocalhost, dnsLookup });
            return {
              allowed: r.allowed,
              reason: r.allowed ? undefined : 'Disallowed by robots.txt',
            };
          }
        : undefined,
    });

    if (
      subRes.blockedBySsrf ||
      subRes.blockedByRobots ||
      !subRes.ok ||
      isBinaryContentType(subRes.contentType)
    ) {
      continue;
    }

    // F-09: Verify resolved subpage finalUrl stays on the same registrable root domain before merging
    const resolvedSubRoot = extractRegistrableDomain(safeExtractHostname(subRes.finalUrl));
    if (!resolvedSubRoot || resolvedSubRoot !== homeRegistrableRoot) {
      continue;
    }

    const subDoc = parseHtmlDocument(subRes.bodyText || '', subRes.finalUrl);
    inspectedPages.push({
      requestedUrl: subUrl,
      finalUrl: subRes.finalUrl,
      redirectChain: subRes.redirectChain,
      doc: subDoc,
    });
    if (!pagesFetched.includes(subRes.finalUrl)) {
      pagesFetched.push(subRes.finalUrl);
    }
  }

  // 7. Charge `url-audited` ONLY now that the site was cleanly fetched and inspected!
  const urlCharge = await billing.chargeEvent(PPE_EVENTS.URL_AUDITED, 1);
  if (!urlCharge.charged) {
    return { item: null, budgetStopped: true };
  }

  // 8. Run 36-SDK SaaS/Cloud Applicability Fingerprinting & all 4 EU Data Act / DORA checks
  const allDocs = inspectedPages.map((p) => p.doc);
  const domain = finalHomeHost;
  const detectedLanguage = detectSiteLanguage(allDocs);
  const footprint = fingerprintSaasAndCloudApplicability(inspectedPages);
  const discoveredLinks = discoverSaasComplianceLinks(allDocs);

  const egressAndExportInterfaceCheck = checkEgressAndExportInterfaces({
    pages: inspectedPages,
    isSaasOrCloudServiceDetected: footprint.isSaasOrCloudServiceDetected,
    enabled: config.checkEgressFeesAndExportPaywalls,
  });

  const art25SwitchingContractCheck = checkArt25SwitchingContract({
    pages: inspectedPages,
    discoveredLinks,
    isSaasOrCloudServiceDetected: footprint.isSaasOrCloudServiceDetected,
    enabled: config.checkArt25SwitchingTermsAndLockIn,
  });

  const art26bAndArt28TransparencyCheck = checkArt26bAndArt28Transparency({
    pages: inspectedPages,
    isSaasOrCloudServiceDetected: footprint.isSaasOrCloudServiceDetected,
    enabled: config.checkArt26bRegisterAndArt28Notice,
  });

  const art29TerminationAndDoraExitCheck = checkArt29TerminationAndDoraExit({
    pages: inspectedPages,
    isSaasOrCloudServiceDetected: footprint.isSaasOrCloudServiceDetected,
    trustCenterGrcVendors: footprint.trustCenterGrcVendors,
    enabled: config.checkArt29TerminationAndDoraExit,
  });

  const { findings, complianceScore, riskTier } = buildFindingsAndScore({
    homeUrl: homeRes.finalUrl,
    isSaasOrCloudServiceDetected: footprint.isSaasOrCloudServiceDetected,
    discoveredLinks,
    egressCheck: egressAndExportInterfaceCheck,
    art25Check: art25SwitchingContractCheck,
    art26b28Check: art26bAndArt28TransparencyCheck,
    art29DoraCheck: art29TerminationAndDoraExitCheck,
  });

  const coldOutreachHook = generateColdOutreachHook({
    domain,
    isSaasOrCloudServiceDetected: footprint.isSaasOrCloudServiceDetected,
    billingSdkVendors: footprint.billingSdkVendors,
    authIdentityVendors: footprint.authIdentityVendors,
    trustCenterGrcVendors: footprint.trustCenterGrcVendors,
    egressCheck: egressAndExportInterfaceCheck,
    art25Check: art25SwitchingContractCheck,
    art26b28Check: art26bAndArt28TransparencyCheck,
    art29DoraCheck: art29TerminationAndDoraExitCheck,
    findings,
  });

  // 9. Optional Remediation Pack (ONLY generated & charged when enabled AND findings.length > 0)
  let remediationPackGenerated = false;
  let remediationPack: EuDataActAuditReportItem['remediationPack'] = null;

  if (
    config.includeRemediationPack &&
    findings.length > 0 &&
    billing.canAfford(PPE_EVENTS.REMEDIATION_PACK_GENERATED, 1)
  ) {
    const remCharge = await billing.chargeEvent(PPE_EVENTS.REMEDIATION_PACK_GENERATED, 1);
    if (remCharge.charged) {
      remediationPackGenerated = true;
      remediationPack = generateRemediationPack({
        domain,
        sitePlatform: footprint.sitePlatform,
        siteCategory: footprint.siteCategory,
        billingSdkVendors: footprint.billingSdkVendors,
        authIdentityVendors: footprint.authIdentityVendors,
        trustCenterGrcVendors: footprint.trustCenterGrcVendors,
      });
    }
  }

  const reportItem: EuDataActAuditReportItem = {
    url: rawUrl,
    normalizedInputUrl,
    finalUrl: homeRes.finalUrl,
    domain,
    auditedAt: new Date().toISOString(),
    status: 'audited',
    httpStatus: homeRes.statusCode,
    pageTitle: homeDoc.title,
    detectedLanguage,
    sitePlatform: footprint.sitePlatform,
    siteCategory: footprint.siteCategory,
    loadTimeMs: Date.now() - startedMs,
    pagesFetchedCount: pagesFetched.length,
    pagesFetched,
    errorMessage: null,

    isSaasOrCloudServiceDetected: footprint.isSaasOrCloudServiceDetected,
    complianceScore,
    riskTier,

    billingSdkVendors: footprint.billingSdkVendors,
    authIdentityVendors: footprint.authIdentityVendors,
    trustCenterGrcVendors: footprint.trustCenterGrcVendors,
    docsStatusSupportVendors: footprint.docsStatusSupportVendors,
    saasApplicabilitySignals: footprint.saasApplicabilitySignals,

    egressOrSwitchingFeeFound: egressAndExportInterfaceCheck.egressOrSwitchingFeeFound,
    exportPaywallOrTierLockFound: egressAndExportInterfaceCheck.exportPaywallOrTierLockFound,
    egressAndExportInterfaceCheck,

    shortPostTerminationRetentionFound:
      art25SwitchingContractCheck.shortPostTerminationRetentionFound,
    excessiveNoticePeriodLockInFound:
      art25SwitchingContractCheck.excessiveNoticePeriodLockInFound,
    switchingAddendumFound: art25SwitchingContractCheck.switchingAddendumFound,
    art25SwitchingContractCheck,

    art26bOnlinePortabilityRegisterFound:
      art26bAndArt28TransparencyCheck.art26bOnlinePortabilityRegisterFound,
    art28IctJurisdictionDisclosed: art26bAndArt28TransparencyCheck.art28IctJurisdictionDisclosed,
    art28NonPersonalGovAccessSafeguardsDisclosed:
      art26bAndArt28TransparencyCheck.art28NonPersonalGovAccessSafeguardsDisclosed,
    art26bAndArt28TransparencyCheck,

    nonCancellableFixedTermFound: art29TerminationAndDoraExitCheck.nonCancellableFixedTermFound,
    art29EarlyTerminationAndDoraExitGapFound:
      art29TerminationAndDoraExitCheck.art29EarlyTerminationAndDoraExitGapFound,
    art29TerminationAndDoraExitCheck,

    dataActAddendumUrl: discoveredLinks.dataActAddendumUrl,
    portabilityRegisterUrl: discoveredLinks.portabilityRegisterUrl,
    trustOrJurisdictionUrl: discoveredLinks.trustOrJurisdictionUrl,
    pricingOrPlansUrl: discoveredLinks.pricingOrPlansUrl,
    termsOrMsaUrl: discoveredLinks.termsOrMsaUrl,
    discoveredLinks,

    findingsCount: findings.length,
    findings,
    coldOutreachHook,

    remediationPackGenerated,
    remediationPack,

    recommendedNextAudits: buildRecommendedNextAudits(domain),
    disclaimer: LEGAL_DISCLAIMER,
  };

  return { item: reportItem, budgetStopped: billing.isLimitReached() };
}

export async function runBatchAudit(
  rawInput: RawActorInput | null | undefined,
  deps: AuditExecutionDependencies = {},
): Promise<BatchAuditResult> {
  const runtime = deps.runtime ?? new ApifyRuntimeAdapter();
  await runtime.init();

  let extraDatasetUrls: string[] = [];
  if (typeof rawInput?.datasetId === 'string' && rawInput.datasetId.trim().length > 0) {
    extraDatasetUrls = await runtime.loadUrlsFromDataset(
      rawInput.datasetId,
      rawInput.datasetUrlField,
    );
  }

  const config = normalizeAuditInput(rawInput, extraDatasetUrls);
  const billing = deps.billing ?? new BillingManager(runtime, config.maxBudgetUsd);
  const robotsGuard = deps.robotsGuard ?? new RobotsAndRateGuard();
  const pushToDataset = deps.pushToDataset ?? true;
  const chargeActorStart = deps.chargeActorStart ?? true;

  if (chargeActorStart) {
    const startCharge = await billing.chargeEvent(PPE_EVENTS.ACTOR_START, 1);
    if (!startCharge.charged) {
      return {
        items: [],
        billing: billing.getSummary(),
        stoppedDueToBudgetCap: true,
        engineName: 'zero-playwright-pinned-http',
      };
    }
  }

  if (config.urls.length === 0) {
    return {
      items: [],
      billing: billing.getSummary(),
      stoppedDueToBudgetCap: false,
      engineName: 'zero-playwright-pinned-http',
    };
  }

  const orderedItems: Array<EuDataActAuditReportItem | null> = new Array(
    config.urls.length,
  ).fill(null);
  let cursor = 0;
  let stoppedDueToBudgetCap = false;

  const workerCount = Math.min(config.maxConcurrency, config.urls.length);
  const workers = Array.from({ length: workerCount }, async () => {
    while (!stoppedDueToBudgetCap) {
      const index = cursor++;
      if (index >= config.urls.length) break;

      if (billing.isLimitReached() || !billing.canAfford(PPE_EVENTS.URL_AUDITED, 1)) {
        stoppedDueToBudgetCap = true;
        break;
      }

      const targetUrl = config.urls[index];
      const { item, budgetStopped } = await auditSingleSite({
        rawUrl: targetUrl,
        config,
        billing,
        robotsGuard,
        allowLocalhost: deps.allowLocalhost,
        dnsLookup: deps.dnsLookup,
      });

      if (item) {
        orderedItems[index] = item;
        if (pushToDataset) {
          await runtime.pushData(item);
        }
      }

      if (budgetStopped) {
        stoppedDueToBudgetCap = true;
        break;
      }
    }
  });

  await Promise.all(workers);

  const items = orderedItems.filter(
    (x): x is EuDataActAuditReportItem => x !== null,
  );

  return {
    items,
    billing: billing.getSummary(),
    stoppedDueToBudgetCap,
    engineName: 'zero-playwright-pinned-http',
  };
}
