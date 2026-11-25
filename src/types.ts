export const LEGAL_DISCLAIMER =
  'Automated technical heuristic signals for human review only; does not constitute legal advice or formal regulatory certification.';

export const PPE_EVENTS = {
  ACTOR_START: 'actor-start',
  URL_AUDITED: 'url-audited',
  REMEDIATION_PACK_GENERATED: 'remediation-pack-generated',
} as const;

export type PpeEventName = (typeof PPE_EVENTS)[keyof typeof PPE_EVENTS];

export type RiskTier = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type AuditStatus = 'audited' | 'blocked_ssrf' | 'blocked_robots' | 'error';

export type SitePlatform =
  | 'nextjs'
  | 'webflow'
  | 'framer'
  | 'wordpress'
  | 'docusaurus'
  | 'mintlify'
  | 'shopify'
  | 'custom';

export type SiteCategory =
  | 'b2b_or_b2c_saas'
  | 'cloud_or_api_infra'
  | 'ai_or_data_platform'
  | 'ecommerce_or_marketplace'
  | 'brochure_or_content';

export type BillingSdkVendor =
  | 'stripe-billing'
  | 'paddle'
  | 'chargebee'
  | 'recurly'
  | 'lemon-squeezy'
  | 'zuora'
  | 'fastspring'
  | 'braintree';

export type AuthIdentityVendor =
  | 'auth0'
  | 'clerk'
  | 'workos'
  | 'okta'
  | 'stytch'
  | 'supabase-auth'
  | 'firebase-auth'
  | 'cognito';

export type TrustCenterGrcVendor =
  | 'vanta'
  | 'drata'
  | 'safebase'
  | 'conveyor'
  | 'whistic'
  | 'onetrust'
  | 'secureframe'
  | 'sprinto';

export type DocsStatusSupportVendor =
  | 'statuspage'
  | 'betterstack'
  | 'instatus'
  | 'swagger-openapi'
  | 'mintlify'
  | 'readme-io'
  | 'gitbook'
  | 'docusaurus'
  | 'intercom'
  | 'zendesk'
  | 'crisp'
  | 'hubspot';

export interface UrlRequestObject {
  url: string;
}

export interface RawActorInput {
  urls?: Array<string | UrlRequestObject>;
  startUrls?: Array<string | UrlRequestObject>;
  url?: string;
  datasetId?: string;
  datasetUrlField?: string;
  maxLegalPagesPerDomain?: number;
  includeRemediationPack?: boolean;
  checkEgressFeesAndExportPaywalls?: boolean;
  checkArt25SwitchingTermsAndLockIn?: boolean;
  checkArt26bRegisterAndArt28Notice?: boolean;
  checkArt29TerminationAndDoraExit?: boolean;
  respectRobotsTxt?: boolean;
  maxUrls?: number;
  maxConcurrency?: number;
  domainDelayMs?: number;
  requestTimeoutMs?: number;
  maxBudgetUsd?: number;
  maxTotalChargeUsd?: number;
}

export interface NormalizedAuditInput {
  urls: string[];
  datasetId?: string;
  datasetUrlField?: string;
  maxLegalPagesPerDomain: number;
  includeRemediationPack: boolean;
  checkEgressFeesAndExportPaywalls: boolean;
  checkArt25SwitchingTermsAndLockIn: boolean;
  checkArt26bRegisterAndArt28Notice: boolean;
  checkArt29TerminationAndDoraExit: boolean;
  respectRobotsTxt: boolean;
  maxUrls: number;
  maxConcurrency: number;
  domainDelayMs: number;
  requestTimeoutMs: number;
  maxBudgetUsd?: number;
}

export interface ParsedScriptTag {
  src: string;
  resolvedSrc: string;
  dataSrc: string;
  resolvedDataSrc: string;
  type: string;
  id: string;
  className: string;
  dataAttributes: string;
  rawAttrs: string;
  inlineCode: string;
}

export interface ParsedIframeTag {
  src: string;
  resolvedSrc: string;
  dataSrc: string;
  resolvedDataSrc: string;
  title: string;
  id: string;
  className: string;
  dataAttributes: string;
  rawAttrs: string;
}

export interface ParsedAnchor {
  href: string;
  resolvedHref: string;
  text: string;
  ariaLabel: string;
  title: string;
  id: string;
  className: string;
  inFooter: boolean;
  inNav: boolean;
}

export interface ParsedControl {
  tag: 'button' | 'input' | 'role-button';
  type: string;
  text: string;
  ariaLabel: string;
  id: string;
  className: string;
  name: string;
  dataAttributes: string;
}

export interface ParsedCheckbox {
  id: string;
  name: string;
  className: string;
  value: string;
  checked: boolean;
  required: boolean;
  dataAttributes: string;
  rawAttrs: string;
  associatedText: string;
}

export interface ParsedForm {
  action: string;
  resolvedAction: string;
  method: string;
  id: string;
  className: string;
  inputNamesAndTypes: string[];
  buttonTexts: string[];
  textSnippet: string;
}

export interface ParsedHtmlDocument {
  url: string;
  title: string | null;
  htmlLang: string | null;
  rawHtml: string;
  domHtml: string;
  visibleText: string;
  scripts: ParsedScriptTag[];
  scriptUrls: string[];
  inlineScripts: string[];
  iframes: ParsedIframeTag[];
  stylesheetUrls: string[];
  jsonLdBlocks: unknown[];
  hasSoftwareAppJsonLd: boolean;
  hasProductJsonLd: boolean;
  anchors: ParsedAnchor[];
  controls: ParsedControl[];
  checkboxes: ParsedCheckbox[];
  forms: ParsedForm[];
}

export interface DiscoveredSaasComplianceLinks {
  dataActAddendumUrl: string | null;
  portabilityRegisterUrl: string | null;
  trustOrJurisdictionUrl: string | null;
  pricingOrPlansUrl: string | null;
  termsOrMsaUrl: string | null;
  docsOrApiUrl: string | null;
}

export interface EgressAndExportInterfaceCheckResult {
  checked: boolean;
  egressOrSwitchingFeeFound: boolean;
  egressFeeMatches: string[];
  exportPaywallOrTierLockFound: boolean;
  exportPaywallMatches: string[];
  zeroEgressGuaranteeFound: boolean;
  freeOpenExportAllPlansFound: boolean;
  art34ParallelMultiCloudCarveOutFound: boolean;
  evidence: string[];
  foundOnPages: string[];
}

export interface Art25SwitchingContractCheckResult {
  checked: boolean;
  switchingAddendumFound: boolean;
  commissionRec20262394Referenced: boolean;
  shortPostTerminationRetentionFound: boolean;
  shortRetentionMatches: string[];
  excessiveNoticePeriodLockInFound: boolean;
  excessiveNoticeMatches: string[];
  art25NoticeOverrideFound: boolean;
  maxTwoMonthNoticeFound: boolean;
  thirtyDayTransitionFound: boolean;
  thirtyDayRetrievalAndErasureFound: boolean;
  evidence: string[];
  foundOnPages: string[];
}

export interface Art26bAndArt28TransparencyCheckResult {
  checked: boolean;
  art26bOnlinePortabilityRegisterFound: boolean;
  exportFormatsDisclosed: string[];
  exemptedTradeSecretCategoriesSpecified: boolean;
  art28IctJurisdictionDisclosed: boolean;
  jurisdictionSignals: string[];
  art28NonPersonalGovAccessSafeguardsDisclosed: boolean;
  govAccessSafeguardSignals: string[];
  gdprPersonalDataOnlyNoticeWithoutArt28: boolean;
  evidence: string[];
  foundOnPages: string[];
}

export interface Art29TerminationAndDoraExitCheckResult {
  checked: boolean;
  nonCancellableFixedTermFound: boolean;
  fixedTermMatches: string[];
  enterpriseOrRegulatedTargetSignalsFound: boolean;
  enterpriseTargetSignals: string[];
  art29EarlyTerminationMethodologyFound: boolean;
  doraOrDocumentedExitStrategyFound: boolean;
  art29EarlyTerminationAndDoraExitGapFound: boolean;
  evidence: string[];
  foundOnPages: string[];
}

export interface ComplianceFinding {
  ruleId: string;
  title: string;
  regulation: string;
  severity: FindingSeverity;
  deductionPoints: number;
  pageUrl: string;
  evidence: string;
  recommendation: string;
}

export interface RemediationPack {
  domain: string;
  sitePlatform: SitePlatform;
  siteCategory: SiteCategory;
  detectedBillingVendors: BillingSdkVendor[];
  detectedAuthVendors: AuthIdentityVendor[];
  detectedTrustCenterVendors: TrustCenterGrcVendor[];
  euDataActSwitchingAddendumHtml: string;
  onlinePortabilityRegisterAndArt28Html: string;
  pricingZeroEgressDisclosureWidgetHtmlJs: string;
  regulatoryCoverageSummary: string;
  implementationNotes: string[];
}

export interface RecommendedNextAudit {
  actorSlug: string;
  actorUrl: string;
  mcpEndpointUrl: string;
  reason: string;
}

export interface EuDataActAuditReportItem {
  url: string;
  normalizedInputUrl: string;
  finalUrl: string | null;
  domain: string;
  auditedAt: string;
  status: AuditStatus;
  httpStatus: number | null;
  pageTitle: string | null;
  detectedLanguage: string | null;
  sitePlatform: SitePlatform;
  siteCategory: SiteCategory;
  loadTimeMs: number;
  pagesFetchedCount: number;
  pagesFetched: string[];
  errorMessage: string | null;

  isSaasOrCloudServiceDetected: boolean;
  complianceScore: number;
  riskTier: RiskTier;

  billingSdkVendors: BillingSdkVendor[];
  authIdentityVendors: AuthIdentityVendor[];
  trustCenterGrcVendors: TrustCenterGrcVendor[];
  docsStatusSupportVendors: DocsStatusSupportVendor[];
  saasApplicabilitySignals: string[];

  egressOrSwitchingFeeFound: boolean;
  exportPaywallOrTierLockFound: boolean;
  egressAndExportInterfaceCheck: EgressAndExportInterfaceCheckResult;

  shortPostTerminationRetentionFound: boolean;
  excessiveNoticePeriodLockInFound: boolean;
  switchingAddendumFound: boolean;
  art25SwitchingContractCheck: Art25SwitchingContractCheckResult;

  art26bOnlinePortabilityRegisterFound: boolean;
  art28IctJurisdictionDisclosed: boolean;
  art28NonPersonalGovAccessSafeguardsDisclosed: boolean;
  art26bAndArt28TransparencyCheck: Art26bAndArt28TransparencyCheckResult;

  nonCancellableFixedTermFound: boolean;
  art29EarlyTerminationAndDoraExitGapFound: boolean;
  art29TerminationAndDoraExitCheck: Art29TerminationAndDoraExitCheckResult;

  dataActAddendumUrl: string | null;
  portabilityRegisterUrl: string | null;
  trustOrJurisdictionUrl: string | null;
  pricingOrPlansUrl: string | null;
  termsOrMsaUrl: string | null;
  discoveredLinks: DiscoveredSaasComplianceLinks;

  findingsCount: number;
  findings: ComplianceFinding[];
  coldOutreachHook: string;

  remediationPackGenerated: boolean;
  remediationPack: RemediationPack | null;

  recommendedNextAudits: RecommendedNextAudit[];
  disclaimer: string;
}
