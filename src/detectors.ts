import type {
  Art25SwitchingContractCheckResult,
  Art26bAndArt28TransparencyCheckResult,
  Art29TerminationAndDoraExitCheckResult,
  AuthIdentityVendor,
  BillingSdkVendor,
  DiscoveredSaasComplianceLinks,
  DocsStatusSupportVendor,
  EgressAndExportInterfaceCheckResult,
  ParsedAnchor,
  ParsedHtmlDocument,
  SiteCategory,
  SitePlatform,
  TrustCenterGrcVendor,
} from './types.js';

export interface InspectedPageBundle {
  requestedUrl: string;
  finalUrl: string;
  redirectChain: string[];
  doc: ParsedHtmlDocument;
}

const ASSET_EXTENSION_RE =
  /\.(?:jpg|jpeg|png|gif|webp|avif|svg|ico|css|js|mjs|woff|woff2|ttf|eot|mp4|webm|mp3|zip|tar|gz|rar|xml)(?:[?#]|$)/i;

const TWO_PART_PUBLIC_SUFFIXES = new Set([
  'co.uk',
  'org.uk',
  'gov.uk',
  'ac.uk',
  'com.au',
  'net.au',
  'org.au',
  'co.jp',
  'ne.jp',
  'or.jp',
  'com.br',
  'co.nz',
  'co.in',
  'co.za',
  'com.sg',
  'com.hk',
  'com.mx',
  'co.kr',
  'co.il',
]);

export function extractRegistrableDomain(rawHost: string): string {
  const host = rawHost
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.+$/, '');
  if (
    !host ||
    host === 'localhost' ||
    /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) ||
    host.includes(':')
  ) {
    return host;
  }
  const labels = host.split('.').filter(Boolean);
  if (labels.length <= 2) {
    return labels.join('.');
  }
  const lastTwo = `${labels[labels.length - 2]}.${labels[labels.length - 1]}`;
  if (TWO_PART_PUBLIC_SUFFIXES.has(lastTwo) && labels.length >= 3) {
    return labels.slice(-3).join('.');
  }
  return labels.slice(-2).join('.');
}

// 1. Billing / Subscription SDKs (8) — separating strong SaaS billing from generic payment gateways (F-02)
const STRIPE_STRONG_SAAS_BILLING_RE = /\b(?:billing\.stripe\.com|stripe-pricing-table)\b/i;
const STRIPE_GENERIC_JS_RE = /\b(?:js\.stripe\.com|buy\.stripe\.com)\b/i;

const NON_STRIPE_BILLING_SDK_PATTERNS: Array<{
  vendor: Exclude<BillingSdkVendor, 'stripe-billing'>;
  strongSaas: boolean;
  regex: RegExp;
}> = [
  {
    vendor: 'paddle',
    strongSaas: true,
    regex: /\b(?:cdn\.paddle\.com|paddle\.com\/paddle\.js|Paddle\.(?:Setup|Initialize))\b/i,
  },
  {
    vendor: 'chargebee',
    strongSaas: true,
    regex: /\b(?:js\.chargebee\.com|chargebee\.com\/v2\/chargebee\.js|data-cb-type)\b/i,
  },
  {
    vendor: 'recurly',
    strongSaas: true,
    regex: /\b(?:js\.recurly\.com|recurly\.Configure)\b/i,
  },
  {
    vendor: 'lemon-squeezy',
    strongSaas: true,
    regex: /\b(?:assets\.lemonsqueezy\.com|lemonsqueezy\.com|createLemonSqueezy)\b/i,
  },
  {
    vendor: 'zuora',
    strongSaas: true,
    regex: /\b(?:static\.zuora\.com|zuora\.com|Z\.renderWithErrorHandler)\b/i,
  },
  {
    vendor: 'fastspring',
    strongSaas: true,
    regex: /\b(?:d1f8f9xcsvx3ha\.cloudfront\.net|fastspring\.com|data-fsc-[a-z0-9_-]+)/i,
  },
  {
    vendor: 'braintree',
    strongSaas: false,
    regex: /\b(?:js\.braintreegateway\.com|braintreegateway\.com|braintree\.client\.create)\b/i,
  },
];

// 2. Auth / SSO / B2B Identity SDKs (8 — all strong SaaS signals)
const AUTH_IDENTITY_PATTERNS: Array<{ vendor: AuthIdentityVendor; regex: RegExp }> = [
  {
    vendor: 'auth0',
    regex: /\b(?:cdn\.auth0\.com|auth0\.com|auth0-spa-js|createAuth0Client)\b/i,
  },
  {
    vendor: 'clerk',
    regex: /\b(?:clerk\.com|clerk\.accounts|clerk\.browser\.js|data-clerk-[a-z0-9_-]+)/i,
  },
  {
    vendor: 'workos',
    regex: /\b(?:workos\.com|authkit\.app|workos-inc)\b/i,
  },
  {
    vendor: 'okta',
    regex: /\b(?:oktacdn\.com|okta\.com|OktaSignIn|okta-signin-widget)\b/i,
  },
  {
    vendor: 'stytch',
    regex: /\b(?:js\.stytch\.com|stytch\.com)\b/i,
  },
  {
    vendor: 'supabase-auth',
    regex: /\b(?:supabase\.co|supabase-js|gotrue-js)\b/i,
  },
  {
    vendor: 'firebase-auth',
    regex: /\b(?:firebaseapp\.com|firebasejs|firebase-auth|googleapis\.com\/identitytoolkit)\b/i,
  },
  {
    vendor: 'cognito',
    regex: /\b(?:amazoncognito\.com|aws-amplify|cognito-identity)\b/i,
  },
];

// 3. Trust Center & GRC Platforms (8)
const TRUST_CENTER_GRC_PATTERNS: Array<{ vendor: TrustCenterGrcVendor; regex: RegExp }> = [
  {
    vendor: 'vanta',
    regex: /\b(?:vanta\.com|trust\.vanta|static\.vanta\.com)\b/i,
  },
  {
    vendor: 'drata',
    regex: /\b(?:drata\.com|trust\.drata)\b/i,
  },
  {
    vendor: 'safebase',
    regex: /\b(?:safebase\.io|trust\.safebase)\b/i,
  },
  {
    vendor: 'conveyor',
    regex: /\b(?:conveyor\.com|conveyor-trust)\b/i,
  },
  {
    vendor: 'whistic',
    regex: /\b(?:whistic\.com|trust\.whistic)\b/i,
  },
  {
    vendor: 'onetrust',
    regex: /\b(?:onetrust\.com|cookielaw\.org|optanon)\b/i,
  },
  {
    vendor: 'secureframe',
    regex: /\b(?:secureframe\.com|trust\.secureframe)\b/i,
  },
  {
    vendor: 'sprinto',
    regex: /\b(?:sprinto\.com|trust\.sprinto)\b/i,
  },
];

// 4. Developer Docs, Status & Support SaaS Markers (12)
const DOCS_STATUS_SUPPORT_PATTERNS: Array<{ vendor: DocsStatusSupportVendor; regex: RegExp }> = [
  {
    vendor: 'statuspage',
    regex: /\b(?:statuspage\.io|sp-status-embed)\b/i,
  },
  {
    vendor: 'betterstack',
    regex: /\b(?:betterstack\.com|betteruptime\.com)\b/i,
  },
  {
    vendor: 'instatus',
    regex: /\b(?:instatus\.com|instatus-widget)\b/i,
  },
  {
    vendor: 'swagger-openapi',
    regex: /\b(?:swagger-ui|openapi\.(?:json|yaml|yml)|\bredoc(?:\.standalone)?\b)/i,
  },
  {
    vendor: 'mintlify',
    regex: /\b(?:mintlify\.com|mintlify\.app|_mintlify)\b/i,
  },
  {
    vendor: 'readme-io',
    regex: /\b(?:readme\.io|readme\.com|rm-Guides)\b/i,
  },
  {
    vendor: 'gitbook',
    regex: /\b(?:gitbook\.io|gitbook-root)\b/i,
  },
  {
    vendor: 'docusaurus',
    regex: /\b(?:docusaurus|__docusaurus)\b/i,
  },
  {
    vendor: 'intercom',
    regex: /\b(?:widget\.intercom\.io|intercomSettings)\b/i,
  },
  {
    vendor: 'zendesk',
    regex: /\b(?:static\.zdassets\.com|zdassets\.com|ze-snippet)\b/i,
  },
  {
    vendor: 'crisp',
    regex: /(?:(?:\bclient\.crisp\.chat|\bCRISP_WEBSITE_ID)\b|\$crisp\b)/i,
  },
  {
    vendor: 'hubspot',
    regex: /\b(?:js\.hs-scripts\.com|js\.hsforms\.net|hs-script-loader)\b/i,
  },
];

// Dedicated SaaS Trust & Docs vendors (excludes generic cookie CMP OneTrust and generic chat/CRM Intercom/Zendesk/Crisp/HubSpot alone)
const DEDICATED_SAAS_TRUST_VENDORS = new Set<TrustCenterGrcVendor>([
  'vanta',
  'drata',
  'safebase',
  'conveyor',
  'whistic',
  'secureframe',
  'sprinto',
]);

const DEDICATED_SAAS_DOCS_STATUS_VENDORS = new Set<DocsStatusSupportVendor>([
  'statuspage',
  'betterstack',
  'instatus',
  'swagger-openapi',
  'mintlify',
  'readme-io',
  'gitbook',
  'docusaurus',
]);

// Strong vs Weak Structural SaaS / Cloud / API signals (F-02)
const STRONG_SAAS_CONSOLE_LINK_RE =
  /(?:^https?:\/\/(?:app|console|dashboard|portal|cloud)\.[a-z0-9.-]+|\/(?:console|dashboard|sso)(?:[/?#]|$))/i;

const WEAK_ROOT_AUTH_PATH_RE = /^\/(?:login|signin|sign-in|signup|sign-up|register)(?:[/?#]|$)/i;

const NON_SAAS_AUTH_OR_ECOM_PATH_RE =
  /(?:\/account\/(?:login|register)|\/customer\/account|\/my-account|\/cart\b|\/checkout\b|wp-login\.php|\/wp-admin)/i;

const STRONG_SAAS_SEAT_OR_TIER_COPY_RE =
  /\b(?:per\s+(?:seat|user|workspace|organization)|starter\s+plan|pro\s+plan|enterprise\s+plan|api\s+access|developer\s+api|start\s+(?:your\s+)?free\s+trial)\b/i;

const WEAK_RECURRING_PRICE_COPY_RE =
  /(?:[\$€£]\s*\d{1,6}(?:\.\d{1,2})?\s*(?:\/\s*(?:mo(?:nth)?|yr|year)\b|\bper\s+(?:month|year)\b)|\bbilled\s+(?:monthly|annually)\b)/i;

// Bare `subprocessors?` removed per F-02 so retail GDPR privacy policies never trigger SaaS classification
const STRONG_SAAS_EXPLICIT_SERVICE_TERMS_RE =
  /\b(?:b2b\s+saas|saas\s+(?:platform|service|application|stack)|cloud\s+(?:platform|infrastructure|hosting|database|storage|computing)|data\s+processing\s+services?|\bpaas\b|\biaas\b|rest\s+api|graphql\s+api|multi[- ]tenant|eu\s+data\s+act)\b/i;

// Sentence-bounded negation guard
const POLICY_NEGATION_PREFIX_RE =
  /\b(?:no|zero|free(?:\s+of\s+charge)?|without(?:\s+any)?|never|prohibit(?:s|ed|ing)?|waive(?:s|d)?|eliminat(?:e|ed|es|ing)|abolish(?:ed)?|do\s+not|don't|does\s+not|shall\s+not(?:\s+impose)?|will\s+not(?:\s+impose|\s+charge)?|not\s+(?:charge|impose|apply|require|lock|restrict|gate|delete|erase|disclose)|exempt(?:ed)?\s+from|[\$€£]\s*0(?:\.00)?)\b/i;

const ART_34_PARALLEL_CARVE_OUT_RE =
  /\b(?:in[- ]parallel(?:\s+multi[- ]cloud)?|multi[- ]cloud\s+in\s+parallel|art(?:icle)?\.?\s*34\s*\(\s*2\s*\))\b/i;

const SAME_SENTENCE_DATA_ACT_CARVE_OUT_RE =
  /(?:\b(?:waived|eliminated|€0|[\$£]0(?:\.00)?|free\s+of\s+charge|no\s+(?:switching|egress|offboarding)\s+(?:fee|charge)s?)[^.!?\n]{0,100}?(?:eu\s+data\s+act|art(?:icle)?\.?\s*(?:29|30)|2023\/2854)|\b(?:under|pursuant\s+to|for\s+eu\s+customers\s+under)\s+(?:the\s+)?(?:eu\s+data\s+act|art(?:icle)?\.?\s*(?:29|30))[^.!?\n]{0,100}?(?:waived|€0|[\$£]0(?:\.00)?|free\s+of\s+charge|unlocked\s+on\s+all\s+plans)\b)/i;

// Rule 1: Explicit Egress / Switching / Offboarding / Data-Extraction Fees (Art. 29(1)) — ReDoS-free disjoint `0\.0*[1-9]\d{0,5}` + sub-$1/GB + outbound transfer (F-01, F-04)
const EGRESS_FEE_CURRENCY_FIRST_RE =
  /(?:[\$€£]\s*(?:0\.0*[1-9]\d{0,5}|[1-9]\d{0,6}(?:,\d{3}){0,2}(?:\.\d{1,4})?)|\b(?:0\.0*[1-9]\d{0,5}|[1-9]\d{0,6}(?:,\d{3}){0,2}(?:\.\d{1,4})?)\s*(?:usd|eur|gbp|cents))\s*(?:\/\s*(?:gb|tb|mb)\s*|per\s+(?:gb|tb|mb|export|migration|workspace)\s+)?(?:one[- ]time\s+|professional[- ]services\s+|custom\s+|paid\s+|mandatory\s+)?(?:data[- ]?|network[- ]?)?(?:offboarding(?:\s*\/\s*(?:data[- ]?)?extraction)?|switching|egress|outbound\s+(?:data\s+)?transfer|data[- ]extraction|extraction|migration(?:\s+export)?|data[- ]retrieval)(?:\s+data)?(?:\s+extraction|\s+transfer|\s+export)?\s*(?:fee|charge|surcharge|cost)s?/gi;

const EGRESS_FEE_LABEL_FIRST_RE =
  /\b(?:data\s+egress|network\s+egress|outbound\s+(?:data\s+)?transfer|cloud\s+switching|switching|offboarding|data\s+extraction|data\s+retrieval)\s+(?:fee|charge|rate|tariff|surcharge)s?\s*(?:of|:|-|–|—|\bat\b)?\s*(?:[\$€£]\s*0\.0*[1-9]\d{0,5}|[\$€£]\s*[1-9]\d{0,6}(?:,\d{3}){0,2}(?:\.\d{1,4})?|\b0\.0*[1-9]\d{0,5}\s*(?:usd|eur|gbp|cents))\s*(?:\/\s*(?:gb|tb|mb)|per\s+(?:gb|tb|mb))?/gi;

const PAID_MIGRATION_EXPORT_RE =
  /\b(?:paid\s+(?:migration|data|offboarding)\s+export|(?:migration|data|offboarding)\s+(?:export|extraction)\s+(?:requires|incurs|is\s+subject\s+to)\s+a\s+(?:paid|custom|professional\s+services|one[- ]time)\s+(?:fee|charge|engagement))\b/gi;

// Rule 1: Export / Open-Interface Paywall (Art. 30(2) & Art. 29(1)) — Mandatory gating verb OR `: Enterprise [Plan] only` (F-04)
const EXPORT_PAYWALL_RE =
  /\b(?:(?:bulk\s+|full\s+|raw\s+|automated\s+|self[- ]serve\s+)?(?:csv\s*\/\s*json|json\s*\/\s*csv|csv|json|parquet|sql|api\s*(?:&|and)\s*data|data|workspace|account)\s+(?:bulk\s+)?export(?:s|\s+api)?|(?:open|rest|export)\s+api\s*(?:&|and)\s*(?:bulk\s+)?data\s+export)(?:(?:\s*(?::|-|–|—|\bis\b|\bare\b)?\s+(?:available\s+only\s+(?:on|in|for|with)|only\s+available\s+(?:on|in|for|with)|restricted\s+to|exclusive\s+to|requires?(?:\s+an?)?|locked\s+behind|gated\s+behind|included\s+only\s+(?:on|in))\s+(?:the\s+)?(?:enterprise|ultimate|scale|premier|business\s+plus|higher[- ]tier)(?:\s+(?:plan|tier|edition|upgrade|subscription)s?)?(?:\s+only)?)|(?:\s*(?::|-|–|—)\s*(?:the\s+)?(?:enterprise|ultimate|scale|premier|business\s+plus)(?:\s+(?:plan|tier|edition|subscription))?\s+only))\b/gi;

const ZERO_EGRESS_GUARANTEE_RE =
  /(?:(?:[\$€£]\s*0(?:\.00)?|zero|no)\s+(?:cloud\s+|saas\s+)?(?:switching|data\s+egress|egress|offboarding|data\s+extraction)\s+(?:fees?|charges?|costs?)|\bshall\s+not\s+impose\s+any\s+switching\s+charges\b|\beu\s+data\s+act\s+art(?:icle)?\.?\s*29\s*\(\s*1\s*\)\s*€0\b)/i;

const FREE_OPEN_EXPORT_ALL_PLANS_RE =
  /\b(?:free(?:\s+of\s+charge)?\s+(?:self[- ]serve\s+|open\s+)?(?:data\s+export|bulk\s+export|csv\s*\/\s*json(?:\s*\/\s*api)?\s+export|open\s+interfaces?)\s+(?:on|across|for)\s+all\s+(?:plans|tiers|subscriptions|customers)|open\s+interfaces?\s+available\s+free\s+of\s+charge(?:\s+across\s+all\s+plans)?)\b/i;

// Rule 2: Post-termination <30-day deletion or >2-month notice lock-in (Art. 25(2)(d) & (g)) — Precision & clause-initial pattern (F-03, F-05)
const IMMEDIATE_POST_TERMINATION_DELETION_RE =
  /\b(?:(?:customer|account|workspace|hosted|tenant|all)\s+data(?:\s+and\s+(?:files|backups|digital\s+assets))?\s+(?:is|are|will\s+be|shall\s+be)?\s*(?:permanently\s+|automatically\s+)?(?:deleted|erased|purged|destroyed|wiped)\s+immediately\s+(?:upon|on|at|after)\s+(?:contract\s+|subscription\s+|account\s+|service\s+)?(?:termination|cancellation|expiration|closure)|(?:customer|account|workspace|all)\s+data\s+(?:is|are|will\s+be|shall\s+be)\s+(?:permanently\s+)?(?:deleted|erased|purged|destroyed)\s+upon\s+(?:contract\s+|subscription\s+|account\s+)?(?:termination|cancellation))\b/gi;

const SUB_30_DAY_POST_TERMINATION_DELETION_RE =
  /\b(?:deleted|erased|purged|destroyed|wiped)\s+(?:permanently\s+)?within\s+(?:([1-9]|[12]\d)\s*(?:calendar\s+|business\s+)?days?|(?:24|48|72)\s*hours?|[12]\s*weeks?)\s+(?:of|after|following)\s+(?:contract\s+|subscription\s+|account\s+|service\s+)?(?:termination|cancellation|expiration|closure|non[- ]renewal)\b/gi;

const CLAUSE_INITIAL_SUB_30_DAY_DELETION_RE =
  /\b(?:upon|on|after|following)\s+(?:contract\s+|subscription\s+|account\s+|service\s+)?(?:termination|cancellation|expiration|closure|non[- ]renewal)\b[^.!?\n]{0,120}?\b(?:customer|account|workspace|hosted|tenant|all)\s+(?:[a-z]+\s+){0,3}?data\b[^.!?\n]{0,80}?\b(?:deleted|erased|purged|destroyed|wiped)\s+(?:permanently\s+)?(?:immediately|within\s+(?:(?:[1-9]|[12]\d)\s*(?:calendar\s+|business\s+)?days?|(?:24|48|72)\s*hours?|[12]\s*weeks?))\b/gi;

const DELETION_EXEMPT_CONTEXT_RE =
  /\b(?:retrieval\s+(?:period|window)|30[- ]?(?:calendar[- ]?)?day\s+(?:data\s+)?retrieval|transitional\s+period|cookies?|sessions?|tokens?|api\s+keys?|credentials?|caches?|temp(?:orary)?\s+(?:files?|links?|urls?)|otps?|password[- ]reset|free\s+trials?|trial\s+(?:accounts?|workspaces?|periods?|expirations?)|sandbox(?:es)?|beta\s+previews?|gdpr\s+(?:art(?:icle)?\.?\s*17\s+)?erasure\s+requests?|data\s+subject\s+(?:deletion|erasure)\s+requests?|upon\s+(?:written\s+)?request\s+by\s+(?:the\s+)?customer)\b/i;

const EXCESSIVE_NOTICE_PERIOD_RE =
  /\b(?:(?:at\s+least|minimum(?:\s+of)?|requires?|give|provide)\s+(?:at\s+least\s+)?(?:(?:6[5-9]|[789]\d|[12]\d{2}|3[0-6]\d)\s*[- ]?(?:calendar\s+)?days?|(?:[3-9]|1[0-2]|three|four|six|nine|twelve)\s*(?:\(\d+\)\s*)?[- ]?months?)\s+(?:prior\s+|advance\s+)?(?:written\s+)?notice|(?:(?:6[5-9]|[789]\d|[12]\d{2}|3[0-6]\d)\s*[- ]?(?:calendar\s+)?days?|(?:[3-9]|1[0-2]|three|four|six|nine|twelve)\s*(?:\(\d+\)\s*)?[- ]?months?)(?:'s?)?\s+(?:prior\s+|advance\s+)?(?:written\s+)?notice)\b/gi;

const NOTICE_SWITCHING_OR_TERMINATION_CONTEXT_RE =
  /\b(?:terminat(?:e|ion|ing)|cancel(?:lation|ling)?|non[- ]renew(?:al)?|opt\s+out\s+of\s+renewal|prevent\s+(?:auto[- ]?)?renewal|switch(?:ing)?)\b/i;

const PROVIDER_GIVES_NOTICE_SUBJECT_RE =
  /\b(?:we|us|our|provider|company|vendor|supplier)\s+(?:shall\s+|will\s+|may\s+|must\s+|agrees?\s+to\s+)?(?:give|provide|send|deliver|notify)\b/i;

const NON_SWITCHING_NOTICE_TOPIC_RE =
  /\b(?:price\s+(?:change|increase|adjustment)s?|fee\s+(?:change|increase)s?|(?:terms|agreement|policy|sla)\s+(?:update|change|modification|amendment)s?|api\s+deprecat(?:e|ed|ion)|end[- ]of[- ]life|subprocessor(?:s|\s+change|\s+addition)?|security\s+audit|penetration\s+test|pen[- ]test|vulnerability\s+(?:scan|test))\b/i;

const ART_25_NOTICE_OVERRIDE_RE =
  /(?:\b(?:notwithstanding|override|supersede|capped\s+at|maximum\s+notice\s+period\s+of|shall\s+not\s+exceed)[^.!?\n]{0,120}?(?:≤\s*2\s*months?|2\s*[- ]?months?|two\s+months?|60\s*days?)[^.!?\n]{0,120}?(?:eu\s+data\s+act|art(?:icle)?\.?\s*25)|\beu\s+data\s+act[^.!?\n]{0,120}?(?:notice\s+period[^.!?\n]{0,60}?(?:≤\s*2\s*months?|not\s+exceed\s+2\s+months?|max(?:imum)?\s+2\s+months?)))/i;

// Rule 3: Art. 25 Switching Addendum signals
const DATA_ACT_FRAMEWORK_SIGNAL_RE =
  /\b(?:eu\s+data\s+act|regulation\s*\(eu\)\s*2023\/2854|cloud\s+switching\s+(?:addendum|terms|clauses)|data\s+act\s+(?:switching\s+)?addendum|commission\s+recommendation\s*\(eu\)\s*2026\/2394|chapter\s+vi\s+of\s+the\s+data\s+act)\b/i;

const RECOMMENDATION_2026_2394_RE =
  /\b(?:2026\/2394|standard\s+contractual\s+clauses\s+for\s+cloud\s+computing|eu\s+cloud\s+switching\s+sccs?)\b/i;

const MAX_TWO_MONTH_NOTICE_SIGNAL_RE =
  /(?:(?:notice\s+period[^.!?\n]{0,70}?(?:≤\s*2\s*months?|not\s+exceed(?:ing)?\s+(?:2|two)\s+months?|max(?:imum)?\s+(?:of\s+)?(?:2|two)\s+months?|\b(?:30|60)\s*(?:calendar\s+)?days?\b))|(?:art(?:icle)?\.?\s*25\s*\(\s*2\s*\)\s*\(\s*d\s*\)))/i;

const THIRTY_DAY_TRANSITION_SIGNAL_RE =
  /(?:\b(?:30[- ]?(?:calendar[- ]?)?day\s+transitional\s+period|transitional\s+period\s+of\s+(?:up\s+to\s+|maximum\s+|≤\s*)?30\s*(?:calendar\s+)?days|port(?:ing)?\s+within\s+30\s+calendar\s+days|art(?:icle)?\.?\s*25\s*\(\s*2\s*\)\s*\(\s*a\s*\))\b)/i;

const THIRTY_DAY_RETRIEVAL_SIGNAL_RE =
  /(?:\b(?:(?:minimum\s+|at\s+least\s+|≥\s*)?30[- ]?(?:calendar[- ]?)?day\s+(?:data\s+)?retrieval\s+(?:period|window)|retrieval\s+period\s+of\s+at\s+least\s+30\s*(?:calendar\s+)?days|retrieve\s+(?:exportable\s+)?data\s+for\s+(?:at\s+least\s+)?30\s*(?:calendar\s+)?days|art(?:icle)?\.?\s*25\s*\(\s*2\s*\)\s*\(\s*g\s*\))\b)/i;

// Rule 4: Art. 26(b) Online Portability Register (strictly distinct from Art. 28!)
const ART_26B_REGISTER_SIGNAL_RE =
  /\b(?:online\s+(?:portability\s+)?register|portability\s+register|data\s+structures\s+and\s+data\s+formats(?:\s+register)?|register\s+of\s+(?:exportable\s+)?data\s+structures|art(?:icle)?\.?\s*26\s*\(\s*b\s*\)|exportable\s+data\s+(?:inventory|catalog|register|specification))\b/i;

const EXPORT_SCHEMA_FORMATS_RE =
  /\b(?:json|ndjson|csv|parquet|openapi(?:\s*3\.\d)?|avro|xml|sql\s+dump|graphql\s+schema)\b/gi;

const TRADE_SECRET_EXEMPTION_SPEC_RE =
  /\b(?:trade[- ]secrets?|exempted\s+(?:data\s+)?categories|internal\s+functioning\s+of\s+the\s+(?:provider|service)|art(?:icle)?\.?\s*25\s*\(\s*2\s*\)\s*\(\s*f\s*\))\b/i;

// Rule 5: Art. 28(1)(a)-(b) & Art. 32 ICT Jurisdiction & Non-Personal Data Gov-Access Safeguards (expanded per F-09)
const ART_28_ICT_JURISDICTION_RE =
  /\b(?:(?:ict|cloud|hosting|server|data\s+center|data\s+processing)\s+infrastructure[^.!?\n]{0,120}?jurisdiction|jurisdiction\s+to\s+which\s+(?:the\s+|our\s+)?(?:ict|cloud|hosting|server|data\s+center|data\s+processing)\s+infrastructure|art(?:icle)?\.?\s*28\s*\(\s*1\s*\)\s*\(\s*a\s*\)|subject\s+to\s+(?:the\s+)?(?:laws\s+and\s+)?jurisdiction\s+of\s+[a-z])/gi;

const ART_28_32_NON_PERSONAL_GOV_ACCESS_RE =
  /(?:\b(?:non[- ]personal\s+data[^.!?\n]{0,160}?(?:governmental\s+access|government\s+access|public\s+authority\s+access|unlawful\s+international\s+(?:governmental\s+)?(?:access|transfer)|art(?:icle)?\.?\s*(?:28|32)))|(?:(?:governmental\s+access|foreign\s+government\s+access|international\s+governmental\s+access|art(?:icle)?\.?\s*28\s*\(\s*1\s*\)\s*\(\s*b\s*\)|art(?:icle)?\.?\s*32)[^.!?\n]{0,160}?non[- ]personal\s+data))/i;

const GDPR_PERSONAL_DATA_ONLY_TRANSFER_RE =
  /\b(?:gdpr|standard\s+contractual\s+clauses\s+\(sccs\)|personal\s+data\s+transfers?|schrems\s+ii|data\s+privacy\s+framework)\b/i;

// Rule 6: Art. 29(4)-(5) Fixed-Term Early Termination & EU DORA Art. 30(2)(h) Financial Exit Gate (F-09)
const NON_CANCELLABLE_FIXED_TERM_RE =
  /\b(?:non[- ]cancellable(?:\s+and\s+non[- ]refundable)?|no\s+early\s+termination(?:\s+or\s+refund)?|annual\s+(?:or\s+multi[- ]year\s+)?(?:subscriptions?|contracts?|commitments?)\s+are\s+non[- ](?:cancellable|refundable)|remaining\s+balance\s+of\s+the\s+(?:annual|fixed|multi[- ]year)\s+term\s+becomes\s+immediately\s+due)\b/gi;

const ENTERPRISE_OR_REGULATED_TARGET_RE =
  /\b(?:soc\s*2(?:\s+type\s+(?:ii|2))?|iso\s*\/?\s*iec\s*27001|iso\s*27001|trust\s+center|financial\s+(?:institutions?|entities|services)|regulated\s+(?:entities|enterprises)|banking|fintech|insurance|enterprise\s+(?:security|plan|sla|grade))\b/gi;

const FINANCIAL_SECTOR_TARGET_RE =
  /\b(?:financial\s+(?:institutions?|entities|services)|banking|fintech|insurance|\bdora\b|2022\/2554)\b/gi;

const ART_29_4_EARLY_TERMINATION_TRANSPARENCY_RE =
  /\b(?:art(?:icle)?\.?\s*29\s*\(\s*(?:4|5)\s*\)|proportionate\s+early\s+termination(?:\s+(?:penalty|fee|charge))?|early\s+termination\s+(?:fee|penalty)\s+(?:calculation|methodology|formula)|no\s+early\s+termination\s+(?:penalty|fee)|€0\s+early\s+termination|cancel\s+at\s+any\s+time\s+without\s+penalty)\b/i;

const DORA_OR_EXIT_STRATEGY_RE =
  /\b(?:dora|regulation\s*\(eu\)\s*2022\/2554|art(?:icle)?\.?\s*30\s*\(\s*2\s*\)\s*\(\s*h\s*\)|art(?:icle)?\.?\s*28\s*\(\s*8\s*\)|documented\s+(?:ict\s+)?exit\s+(?:strategy|plan)|exit\s+strategy\s+and\s+transition|transitional\s+continuity\s+and\s+exit)\b/i;

function extractPhraseContext(text: string, matchIndex: number, matchLength: number): string {
  const start = Math.max(0, matchIndex - 28);
  const end = Math.min(text.length, matchIndex + matchLength + 44);
  let snippet = text.slice(start, end).replace(/\s+/g, ' ').trim();
  if (start > 0) snippet = `...${snippet}`;
  if (end < text.length) snippet = `${snippet}...`;
  return snippet;
}

function isSentenceBreakAt(raw: string, idx: number): boolean {
  const ch = raw[idx];
  if (ch === '!' || ch === '?' || ch === '\n' || ch === ';') return true;
  if (ch === '.') {
    const prevChar = idx > 0 ? raw[idx - 1] : '';
    const nextChar = idx + 1 < raw.length ? raw[idx + 1] : '';
    if (/\d/.test(prevChar) && /\d/.test(nextChar)) {
      return false;
    }
    const beforeDot = raw.slice(Math.max(0, idx - 6), idx);
    if (/\b(?:Art|Arts|Reg|Sec|No|vs|cf|al|e\.g|i\.e)$/i.test(beforeDot)) {
      return false;
    }
    return true;
  }
  return false;
}

function extractSameSentencePrefix(text: string, matchIndex: number): string {
  const windowStart = Math.max(0, matchIndex - 160);
  const rawWindow = text.slice(windowStart, matchIndex);

  for (let i = rawWindow.length - 1; i >= 0; i -= 1) {
    if (isSentenceBreakAt(rawWindow, i)) {
      return rawWindow.slice(i + 1);
    }
  }
  return rawWindow;
}

function extractSameSentenceWindow(
  text: string,
  matchIndex: number,
  matchLength: number,
  radius = 140,
): string {
  const minStart = Math.max(0, matchIndex - radius);
  let start = minStart;
  for (let i = matchIndex - 1; i >= minStart; i -= 1) {
    if (isSentenceBreakAt(text, i)) {
      start = i + 1;
      break;
    }
  }

  const maxEnd = Math.min(text.length, matchIndex + matchLength + radius);
  let end = maxEnd;
  for (let i = matchIndex + matchLength; i < maxEnd; i += 1) {
    if (isSentenceBreakAt(text, i)) {
      end = i;
      break;
    }
  }

  return text.slice(start, end);
}

export function isNegatedByPolicy(text: string, matchIndex: number): boolean {
  const sameSentencePrefix = extractSameSentencePrefix(text, matchIndex);
  return POLICY_NEGATION_PREFIX_RE.test(sameSentencePrefix);
}

export function detectSiteLanguage(pages: ParsedHtmlDocument[]): string {
  for (const p of pages) {
    if (p.htmlLang && /^[a-z]{2,3}$/i.test(p.htmlLang)) {
      return p.htmlLang.toLowerCase();
    }
  }
  return 'en';
}

export interface SaasFootprintAndApplicability {
  sitePlatform: SitePlatform;
  siteCategory: SiteCategory;
  isSaasOrCloudServiceDetected: boolean;
  billingSdkVendors: BillingSdkVendor[];
  authIdentityVendors: AuthIdentityVendor[];
  trustCenterGrcVendors: TrustCenterGrcVendor[];
  docsStatusSupportVendors: DocsStatusSupportVendor[];
  saasApplicabilitySignals: string[];
}

export function fingerprintSaasAndCloudApplicability(
  pages: InspectedPageBundle[],
): SaasFootprintAndApplicability {
  const billingSet = new Set<BillingSdkVendor>();
  const authSet = new Set<AuthIdentityVendor>();
  const trustSet = new Set<TrustCenterGrcVendor>();
  const docsSet = new Set<DocsStatusSupportVendor>();
  const strongSaasSignals = new Set<string>();
  const weakSaasSignals = new Set<string>();

  let hasStrongStripeBilling = false;
  let hasGenericStripeJs = false;

  const combinedMarkupParts: string[] = [];
  const combinedTextParts: string[] = [];
  const combinedAnchorHrefs: string[] = [];

  for (const { doc } of pages) {
    const anchorHrefBlob = doc.anchors.map((a) => `${a.href} ${a.resolvedHref}`).join(' ');
    const pageSurface = [
      doc.scriptUrls.join(' '),
      doc.stylesheetUrls.join(' '),
      doc.scripts
        .map(
          (s) =>
            `${s.src} ${s.resolvedSrc} ${s.dataSrc} ${s.resolvedDataSrc} ${s.className} ${s.dataAttributes} ${s.rawAttrs} ${s.inlineCode}`,
        )
        .join('\n'),
      doc.iframes
        .map(
          (f) =>
            `${f.src} ${f.resolvedSrc} ${f.dataSrc} ${f.resolvedDataSrc} ${f.className} ${f.dataAttributes} ${f.rawAttrs}`,
        )
        .join('\n'),
      anchorHrefBlob,
      doc.domHtml.slice(0, 60_000),
    ].join('\n');

    combinedMarkupParts.push(pageSurface);
    combinedTextParts.push(`${doc.url} ${doc.title ?? ''} ${doc.visibleText}`);
    combinedAnchorHrefs.push(anchorHrefBlob);

    if (STRIPE_STRONG_SAAS_BILLING_RE.test(pageSurface)) {
      hasStrongStripeBilling = true;
      strongSaasSignals.add('billing-sdk:stripe-billing');
    } else if (STRIPE_GENERIC_JS_RE.test(pageSurface)) {
      hasGenericStripeJs = true;
      weakSaasSignals.add('payment-sdk:stripe-js');
    }

    for (const pat of NON_STRIPE_BILLING_SDK_PATTERNS) {
      if (pat.regex.test(pageSurface)) {
        billingSet.add(pat.vendor);
        if (pat.strongSaas) {
          strongSaasSignals.add(`billing-sdk:${pat.vendor}`);
        } else {
          weakSaasSignals.add(`payment-sdk:${pat.vendor}`);
        }
      }
    }

    for (const pat of AUTH_IDENTITY_PATTERNS) {
      if (pat.regex.test(pageSurface)) {
        authSet.add(pat.vendor);
        strongSaasSignals.add(`auth-sdk:${pat.vendor}`);
      }
    }

    for (const pat of TRUST_CENTER_GRC_PATTERNS) {
      if (pat.regex.test(pageSurface)) {
        trustSet.add(pat.vendor);
        if (DEDICATED_SAAS_TRUST_VENDORS.has(pat.vendor)) {
          strongSaasSignals.add(`trust-center-sdk:${pat.vendor}`);
        }
      }
    }

    for (const pat of DOCS_STATUS_SUPPORT_PATTERNS) {
      if (pat.regex.test(pageSurface)) {
        docsSet.add(pat.vendor);
        if (DEDICATED_SAAS_DOCS_STATUS_VENDORS.has(pat.vendor)) {
          strongSaasSignals.add(`docs-status-sdk:${pat.vendor}`);
        }
      }
    }

    if (doc.hasSoftwareAppJsonLd) {
      strongSaasSignals.add('jsonld:SoftwareApplication');
    }

    for (const a of doc.anchors) {
      const target = a.resolvedHref || a.href;
      if (!target || NON_SAAS_AUTH_OR_ECOM_PATH_RE.test(target)) continue;

      if (STRONG_SAAS_CONSOLE_LINK_RE.test(target)) {
        strongSaasSignals.add(`app-console-route:${a.href.slice(0, 64)}`);
        break;
      }

      let pathname = '';
      try {
        pathname = new URL(target, doc.url).pathname;
      } catch {
        pathname = target;
      }
      if (!NON_SAAS_AUTH_OR_ECOM_PATH_RE.test(pathname) && WEAK_ROOT_AUTH_PATH_RE.test(pathname)) {
        weakSaasSignals.add(`auth-route:${pathname.slice(0, 48)}`);
      }
    }

    const pageHeadlineAndText = `${doc.title ?? ''} ${doc.visibleText}`;

    const strongTierMatch = STRONG_SAAS_SEAT_OR_TIER_COPY_RE.exec(pageHeadlineAndText);
    if (strongTierMatch) {
      strongSaasSignals.add(`saas-tier:${strongTierMatch[0].trim().slice(0, 48)}`);
    } else {
      const weakPriceMatch = WEAK_RECURRING_PRICE_COPY_RE.exec(pageHeadlineAndText);
      if (weakPriceMatch) {
        weakSaasSignals.add(`recurring-pricing:${weakPriceMatch[0].trim().slice(0, 48)}`);
      }
    }

    const saasTermMatch = STRONG_SAAS_EXPLICIT_SERVICE_TERMS_RE.exec(pageHeadlineAndText);
    if (saasTermMatch) {
      strongSaasSignals.add(`saas-cloud-term:${saasTermMatch[0].trim().slice(0, 48)}`);
    }
  }

  const allMarkup = combinedMarkupParts.join('\n');
  const allText = combinedTextParts.join('\n');
  const allAnchorHrefs = combinedAnchorHrefs.join(' ');

  let sitePlatform: SitePlatform = 'custom';
  if (docsSet.has('mintlify') || /\b_mintlify\b/i.test(allMarkup)) {
    sitePlatform = 'mintlify';
  } else if (docsSet.has('docusaurus') || /\b__docusaurus\b/i.test(allMarkup)) {
    sitePlatform = 'docusaurus';
  } else if (/\/_next\/static\/|__NEXT_DATA__/i.test(allMarkup)) {
    sitePlatform = 'nextjs';
  } else if (/\bdata-wf-site\b|\bwebflow\.js\b|\bwebsite-files\.com\b/i.test(allMarkup)) {
    sitePlatform = 'webflow';
  } else if (/\bframerusercontent\.com\b|\bdata-framer-appear-id\b/i.test(allMarkup)) {
    sitePlatform = 'framer';
  } else if (/\bcdn\.shopify\.com\b|\bShopify\.shop\b/i.test(allMarkup)) {
    sitePlatform = 'shopify';
  } else if (/\/wp-content\/|\/wp-includes\//i.test(allMarkup)) {
    sitePlatform = 'wordpress';
  }

  const anyProductJsonLd = pages.some((p) => p.doc.hasProductJsonLd);
  const anySoftwareAppJsonLd = pages.some((p) => p.doc.hasSoftwareAppJsonLd);

  const hasRetailEcommerceMarkers =
    sitePlatform === 'shopify' ||
    /\/wp-content\/plugins\/woocommerce\b|\bwoocommerce-Price-amount\b/i.test(allMarkup) ||
    (anyProductJsonLd && !anySoftwareAppJsonLd) ||
    /\b(?:add\s+to\s+cart|shopping\s+cart|shopping\s+bag)\b|\/collections\/[a-z0-9_-]+/i.test(
      `${allText}\n${allAnchorHrefs}`,
    );

  let isSaasOrCloudServiceDetected: boolean;
  if (hasRetailEcommerceMarkers && strongSaasSignals.size === 0) {
    isSaasOrCloudServiceDetected = false;
  } else {
    isSaasOrCloudServiceDetected = strongSaasSignals.size >= 1 || weakSaasSignals.size >= 2;
  }

  if (hasStrongStripeBilling || (hasGenericStripeJs && isSaasOrCloudServiceDetected)) {
    // Keep stripe-billing at front when detected
    const existing = Array.from(billingSet);
    billingSet.clear();
    billingSet.add('stripe-billing');
    for (const v of existing) billingSet.add(v);
  }

  const billingSdkVendors = Array.from(billingSet);
  const authIdentityVendors = Array.from(authSet);
  const trustCenterGrcVendors = Array.from(trustSet);
  const docsStatusSupportVendors = Array.from(docsSet);

  const saasApplicabilitySignals = isSaasOrCloudServiceDetected
    ? Array.from(new Set([...strongSaasSignals, ...weakSaasSignals])).slice(0, 20)
    : [];

  let siteCategory: SiteCategory = 'brochure_or_content';
  if (isSaasOrCloudServiceDetected) {
    if (
      /\b(?:llm|ai\s+agents?|vector\s+database|model\s+inference|fine[- ]tuning|embeddings\s+api)\b/i.test(
        allText,
      )
    ) {
      siteCategory = 'ai_or_data_platform';
    } else if (
      /\b(?:iaas|paas|kubernetes|object\s+storage|cloud\s+infrastructure|compute\s+instances)\b/i.test(
        allText,
      )
    ) {
      siteCategory = 'cloud_or_api_infra';
    } else {
      siteCategory = 'b2b_or_b2c_saas';
    }
  } else if (hasRetailEcommerceMarkers) {
    siteCategory = 'ecommerce_or_marketplace';
  }

  return {
    sitePlatform,
    siteCategory,
    isSaasOrCloudServiceDetected,
    billingSdkVendors,
    authIdentityVendors,
    trustCenterGrcVendors,
    docsStatusSupportVendors,
    saasApplicabilitySignals,
  };
}

function anchorCombinedLabel(a: ParsedAnchor): string {
  return `${a.text} ${a.ariaLabel} ${a.title} ${a.href}`.trim();
}

export function discoverSaasComplianceLinks(
  pages: ParsedHtmlDocument[],
): DiscoveredSaasComplianceLinks {
  let dataActAddendumUrl: string | null = null;
  let portabilityRegisterUrl: string | null = null;
  let trustOrJurisdictionUrl: string | null = null;
  let pricingOrPlansUrl: string | null = null;
  let termsOrMsaUrl: string | null = null;
  let docsOrApiUrl: string | null = null;

  for (const page of pages) {
    for (const a of page.anchors) {
      if (!a.resolvedHref || !/^https?:/i.test(a.resolvedHref)) continue;
      const label = anchorCombinedLabel(a);

      if (
        !dataActAddendumUrl &&
        /\b(?:data[-_ ]?act|cloud[-_ ]?switching|switching[-_ ]?addendum)\b/i.test(label)
      ) {
        dataActAddendumUrl = a.resolvedHref;
      }

      if (
        !portabilityRegisterUrl &&
        /\b(?:portability[-_ ]?register|portability|data[-_ ]?register|interoperability|docs\/export|data[-_ ]?export)\b/i.test(
          label,
        )
      ) {
        portabilityRegisterUrl = a.resolvedHref;
      }

      if (
        !trustOrJurisdictionUrl &&
        /\b(?:trust(?:[-_ ]?center)?|security|subprocessors?|compliance|jurisdiction|governmental[-_ ]?access)\b/i.test(
          label,
        )
      ) {
        trustOrJurisdictionUrl = a.resolvedHref;
      }

      if (!pricingOrPlansUrl && /\b(?:pricing|plans)\b/i.test(label)) {
        pricingOrPlansUrl = a.resolvedHref;
      }

      if (
        !termsOrMsaUrl &&
        /\b(?:terms(?:-of-(?:service|use))?|\btos\b|\bmsa\b|master[-_ ]?services?|legal|\bdpa\b)\b/i.test(
          label,
        )
      ) {
        termsOrMsaUrl = a.resolvedHref;
      }

      if (
        !docsOrApiUrl &&
        /\b(?:\/docs\/export|\/api\b|openapi|api[-_ ]?reference|developer[-_ ]?docs)\b/i.test(label)
      ) {
        docsOrApiUrl = a.resolvedHref;
      }
    }
  }

  return {
    dataActAddendumUrl,
    portabilityRegisterUrl,
    trustOrJurisdictionUrl,
    pricingOrPlansUrl,
    termsOrMsaUrl,
    docsOrApiUrl,
  };
}

function isAllowedFirstPartySubdomain(
  candidateHostRaw: string,
  homeHostRaw: string,
  homeRootDomain: string,
): boolean {
  const candHost = candidateHostRaw
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.+$/, '');
  const homeHost = homeHostRaw
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.+$/, '')
    .replace(/^www\./, '');
  if (!candHost || !homeRootDomain) return false;
  if (extractRegistrableDomain(candHost) !== homeRootDomain) return false;
  if (candHost === homeRootDomain || candHost === homeHost) return true;

  for (const base of [homeRootDomain, homeHost]) {
    if (base && candHost.endsWith(`.${base}`)) {
      const subPrefix = candHost.slice(0, candHost.length - base.length - 1);
      if (/^(?:www|trust|security|docs|developers|legal|compliance)$/i.test(subPrefix)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Selects up to `maxPages` (default 4, range 0..6) same-origin or first-party compliance subdomain
 * (`trust.`, `security.`, `docs.`, `developers.`, `legal.`, `compliance.`) internal subpages matching:
 * `/data-act`, `/cloud-switching`, `/portability`, `/terms`, `/tos`, `/msa`, `/legal`, `/dpa`,
 * `/pricing`, `/plans`, `/trust`, `/security`, `/subprocessors`, `/compliance`, `/docs/export`, `/api`.
 */
export function selectPriorityInternalSubpages(
  homeDoc: ParsedHtmlDocument,
  homeFinalUrl: string,
  maxPages: number,
): string[] {
  if (maxPages <= 0) return [];

  let homeOrigin: string;
  let homeHost: string;
  let homeRootDomain: string;
  let homeNormalized: string;
  try {
    const u = new URL(homeFinalUrl);
    homeOrigin = u.origin;
    homeHost = u.hostname;
    homeRootDomain = extractRegistrableDomain(u.hostname);
    u.hash = '';
    homeNormalized = u.toString();
  } catch {
    return [];
  }

  type SubpageCategory =
    | 'data_act_addendum'
    | 'portability_or_docs'
    | 'pricing_or_plans'
    | 'trust_or_security'
    | 'terms_or_legal';

  const candidates = new Map<string, { score: number; category: SubpageCategory }>();

  for (const a of homeDoc.anchors) {
    if (!a.resolvedHref || !/^https?:/i.test(a.resolvedHref)) continue;

    let parsed: URL;
    try {
      parsed = new URL(a.resolvedHref);
    } catch {
      continue;
    }

    const isSameOrigin = parsed.origin === homeOrigin;
    const isFirstPartySub =
      !isSameOrigin && isAllowedFirstPartySubdomain(parsed.hostname, homeHost, homeRootDomain);

    if (!isSameOrigin && !isFirstPartySub) continue;

    parsed.hash = '';
    const cleanUrl = parsed.toString();
    if (cleanUrl === homeNormalized) continue;

    if (ASSET_EXTENSION_RE.test(parsed.pathname) || /\.pdf(?:[?#]|$)/i.test(parsed.pathname)) {
      continue;
    }

    const label = `${a.text} ${a.ariaLabel} ${a.title} ${parsed.hostname} ${parsed.pathname}`.toLowerCase();
    let score = 0;
    let category: SubpageCategory = 'terms_or_legal';

    if (/\b(?:data[-_\s]*act|cloud[-_\s]*switching|switching[-_\s]*addendum)\b/i.test(label)) {
      score = 112;
      category = 'data_act_addendum';
    } else if (
      /\b(?:portability[-_\s]*register|portability|data[-_\s]*register|docs\/export|data[-_\s]*export|\bapi\b|openapi)\b/i.test(
        label,
      )
    ) {
      const isRegister = /portability|register|export/i.test(label);
      score = isRegister ? 108 : 96;
      category = 'portability_or_docs';
    } else if (/\b(?:pricing|plans)\b/i.test(label)) {
      score = 104;
      category = 'pricing_or_plans';
    } else if (
      /\b(?:trust|security|subprocessors?|compliance|jurisdiction|government[-_\s]*access)\b/i.test(
        label,
      )
    ) {
      score = 100;
      category = 'trust_or_security';
    } else if (/\b(?:terms|\btos\b|\bmsa\b|legal|\bdpa\b)\b/i.test(label)) {
      score = 98;
      category = 'terms_or_legal';
    }

    if (score > 0) {
      if (a.inFooter || a.inNav) score += 3;
      const existing = candidates.get(cleanUrl);
      if (!existing || score > existing.score) {
        candidates.set(cleanUrl, { score, category });
      }
    }
  }

  const seenCategories = new Set<SubpageCategory>();
  const sortedRaw = Array.from(candidates.entries()).sort((a, b) => b[1].score - a[1].score);
  const diversified: Array<{ url: string; finalScore: number }> = [];

  for (const [url, meta] of sortedRaw) {
    const bonus = seenCategories.has(meta.category) ? 0 : 15;
    seenCategories.add(meta.category);
    diversified.push({ url, finalScore: meta.score + bonus });
  }

  return diversified
    .sort((a, b) => b.finalScore - a.finalScore)
    .slice(0, maxPages)
    .map((entry) => entry.url);
}

/**
 * Core Check #1 (`Art. 29(1)` & `Art. 30(2)`):
 * - Explicit egress / switching / offboarding / data-extraction fees (prohibited from 12 Jan 2027)
 * - Gating CSV/JSON/API bulk data export behind Enterprise-only plans (`Art. 30(2)` requires free open interfaces)
 */
export function checkEgressAndExportInterfaces(params: {
  pages: InspectedPageBundle[];
  isSaasOrCloudServiceDetected: boolean;
  enabled: boolean;
}): EgressAndExportInterfaceCheckResult {
  const { pages, enabled } = params;

  if (!enabled) {
    return {
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
    };
  }

  const egressFeeMatches: string[] = [];
  const exportPaywallMatches: string[] = [];
  const evidence: string[] = [];
  const foundOnPages = new Set<string>();

  let zeroEgressGuaranteeFound = false;
  let freeOpenExportAllPlansFound = false;
  let art34ParallelMultiCloudCarveOutFound = false;

  for (const { doc, finalUrl } of pages) {
    const text = doc.visibleText;

    if (ZERO_EGRESS_GUARANTEE_RE.test(text)) {
      zeroEgressGuaranteeFound = true;
    }
    if (FREE_OPEN_EXPORT_ALL_PLANS_RE.test(text)) {
      freeOpenExportAllPlansFound = true;
    }
    if (ART_34_PARALLEL_CARVE_OUT_RE.test(text)) {
      art34ParallelMultiCloudCarveOutFound = true;
    }

    for (const feeRe of [
      EGRESS_FEE_CURRENCY_FIRST_RE,
      EGRESS_FEE_LABEL_FIRST_RE,
      PAID_MIGRATION_EXPORT_RE,
    ]) {
      feeRe.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = feeRe.exec(text)) !== null) {
        if (isNegatedByPolicy(text, m.index)) continue;
        const sameSentence = extractSameSentenceWindow(text, m.index, m[0].length, 140);
        if (
          ART_34_PARALLEL_CARVE_OUT_RE.test(sameSentence) ||
          SAME_SENTENCE_DATA_ACT_CARVE_OUT_RE.test(sameSentence)
        ) {
          continue;
        }
        const snippet = extractPhraseContext(text, m.index, m[0].length);
        if (!egressFeeMatches.includes(snippet) && egressFeeMatches.length < 6) {
          egressFeeMatches.push(snippet);
          foundOnPages.add(finalUrl);
          evidence.push(`Switching / data egress / offboarding fee on ${finalUrl}: "${snippet}"`);
        }
      }
    }

    EXPORT_PAYWALL_RE.lastIndex = 0;
    let pm: RegExpExecArray | null;
    while ((pm = EXPORT_PAYWALL_RE.exec(text)) !== null) {
      if (isNegatedByPolicy(text, pm.index)) continue;
      const sameSentence = extractSameSentenceWindow(text, pm.index, pm[0].length, 140);
      if (SAME_SENTENCE_DATA_ACT_CARVE_OUT_RE.test(sameSentence)) {
        continue;
      }
      const snippet = extractPhraseContext(text, pm.index, pm[0].length);
      if (!exportPaywallMatches.includes(snippet) && exportPaywallMatches.length < 6) {
        exportPaywallMatches.push(snippet);
        foundOnPages.add(finalUrl);
        evidence.push(`Enterprise-only data/API export paywall on ${finalUrl}: "${snippet}"`);
      }
    }
  }

  return {
    checked: true,
    egressOrSwitchingFeeFound: egressFeeMatches.length > 0,
    egressFeeMatches,
    exportPaywallOrTierLockFound: exportPaywallMatches.length > 0,
    exportPaywallMatches,
    zeroEgressGuaranteeFound,
    freeOpenExportAllPlansFound,
    art34ParallelMultiCloudCarveOutFound,
    evidence: Array.from(new Set(evidence)).slice(0, 8),
    foundOnPages: Array.from(foundOnPages),
  };
}

/**
 * Core Check #2 (`Art. 25(1)-(5)` & `Commission Recommendation (EU) 2026/2394`):
 * - Immediate or `< 30-day` post-termination data deletion (violates `Art. 25(2)(g)` `≥ 30 calendar days` retrieval)
 * - `> 2-month` (`65-365 days`) customer initiation notice lock-in (violates `Art. 25(2)(d)`)
 * - Presence of EU Data Act Chapter VI Switching Addendum
 */
export function checkArt25SwitchingContract(params: {
  pages: InspectedPageBundle[];
  discoveredLinks: DiscoveredSaasComplianceLinks;
  isSaasOrCloudServiceDetected: boolean;
  enabled: boolean;
}): Art25SwitchingContractCheckResult {
  const { pages, discoveredLinks, isSaasOrCloudServiceDetected, enabled } = params;

  if (!enabled) {
    return {
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
    };
  }

  const shortRetentionMatches: string[] = [];
  const excessiveNoticeMatches: string[] = [];
  const evidence: string[] = [];
  const foundOnPages = new Set<string>();

  let dataActFrameworkFound = Boolean(discoveredLinks.dataActAddendumUrl);
  let commissionRec20262394Referenced = false;
  let art25NoticeOverrideFound = false;
  let maxTwoMonthNoticeFound = false;
  let thirtyDayTransitionFound = false;
  let thirtyDayRetrievalAndErasureFound = false;

  for (const { doc, finalUrl } of pages) {
    const text = doc.visibleText;

    if (
      DATA_ACT_FRAMEWORK_SIGNAL_RE.test(text) ||
      /\bdata[-_]act|cloud[-_]switching\b/i.test(finalUrl)
    ) {
      dataActFrameworkFound = true;
    }
    if (RECOMMENDATION_2026_2394_RE.test(text)) {
      commissionRec20262394Referenced = true;
    }
    if (ART_25_NOTICE_OVERRIDE_RE.test(text)) {
      art25NoticeOverrideFound = true;
      maxTwoMonthNoticeFound = true;
    }
    if (MAX_TWO_MONTH_NOTICE_SIGNAL_RE.test(text)) {
      maxTwoMonthNoticeFound = true;
    }
    if (THIRTY_DAY_TRANSITION_SIGNAL_RE.test(text)) {
      thirtyDayTransitionFound = true;
    }
    if (THIRTY_DAY_RETRIEVAL_SIGNAL_RE.test(text)) {
      thirtyDayRetrievalAndErasureFound = true;
    }

    // 1. Immediate or <30-day post-termination deletion (F-05: pre/post ±140 same-sentence guard + clause-initial pattern)
    for (const delRe of [
      IMMEDIATE_POST_TERMINATION_DELETION_RE,
      SUB_30_DAY_POST_TERMINATION_DELETION_RE,
      CLAUSE_INITIAL_SUB_30_DAY_DELETION_RE,
    ]) {
      delRe.lastIndex = 0;
      let dm: RegExpExecArray | null;
      while ((dm = delRe.exec(text)) !== null) {
        if (isNegatedByPolicy(text, dm.index)) continue;
        const sentenceWindow = extractSameSentenceWindow(text, dm.index, dm[0].length, 140);
        if (DELETION_EXEMPT_CONTEXT_RE.test(sentenceWindow)) {
          continue;
        }
        const snippet = extractPhraseContext(text, dm.index, dm[0].length);
        if (!shortRetentionMatches.includes(snippet) && shortRetentionMatches.length < 6) {
          shortRetentionMatches.push(snippet);
          foundOnPages.add(finalUrl);
          evidence.push(
            `Post-termination data deletion shorter than mandatory 30-day Art. 25(2)(g) retrieval period on ${finalUrl}: "${snippet}"`,
          );
        }
      }
    }

    // 2. >2-month (65-365 days / 3-12 months) customer initiation notice lock-in (F-03)
    EXCESSIVE_NOTICE_PERIOD_RE.lastIndex = 0;
    let nm: RegExpExecArray | null;
    while ((nm = EXCESSIVE_NOTICE_PERIOD_RE.exec(text)) !== null) {
      if (isNegatedByPolicy(text, nm.index)) continue;
      const sentenceWindow = extractSameSentenceWindow(text, nm.index, nm[0].length, 180);

      if (!NOTICE_SWITCHING_OR_TERMINATION_CONTEXT_RE.test(sentenceWindow)) {
        continue;
      }
      if (PROVIDER_GIVES_NOTICE_SUBJECT_RE.test(sentenceWindow)) {
        continue;
      }
      if (NON_SWITCHING_NOTICE_TOPIC_RE.test(sentenceWindow)) {
        continue;
      }

      const snippet = extractPhraseContext(text, nm.index, nm[0].length);
      if (!excessiveNoticeMatches.includes(snippet) && excessiveNoticeMatches.length < 6) {
        excessiveNoticeMatches.push(snippet);
        foundOnPages.add(finalUrl);
      }
    }
  }

  const excessiveNoticePeriodLockInFound =
    excessiveNoticeMatches.length > 0 && !art25NoticeOverrideFound;

  if (excessiveNoticePeriodLockInFound) {
    evidence.push(
      `Notice period exceeding EU Data Act Art. 25(2)(d) 2-month cap without override: "${excessiveNoticeMatches[0]}"`,
    );
  }

  const switchingAddendumFound =
    dataActFrameworkFound && (thirtyDayTransitionFound || thirtyDayRetrievalAndErasureFound);

  if (isSaasOrCloudServiceDetected && !switchingAddendumFound) {
    const homeUrl = pages[0]?.finalUrl || '';
    if (homeUrl) foundOnPages.add(homeUrl);
    evidence.push(
      'Active SaaS/cloud platform lacks a published EU Data Act Chapter VI Switching Addendum (Art. 25 ≤2-month notice, ≤30-day transition, ≥30-day retrieval & erasure).',
    );
  }

  return {
    checked: true,
    switchingAddendumFound,
    commissionRec20262394Referenced,
    shortPostTerminationRetentionFound: shortRetentionMatches.length > 0,
    shortRetentionMatches,
    excessiveNoticePeriodLockInFound,
    excessiveNoticeMatches: excessiveNoticePeriodLockInFound ? excessiveNoticeMatches : [],
    art25NoticeOverrideFound,
    maxTwoMonthNoticeFound,
    thirtyDayTransitionFound,
    thirtyDayRetrievalAndErasureFound,
    evidence: Array.from(new Set(evidence)).slice(0, 8),
    foundOnPages: Array.from(foundOnPages),
  };
}

/**
 * Core Check #3 (`Art. 26(b)` Online Portability Register & `Art. 28(1)` / `Art. 32` Website Transparency):
 * - Strictly distinguishes `Art. 26(b)` (provider-hosted online register of data structures, formats & open interoperability specs)
 *   from `Art. 28(1)(a)-(b)` & `Art. 32` (ICT hosting jurisdiction + safeguards against unlawful international governmental access to non-personal data).
 */
export function checkArt26bAndArt28Transparency(params: {
  pages: InspectedPageBundle[];
  isSaasOrCloudServiceDetected: boolean;
  enabled: boolean;
}): Art26bAndArt28TransparencyCheckResult {
  const { pages, isSaasOrCloudServiceDetected, enabled } = params;

  if (!enabled) {
    return {
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
    };
  }

  const formatSet = new Set<string>();
  const jurisdictionSignals: string[] = [];
  const govAccessSafeguardSignals: string[] = [];
  const evidence: string[] = [];
  const foundOnPages = new Set<string>();

  let registerMentioned = false;
  let exemptedTradeSecretCategoriesSpecified = false;
  let gdprPersonalNoticeSeen = false;

  for (const { doc, finalUrl } of pages) {
    const text = doc.visibleText;

    if (
      ART_26B_REGISTER_SIGNAL_RE.test(text) ||
      /\b(?:portability-register|data-register)\b/i.test(finalUrl)
    ) {
      registerMentioned = true;
    }

    EXPORT_SCHEMA_FORMATS_RE.lastIndex = 0;
    let fm: RegExpExecArray | null;
    while ((fm = EXPORT_SCHEMA_FORMATS_RE.exec(text)) !== null) {
      formatSet.add(fm[0].toUpperCase().replace(/\s+/g, ' '));
    }

    if (TRADE_SECRET_EXEMPTION_SPEC_RE.test(text)) {
      exemptedTradeSecretCategoriesSpecified = true;
    }

    ART_28_ICT_JURISDICTION_RE.lastIndex = 0;
    let jurMatch: RegExpExecArray | null;
    while ((jurMatch = ART_28_ICT_JURISDICTION_RE.exec(text)) !== null) {
      if (isNegatedByPolicy(text, jurMatch.index)) continue;
      const snippet = extractPhraseContext(text, jurMatch.index, jurMatch[0].length);
      if (!jurisdictionSignals.includes(snippet) && jurisdictionSignals.length < 4) {
        jurisdictionSignals.push(snippet);
      }
    }

    const govMatch = ART_28_32_NON_PERSONAL_GOV_ACCESS_RE.exec(text);
    if (govMatch && !isNegatedByPolicy(text, govMatch.index)) {
      const snippet = extractPhraseContext(text, govMatch.index, govMatch[0].length);
      if (govAccessSafeguardSignals.length < 4) {
        govAccessSafeguardSignals.push(snippet);
      }
    }

    if (GDPR_PERSONAL_DATA_ONLY_TRANSFER_RE.test(text)) {
      gdprPersonalNoticeSeen = true;
    }
  }

  const exportFormatsDisclosed = Array.from(formatSet);
  const art26bOnlinePortabilityRegisterFound =
    registerMentioned && exportFormatsDisclosed.length > 0;
  const art28IctJurisdictionDisclosed = jurisdictionSignals.length > 0;
  const art28NonPersonalGovAccessSafeguardsDisclosed = govAccessSafeguardSignals.length > 0;

  const gdprPersonalDataOnlyNoticeWithoutArt28 =
    gdprPersonalNoticeSeen && !art28NonPersonalGovAccessSafeguardsDisclosed;

  if (isSaasOrCloudServiceDetected) {
    const homeUrl = pages[0]?.finalUrl || '';
    if (!art26bOnlinePortabilityRegisterFound) {
      if (homeUrl) foundOnPages.add(homeUrl);
      evidence.push(
        'Missing EU Data Act Art. 26(b) provider-hosted online register detailing exportable data structures, machine-readable formats (JSON/CSV/Parquet/OpenAPI), and interoperability standards.',
      );
    }
    if (!art28IctJurisdictionDisclosed || !art28NonPersonalGovAccessSafeguardsDisclosed) {
      if (homeUrl) foundOnPages.add(homeUrl);
      const missingArt28: string[] = [];
      if (!art28IctJurisdictionDisclosed) {
        missingArt28.push('Art. 28(1)(a) ICT infrastructure processing jurisdiction');
      }
      if (!art28NonPersonalGovAccessSafeguardsDisclosed) {
        missingArt28.push(
          'Art. 28(1)(b) & Art. 32 technical/organisational/contractual measures preventing unlawful international governmental access to non-personal EU data',
        );
      }
      evidence.push(`Website lacks mandatory ${missingArt28.join(' and ')}.`);
    }
  }

  return {
    checked: true,
    art26bOnlinePortabilityRegisterFound,
    exportFormatsDisclosed,
    exemptedTradeSecretCategoriesSpecified,
    art28IctJurisdictionDisclosed,
    jurisdictionSignals,
    art28NonPersonalGovAccessSafeguardsDisclosed,
    govAccessSafeguardSignals,
    gdprPersonalDataOnlyNoticeWithoutArt28,
    evidence: Array.from(new Set(evidence)).slice(0, 8),
    foundOnPages: Array.from(foundOnPages),
  };
}

/**
 * Core Check #4 (`Art. 29(4)-(5)` Early Termination Transparency & `EU DORA Reg. 2022/2554 Art. 30(2)(h)` Exit Support):
 * - Triggers when fixed-term non-cancellable contracts lack `Art. 29(4)-(5)` early-termination fee methodology, OR
 * - When explicit financial-sector signals (`financial institutions|financial entities|financial services|banking|fintech|insurance|DORA`)
 *   are present without documented EU DORA `Art. 30(2)(h)` exit-strategy terms (F-09).
 */
export function checkArt29TerminationAndDoraExit(params: {
  pages: InspectedPageBundle[];
  isSaasOrCloudServiceDetected: boolean;
  trustCenterGrcVendors: TrustCenterGrcVendor[];
  enabled: boolean;
}): Art29TerminationAndDoraExitCheckResult {
  const { pages, isSaasOrCloudServiceDetected, trustCenterGrcVendors, enabled } = params;

  if (!enabled || !isSaasOrCloudServiceDetected) {
    return {
      checked: enabled,
      nonCancellableFixedTermFound: false,
      fixedTermMatches: [],
      enterpriseOrRegulatedTargetSignalsFound: false,
      enterpriseTargetSignals: [],
      art29EarlyTerminationMethodologyFound: false,
      doraOrDocumentedExitStrategyFound: false,
      art29EarlyTerminationAndDoraExitGapFound: false,
      evidence: [],
      foundOnPages: [],
    };
  }

  const fixedTermMatches: string[] = [];
  const enterpriseTargetSignals = new Set<string>();
  const financialSectorSignals = new Set<string>();
  const evidence: string[] = [];
  const foundOnPages = new Set<string>();

  for (const v of trustCenterGrcVendors) {
    if (DEDICATED_SAAS_TRUST_VENDORS.has(v)) {
      enterpriseTargetSignals.add(`trust-center:${v}`);
    }
  }

  let art29EarlyTerminationMethodologyFound = false;
  let doraOrDocumentedExitStrategyFound = false;

  for (const { doc, finalUrl } of pages) {
    const text = doc.visibleText;

    if (ART_29_4_EARLY_TERMINATION_TRANSPARENCY_RE.test(text)) {
      art29EarlyTerminationMethodologyFound = true;
    }
    if (DORA_OR_EXIT_STRATEGY_RE.test(text)) {
      doraOrDocumentedExitStrategyFound = true;
    }

    NON_CANCELLABLE_FIXED_TERM_RE.lastIndex = 0;
    let ftMatch: RegExpExecArray | null;
    while ((ftMatch = NON_CANCELLABLE_FIXED_TERM_RE.exec(text)) !== null) {
      if (isNegatedByPolicy(text, ftMatch.index)) continue;
      const snippet = extractPhraseContext(text, ftMatch.index, ftMatch[0].length);
      if (!fixedTermMatches.includes(snippet) && fixedTermMatches.length < 5) {
        fixedTermMatches.push(snippet);
        foundOnPages.add(finalUrl);
      }
    }

    ENTERPRISE_OR_REGULATED_TARGET_RE.lastIndex = 0;
    let entMatch: RegExpExecArray | null;
    while ((entMatch = ENTERPRISE_OR_REGULATED_TARGET_RE.exec(text)) !== null) {
      if (enterpriseTargetSignals.size < 10) {
        enterpriseTargetSignals.add(entMatch[0].trim().slice(0, 40));
      }
    }

    FINANCIAL_SECTOR_TARGET_RE.lastIndex = 0;
    let finMatch: RegExpExecArray | null;
    while ((finMatch = FINANCIAL_SECTOR_TARGET_RE.exec(text)) !== null) {
      if (financialSectorSignals.size < 8) {
        financialSectorSignals.add(finMatch[0].trim().slice(0, 40));
      }
    }
  }

  const nonCancellableFixedTermFound = fixedTermMatches.length > 0;
  const enterpriseOrRegulatedTargetSignalsFound = enterpriseTargetSignals.size > 0;
  const financialSectorSignalsFound = financialSectorSignals.size > 0;

  const fixedTermGap = nonCancellableFixedTermFound && !art29EarlyTerminationMethodologyFound;
  const financialDoraGap = financialSectorSignalsFound && !doraOrDocumentedExitStrategyFound;

  const art29EarlyTerminationAndDoraExitGapFound = fixedTermGap || financialDoraGap;

  if (art29EarlyTerminationAndDoraExitGapFound) {
    const homeUrl = pages[0]?.finalUrl || '';
    if (foundOnPages.size === 0 && homeUrl) {
      foundOnPages.add(homeUrl);
    }
    if (fixedTermGap) {
      evidence.push(
        `Fixed-term non-cancellable commitment ("${fixedTermMatches[0]}") lacks transparent EU Data Act Art. 29(4)–(5) proportionate early-termination fee methodology.`,
      );
    }
    if (financialDoraGap) {
      evidence.push(
        `Financial-sector SaaS signals ([${Array.from(financialSectorSignals).slice(0, 4).join(', ')}]) lack published EU DORA (Reg. 2022/2554 Art. 28(8) & Art. 30(2)(h)) documented exit-strategy terms.`,
      );
    }
  }

  return {
    checked: true,
    nonCancellableFixedTermFound,
    fixedTermMatches,
    enterpriseOrRegulatedTargetSignalsFound,
    enterpriseTargetSignals: Array.from(enterpriseTargetSignals),
    art29EarlyTerminationMethodologyFound,
    doraOrDocumentedExitStrategyFound,
    art29EarlyTerminationAndDoraExitGapFound,
    evidence: Array.from(new Set(evidence)).slice(0, 8),
    foundOnPages: Array.from(foundOnPages),
  };
}
