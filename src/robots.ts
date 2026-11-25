import { fetchSafeHttp } from './httpClient.js';
import type { DnsLookupFn } from './ssrf.js';

export interface RobotsRule {
  allow: boolean;
  pattern: string;
  segments: string[];
  hasEndAnchor: boolean;
  specificity: number;
}

interface ParsedRobotsPolicy {
  fetchedAt: number;
  rules: RobotsRule[];
  crawlDelayMs: number;
}

export interface RobotsCheckResult {
  allowed: boolean;
  crawlDelayMs: number;
  matchedRule?: string;
}

const BOT_USER_AGENT_TOKENS = ['eu-data-act-saas-switching-auditor', 'apify', '*'];
const ROBOTS_CACHE_TTL_MS = 15 * 60 * 1000;
const MAX_ROBOTS_BYTES = 128 * 1024;
const MAX_CRAWL_DELAY_MS = 10_000;
const MAX_ROBOTS_PATTERN_LEN = 256;
const MAX_ROBOTS_RULES_PER_GROUP = 200;

function compileRobotsPattern(rawPattern: string): {
  normalized: string;
  segments: string[];
  hasEndAnchor: boolean;
} {
  const bounded = rawPattern.slice(0, MAX_ROBOTS_PATTERN_LEN).replace(/\*+/g, '*');
  const hasEndAnchor = bounded.endsWith('$');
  const body = hasEndAnchor ? bounded.slice(0, -1) : bounded;
  return {
    normalized: bounded,
    segments: body.split('*'),
    hasEndAnchor,
  };
}

function matchesRobotsRule(pathAndQuery: string, rule: RobotsRule): boolean {
  const { segments, hasEndAnchor } = rule;
  if (segments.length === 1) {
    const literal = segments[0];
    return hasEndAnchor ? pathAndQuery === literal : pathAndQuery.startsWith(literal);
  }

  if (segments[0].length > 0) {
    if (!pathAndQuery.startsWith(segments[0])) {
      return false;
    }
  }

  let searchPos = segments[0].length;
  const lastIdx = segments.length - 1;

  for (let i = 1; i < lastIdx; i++) {
    const seg = segments[i];
    if (!seg) continue;
    const found = pathAndQuery.indexOf(seg, searchPos);
    if (found < 0) return false;
    searchPos = found + seg.length;
  }

  const tail = segments[lastIdx];
  if (hasEndAnchor) {
    if (!tail) {
      return true;
    }
    return pathAndQuery.endsWith(tail) && pathAndQuery.length - tail.length >= searchPos;
  }

  if (!tail) return true;
  return pathAndQuery.indexOf(tail, searchPos) >= 0;
}

export function parseRobotsTxt(content: string): { rules: RobotsRule[]; crawlDelayMs: number } {
  const lines = content.split(/\r?\n/);

  interface AgentGroup {
    agents: string[];
    rules: RobotsRule[];
    crawlDelayMs: number;
  }

  const groups: AgentGroup[] = [];
  let currentGroup: AgentGroup | null = null;
  let lastLineWasUserAgent = false;

  for (const rawLine of lines) {
    const commentIdx = rawLine.indexOf('#');
    const cleanLine = (commentIdx >= 0 ? rawLine.slice(0, commentIdx) : rawLine).trim();
    if (!cleanLine) {
      lastLineWasUserAgent = false;
      continue;
    }

    const colonIdx = cleanLine.indexOf(':');
    if (colonIdx < 0) continue;

    const directive = cleanLine.slice(0, colonIdx).trim().toLowerCase();
    const value = cleanLine.slice(colonIdx + 1).trim();

    if (directive === 'user-agent') {
      const ua = value.toLowerCase();
      if (!currentGroup || !lastLineWasUserAgent) {
        currentGroup = { agents: [ua], rules: [], crawlDelayMs: 0 };
        groups.push(currentGroup);
      } else {
        currentGroup.agents.push(ua);
      }
      lastLineWasUserAgent = true;
      continue;
    }

    lastLineWasUserAgent = false;
    if (!currentGroup) continue;

    if (directive === 'allow' || directive === 'disallow') {
      if (!value || currentGroup.rules.length >= MAX_ROBOTS_RULES_PER_GROUP) {
        continue;
      }
      const prefixed = value.startsWith('/') || value.startsWith('*') ? value : `/${value}`;
      const compiled = compileRobotsPattern(prefixed);
      currentGroup.rules.push({
        allow: directive === 'allow',
        pattern: compiled.normalized,
        segments: compiled.segments,
        hasEndAnchor: compiled.hasEndAnchor,
        specificity: compiled.normalized.replace(/[*$]/g, '').length,
      });
    } else if (directive === 'crawl-delay') {
      const secs = Number(value);
      if (!Number.isNaN(secs) && secs > 0) {
        currentGroup.crawlDelayMs = Math.min(Math.round(secs * 1000), MAX_CRAWL_DELAY_MS);
      }
    }
  }

  for (const token of BOT_USER_AGENT_TOKENS) {
    const matchingGroups = groups.filter((g) =>
      g.agents.some((ua) => (token === '*' ? ua === '*' : ua.includes(token))),
    );
    if (matchingGroups.length > 0) {
      const mergedRules: RobotsRule[] = [];
      let crawlDelayMs = 0;
      for (const grp of matchingGroups) {
        mergedRules.push(...grp.rules);
        if (grp.crawlDelayMs > crawlDelayMs) {
          crawlDelayMs = grp.crawlDelayMs;
        }
      }
      return { rules: mergedRules, crawlDelayMs };
    }
  }

  return { rules: [], crawlDelayMs: 0 };
}

export function evaluateRobotsRules(
  pathAndQuery: string,
  rules: RobotsRule[],
): { allowed: boolean; matchedRule?: string } {
  let bestMatch: RobotsRule | null = null;

  for (const rule of rules) {
    if (matchesRobotsRule(pathAndQuery, rule)) {
      if (
        !bestMatch ||
        rule.specificity > bestMatch.specificity ||
        (rule.specificity === bestMatch.specificity && rule.allow)
      ) {
        bestMatch = rule;
      }
    }
  }

  if (!bestMatch) {
    return { allowed: true };
  }
  return {
    allowed: bestMatch.allow,
    matchedRule: `${bestMatch.allow ? 'Allow' : 'Disallow'}: ${bestMatch.pattern}`,
  };
}

const MAX_GUARD_MAP_ENTRIES = 2_000;

export class RobotsAndRateGuard {
  private readonly cache = new Map<string, ParsedRobotsPolicy>();
  private readonly domainNextSlotMs = new Map<string, number>();

  private enforceCacheLimit(now: number): void {
    if (this.cache.size < MAX_GUARD_MAP_ENTRIES) return;
    for (const [k, v] of this.cache) {
      if (now - v.fetchedAt > ROBOTS_CACHE_TTL_MS) {
        this.cache.delete(k);
      }
    }
    while (this.cache.size >= MAX_GUARD_MAP_ENTRIES) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey === undefined) break;
      this.cache.delete(oldestKey);
    }
  }

  private enforceSlotMapLimit(now: number): void {
    if (this.domainNextSlotMs.size < MAX_GUARD_MAP_ENTRIES) return;
    for (const [k, slotMs] of this.domainNextSlotMs) {
      if (slotMs <= now) {
        this.domainNextSlotMs.delete(k);
      }
    }
    while (this.domainNextSlotMs.size >= MAX_GUARD_MAP_ENTRIES) {
      const oldestKey = this.domainNextSlotMs.keys().next().value;
      if (oldestKey === undefined) break;
      this.domainNextSlotMs.delete(oldestKey);
    }
  }

  public async checkUrlAllowed(
    targetUrl: string,
    options?: { allowLocalhost?: boolean; dnsLookup?: DnsLookupFn },
  ): Promise<RobotsCheckResult> {
    const parsed = new URL(targetUrl);
    const origin = parsed.origin;
    const now = Date.now();

    let policy = this.cache.get(origin);
    if (!policy || now - policy.fetchedAt > ROBOTS_CACHE_TTL_MS) {
      policy = await this.fetchOriginRobots(origin, options);
      this.enforceCacheLimit(now);
      this.cache.set(origin, policy);
    }

    const pathAndQuery = `${parsed.pathname || '/'}${parsed.search || ''}`;
    const evalResult = evaluateRobotsRules(pathAndQuery, policy.rules);

    return {
      allowed: evalResult.allowed,
      crawlDelayMs: policy.crawlDelayMs,
      matchedRule: evalResult.matchedRule,
    };
  }

  public async waitForDomainSlot(hostname: string, minDelayMs: number): Promise<void> {
    if (minDelayMs <= 0) return;
    const key = hostname.toLowerCase();
    const now = Date.now();
    const scheduled = this.domainNextSlotMs.get(key) ?? now;
    const waitMs = Math.max(0, scheduled - now);
    this.enforceSlotMapLimit(now);
    this.domainNextSlotMs.set(key, Math.max(now, scheduled) + minDelayMs);

    if (waitMs > 0) {
      await new Promise<void>((resolve) => setTimeout(resolve, waitMs));
    }
  }

  private async fetchOriginRobots(
    origin: string,
    options?: { allowLocalhost?: boolean; dnsLookup?: DnsLookupFn },
  ): Promise<ParsedRobotsPolicy> {
    const robotsUrl = `${origin}/robots.txt`;
    const res = await fetchSafeHttp(robotsUrl, {
      maxBytes: MAX_ROBOTS_BYTES,
      timeoutMs: 5_000,
      maxRedirects: 3,
      acceptHeader: 'text/plain,*/*;q=0.8',
      allowLocalhost: options?.allowLocalhost,
      dnsLookup: options?.dnsLookup,
    });

    if (!res.ok || res.statusCode !== 200 || !res.bodyText) {
      return { fetchedAt: Date.now(), rules: [], crawlDelayMs: 0 };
    }

    const parsed = parseRobotsTxt(res.bodyText);
    return {
      fetchedAt: Date.now(),
      rules: parsed.rules,
      crawlDelayMs: parsed.crawlDelayMs,
    };
  }
}
