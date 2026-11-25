import type {
  ParsedAnchor,
  ParsedCheckbox,
  ParsedControl,
  ParsedForm,
  ParsedHtmlDocument,
  ParsedIframeTag,
  ParsedScriptTag,
} from './types.js';

const NAMED_HTML_ENTITIES: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' ',
  euro: '€',
  pound: '£',
  copy: '©',
  reg: '®',
  sect: '§',
  ndash: '–',
  mdash: '—',
  laquo: '«',
  raquo: '»',
  le: '≤',
  ge: '≥',
  middot: '·',
};

export function decodeHtmlEntities(input: string): string {
  if (!input || !input.includes('&')) return input;
  return input.replace(/&(?:#x[0-9a-fA-F]{1,6}|#\d{1,7}|[a-zA-Z0-9]{2,31});/g, (full: string) => {
    const entity = full.slice(1, -1);
    if (entity.startsWith('#x') || entity.startsWith('#X')) {
      const code = parseInt(entity.slice(2), 16);
      if (!Number.isNaN(code) && code > 0 && code <= 0x10ffff) {
        try {
          return String.fromCodePoint(code);
        } catch {
          return full;
        }
      }
      return full;
    }
    if (entity.startsWith('#')) {
      const code = parseInt(entity.slice(1), 10);
      if (!Number.isNaN(code) && code > 0 && code <= 0x10ffff) {
        try {
          return String.fromCodePoint(code);
        } catch {
          return full;
        }
      }
      return full;
    }
    return NAMED_HTML_ENTITIES[entity] ?? full;
  });
}

function getAttr(attrString: string, attrName: string): string {
  if (!attrString) return '';
  const escaped = attrName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const regex = new RegExp(
    `(?:^|\\s)${escaped}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'=<>` + '`' + `]+))`,
    'i',
  );
  const match = regex.exec(attrString);
  if (!match) return '';
  const raw = match[1] ?? match[2] ?? match[3] ?? '';
  return decodeHtmlEntities(raw).trim();
}

function hasBooleanAttr(attrString: string, attrName: string): boolean {
  if (!attrString) return false;
  const escaped = attrName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(
    `(?:^|\\s)${escaped}(?:\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'=<>` + '`' + `]+)))?(?=\\s|$|\\/)`,
    'i',
  );
  const match = re.exec(attrString);
  if (!match) return false;
  const explicitVal = (match[1] ?? match[2] ?? match[3] ?? '').trim().toLowerCase();
  if (explicitVal === 'false' || explicitVal === '0' || explicitVal === 'no') {
    return false;
  }
  return true;
}

function extractDataAttributesSummary(attrString: string): string {
  if (!attrString) return '';
  const matches: string[] = [];
  const re = /\b(data-[a-zA-Z0-9_-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(attrString)) !== null) {
    const key = m[1].toLowerCase();
    const val = decodeHtmlEntities(m[2] ?? m[3] ?? m[4] ?? '').slice(0, 120);
    matches.push(val ? `${key}="${val}"` : key);
    if (matches.length >= 16) break;
  }
  return matches.join(' ');
}

function isTagBoundaryChar(ch: string | undefined): boolean {
  return (
    ch === undefined ||
    ch === '>' ||
    ch === '/' ||
    ch === ' ' ||
    ch === '\t' ||
    ch === '\n' ||
    ch === '\r'
  );
}

function stripCommentsLinear(html: string): string {
  if (!html || !html.includes('<!--')) return html;
  const parts: string[] = [];
  let cursor = 0;
  while (cursor < html.length) {
    const openIdx = html.indexOf('<!--', cursor);
    if (openIdx === -1) {
      parts.push(html.slice(cursor));
      break;
    }
    parts.push(html.slice(cursor, openIdx), ' ');
    const closeIdx = html.indexOf('-->', openIdx + 4);
    if (closeIdx === -1) {
      break;
    }
    cursor = closeIdx + 3;
  }
  return parts.join('');
}

function stripPairedTagLinear(html: string, tagName: string): string {
  if (!html) return html;
  const lower = html.toLowerCase();
  const openToken = `<${tagName}`;
  const closeToken = `</${tagName}`;
  if (!lower.includes(openToken)) return html;

  const parts: string[] = [];
  let cursor = 0;
  let searchFrom = 0;

  while (searchFrom < html.length) {
    const openIdx = lower.indexOf(openToken, searchFrom);
    if (openIdx === -1) {
      parts.push(html.slice(cursor));
      break;
    }
    if (!isTagBoundaryChar(lower[openIdx + openToken.length])) {
      searchFrom = openIdx + openToken.length;
      continue;
    }
    const openEnd = html.indexOf('>', openIdx + openToken.length);
    if (openEnd === -1) {
      parts.push(html.slice(cursor, openIdx));
      break;
    }

    let closeSearch = openEnd + 1;
    let closeIdx = -1;
    while (closeSearch < html.length) {
      const cand = lower.indexOf(closeToken, closeSearch);
      if (cand === -1) break;
      if (isTagBoundaryChar(lower[cand + closeToken.length])) {
        closeIdx = cand;
        break;
      }
      closeSearch = cand + closeToken.length;
    }

    if (closeIdx === -1) {
      parts.push(html.slice(cursor, openIdx));
      break;
    }

    const closeEnd = html.indexOf('>', closeIdx + closeToken.length);
    if (closeEnd === -1) {
      parts.push(html.slice(cursor, openIdx));
      break;
    }

    parts.push(html.slice(cursor, openIdx), ' ');
    cursor = closeEnd + 1;
    searchFrom = cursor;
  }

  return parts.join('');
}

interface PairedElementMatch {
  index: number;
  endIndex: number;
  attrs: string;
  inner: string;
}

function scanPairedElementsLinear(
  html: string,
  tagName: string,
  maxItems: number,
): PairedElementMatch[] {
  const results: PairedElementMatch[] = [];
  if (!html || maxItems <= 0) return results;

  const lower = html.toLowerCase();
  const openToken = `<${tagName}`;
  const closeToken = `</${tagName}`;
  if (!lower.includes(openToken)) return results;

  let searchFrom = 0;
  while (results.length < maxItems && searchFrom < html.length) {
    const openIdx = lower.indexOf(openToken, searchFrom);
    if (openIdx === -1) break;
    if (!isTagBoundaryChar(lower[openIdx + openToken.length])) {
      searchFrom = openIdx + openToken.length;
      continue;
    }

    const openEnd = html.indexOf('>', openIdx + openToken.length);
    if (openEnd === -1) break;

    const attrStart = openIdx + openToken.length;
    const rawAttrs = html.slice(attrStart, Math.min(openEnd, attrStart + 8_192));
    const tailBeforeClose = html.slice(Math.max(attrStart, openEnd - 16), openEnd);
    if (tailBeforeClose.trimEnd().endsWith('/')) {
      results.push({
        index: openIdx,
        endIndex: openEnd + 1,
        attrs: rawAttrs.replace(/\/\s*$/, ''),
        inner: '',
      });
      searchFrom = openEnd + 1;
      continue;
    }

    let closeSearch = openEnd + 1;
    let closeIdx = -1;
    while (closeSearch < html.length) {
      const cand = lower.indexOf(closeToken, closeSearch);
      if (cand === -1) break;
      if (isTagBoundaryChar(lower[cand + closeToken.length])) {
        closeIdx = cand;
        break;
      }
      closeSearch = cand + closeToken.length;
    }

    // Crucial O(N) guarantee: if no closing tag exists anywhere after openEnd, no later opening tag can close either
    if (closeIdx === -1) break;

    const closeEnd = html.indexOf('>', closeIdx + closeToken.length);
    if (closeEnd === -1) break;

    results.push({
      index: openIdx,
      endIndex: closeEnd + 1,
      attrs: rawAttrs,
      inner: html.slice(openEnd + 1, closeIdx),
    });
    searchFrom = closeEnd + 1;
  }

  return results;
}

function stripTagsPreserveAlt(htmlFragment: string): string {
  if (!htmlFragment) return '';
  const withImgAlt = htmlFragment.replace(/<img\b([^<>]{0,2048})>/gi, (_m, attrs: string) => {
    const alt = getAttr(attrs, 'alt');
    return alt ? ` ${alt} ` : ' ';
  });
  const withoutTags = withImgAlt.replace(/<[^<>]{1,4096}>/g, ' ');
  return decodeHtmlEntities(withoutTags).replace(/\s+/g, ' ').trim();
}

function safeResolveUrl(rawHref: string, baseUrl: string): string {
  const trimmed = rawHref.trim();
  if (!trimmed) return '';
  if (/^(?:javascript|mailto|tel|data|about):/i.test(trimmed)) {
    return trimmed;
  }
  try {
    return new URL(trimmed, baseUrl).toString();
  } catch {
    return trimmed;
  }
}

function findRegionRanges(html: string, tagName: string): Array<[number, number]> {
  return scanPairedElementsLinear(html, tagName, 25).map((m) => [m.index, m.endIndex]);
}

function isIndexInRanges(idx: number, ranges: Array<[number, number]>): boolean {
  for (const [start, end] of ranges) {
    if (idx >= start && idx <= end) return true;
  }
  return false;
}

function normalizeSchemaTypes(rawType: unknown): string[] {
  if (typeof rawType === 'string') {
    return [rawType.replace(/^https?:\/\/schema\.org\//i, '').trim()];
  }
  if (Array.isArray(rawType)) {
    return rawType
      .filter((t): t is string => typeof t === 'string')
      .map((t) => t.replace(/^https?:\/\/schema\.org\//i, '').trim());
  }
  return [];
}

function extractJsonLdApplicationSignals(blocks: unknown[]): {
  hasSoftwareAppJsonLd: boolean;
  hasProductJsonLd: boolean;
} {
  let hasSoftwareAppJsonLd = false;
  let hasProductJsonLd = false;

  const visit = (node: unknown, depth = 0): void => {
    if (depth > 8 || !node || typeof node !== 'object') return;
    if (Array.isArray(node)) {
      for (const entry of node) {
        visit(entry, depth + 1);
      }
      return;
    }

    const rec = node as Record<string, unknown>;
    const types = normalizeSchemaTypes(rec['@type']);

    if (types.some((t) => /^(?:SoftwareApplication|WebApplication|CloudApplication|APIReference)$/i.test(t))) {
      hasSoftwareAppJsonLd = true;
    }
    if (types.some((t) => /^(?:Product|ProductGroup|IndividualProduct)$/i.test(t))) {
      hasProductJsonLd = true;
    }

    for (const val of Object.values(rec)) {
      if (val && typeof val === 'object') {
        visit(val, depth + 1);
      }
    }
  };

  for (const block of blocks) {
    visit(block);
  }

  return { hasSoftwareAppJsonLd, hasProductJsonLd };
}

function extractImmediatePostControlText(domHtml: string, afterTagIdx: number): string {
  const slice = domHtml.slice(afterTagIdx, Math.min(domHtml.length, afterTagIdx + 240));
  const stopMatch = /<(?:input|button|select|textarea|form)\b|<\/(?:label|form|li|tr|p|div)\b/i.exec(slice);
  const bounded = stopMatch ? slice.slice(0, stopMatch.index) : slice;
  return stripTagsPreserveAlt(bounded).slice(0, 220);
}

export function parseHtmlDocument(rawHtml: string, pageUrl: string): ParsedHtmlDocument {
  const html = rawHtml || '';

  // 1. Remove HTML comments linearly in O(N)
  const uncommented = stripCommentsLinear(html);

  // 2. <html lang="..."> & <title>
  let htmlLang: string | null = null;
  const htmlTagMatch = /<html\b([^<>]{0,1024})>/i.exec(uncommented);
  if (htmlTagMatch) {
    const rawLang = getAttr(htmlTagMatch[1], 'lang');
    if (rawLang) {
      htmlLang = rawLang.split(/[-_]/)[0].toLowerCase();
    }
  }

  let title: string | null = null;
  const titleMatches = scanPairedElementsLinear(uncommented, 'title', 1);
  if (titleMatches.length > 0) {
    const cleanTitle = decodeHtmlEntities(titleMatches[0].inner).replace(/\s+/g, ' ').trim();
    title = cleanTitle || null;
  }

  // 3. Extract <script> tags, URLs, inline scripts, and JSON-LD blocks linearly in O(N)
  const scripts: ParsedScriptTag[] = [];
  const scriptUrls: string[] = [];
  const inlineScripts: string[] = [];
  const jsonLdBlocks: unknown[] = [];

  for (const scriptEl of scanPairedElementsLinear(uncommented, 'script', 260)) {
    const attrs = scriptEl.attrs;
    const body = scriptEl.inner.trim();
    const src = getAttr(attrs, 'src') || getAttr(attrs, 'data-lazy-src');
    const dataSrc = getAttr(attrs, 'data-src') || getAttr(attrs, 'data-cookieblock-src');
    const type = getAttr(attrs, 'type').toLowerCase();
    const id = getAttr(attrs, 'id');
    const className = getAttr(attrs, 'class');
    const resolvedSrc = src ? safeResolveUrl(src, pageUrl) : '';
    const resolvedDataSrc = dataSrc ? safeResolveUrl(dataSrc, pageUrl) : '';

    if (type === 'application/ld+json') {
      if (body && jsonLdBlocks.length < 30) {
        try {
          jsonLdBlocks.push(JSON.parse(body));
        } catch {
          // Ignore malformed JSON-LD blocks
        }
      }
      continue;
    }

    const inlineSnippet = body.slice(0, 8_000);
    if (scripts.length < 220) {
      scripts.push({
        src,
        resolvedSrc,
        dataSrc,
        resolvedDataSrc,
        type,
        id,
        className,
        dataAttributes: extractDataAttributesSummary(attrs),
        rawAttrs: attrs.slice(0, 600),
        inlineCode: inlineSnippet,
      });
    }

    const effectiveUrl = resolvedSrc || resolvedDataSrc;
    if (effectiveUrl && scriptUrls.length < 220) {
      scriptUrls.push(effectiveUrl);
    }
    if (!src && !dataSrc && inlineSnippet && inlineScripts.length < 60) {
      inlineScripts.push(inlineSnippet);
    }
  }

  const { hasSoftwareAppJsonLd, hasProductJsonLd } = extractJsonLdApplicationSignals(jsonLdBlocks);

  // 4. Extract <link> stylesheet/resource URLs
  const stylesheetUrls: string[] = [];
  const linkRe = /<link\b([^<>]{0,2048})>/gi;
  let linkMatch: RegExpExecArray | null;
  while ((linkMatch = linkRe.exec(uncommented)) !== null) {
    const href = getAttr(linkMatch[1], 'href');
    if (href && stylesheetUrls.length < 100) {
      stylesheetUrls.push(safeResolveUrl(href, pageUrl));
    }
  }

  // 5. Strip <script>, <style>, and <noscript> linearly in O(N) for active DOM inspection
  const domHtml = stripPairedTagLinear(
    stripPairedTagLinear(stripPairedTagLinear(uncommented, 'script'), 'style'),
    'noscript',
  );

  // 6. Extract <iframe> elements (supports self-closed <iframe ... /> without swallowing siblings)
  const iframes: ParsedIframeTag[] = [];
  const iframeRe = /<iframe\b([^<>]{0,2048})>/gi;
  let iframeMatch: RegExpExecArray | null;
  while ((iframeMatch = iframeRe.exec(domHtml)) !== null) {
    if (iframes.length >= 60) break;
    const attrs = iframeMatch[1] || '';
    const src = getAttr(attrs, 'src') || getAttr(attrs, 'data-lazy-src');
    const dataSrc = getAttr(attrs, 'data-src') || getAttr(attrs, 'data-cookieblock-src');
    iframes.push({
      src,
      resolvedSrc: src ? safeResolveUrl(src, pageUrl) : '',
      dataSrc,
      resolvedDataSrc: dataSrc ? safeResolveUrl(dataSrc, pageUrl) : '',
      title: getAttr(attrs, 'title').slice(0, 200),
      id: getAttr(attrs, 'id'),
      className: getAttr(attrs, 'class'),
      dataAttributes: extractDataAttributesSummary(attrs),
      rawAttrs: attrs.slice(0, 600),
    });
  }

  const footerRanges = findRegionRanges(domHtml, 'footer');
  const navRanges = [
    ...findRegionRanges(domHtml, 'nav'),
    ...findRegionRanges(domHtml, 'header'),
  ];

  // Build <label for="..."> map and enclosing <label> ranges linearly in O(N)
  const labelByForId = new Map<string, string>();
  const enclosingLabels: Array<{ start: number; end: number; text: string }> = [];
  for (const lbl of scanPairedElementsLinear(domHtml, 'label', 250)) {
    const text = stripTagsPreserveAlt(lbl.inner).slice(0, 320);
    const forId = getAttr(lbl.attrs, 'for');
    if (forId && !labelByForId.has(forId)) {
      labelByForId.set(forId, text);
    }
    if (text) {
      enclosingLabels.push({ start: lbl.index, end: lbl.endIndex, text });
    }
  }

  // 7. Extract <a ...>...</a> anchors linearly in O(N)
  const anchors: ParsedAnchor[] = [];
  for (const anchorEl of scanPairedElementsLinear(domHtml, 'a', 500)) {
    const attrs = anchorEl.attrs;
    const href = getAttr(attrs, 'href');
    const resolvedHref = href ? safeResolveUrl(href, pageUrl) : '';
    const text = stripTagsPreserveAlt(anchorEl.inner).slice(0, 240);
    const ariaLabel = getAttr(attrs, 'aria-label').slice(0, 200);
    const anchorTitle = getAttr(attrs, 'title').slice(0, 200);
    const id = getAttr(attrs, 'id');
    const className = getAttr(attrs, 'class');

    anchors.push({
      href,
      resolvedHref,
      text,
      ariaLabel,
      title: anchorTitle,
      id,
      className,
      inFooter: isIndexInRanges(anchorEl.index, footerRanges),
      inNav: isIndexInRanges(anchorEl.index, navRanges),
    });
  }

  // 8. Extract interactive <button>, <input>, role="switch"/role="checkbox"/role="button" controls
  const controls: ParsedControl[] = [];
  const checkboxes: ParsedCheckbox[] = [];

  for (const btnEl of scanPairedElementsLinear(domHtml, 'button', 250)) {
    const attrs = btnEl.attrs;
    controls.push({
      tag: 'button',
      type: getAttr(attrs, 'type').toLowerCase() || 'submit',
      text: stripTagsPreserveAlt(btnEl.inner).slice(0, 240),
      ariaLabel: getAttr(attrs, 'aria-label').slice(0, 200),
      id: getAttr(attrs, 'id'),
      className: getAttr(attrs, 'class'),
      name: getAttr(attrs, 'name'),
      dataAttributes: extractDataAttributesSummary(attrs),
    });
  }

  const inputTagRe = /<input\b([^<>]{0,2048})>/gi;
  let inpMatch: RegExpExecArray | null;
  while ((inpMatch = inputTagRe.exec(domHtml)) !== null) {
    const attrs = inpMatch[1] || '';
    const inpType = (getAttr(attrs, 'type') || 'text').toLowerCase();

    if ((inpType === 'submit' || inpType === 'button') && controls.length < 300) {
      controls.push({
        tag: 'input',
        type: inpType,
        text: getAttr(attrs, 'value').slice(0, 240),
        ariaLabel: getAttr(attrs, 'aria-label').slice(0, 200),
        id: getAttr(attrs, 'id'),
        className: getAttr(attrs, 'class'),
        name: getAttr(attrs, 'name'),
        dataAttributes: extractDataAttributesSummary(attrs),
      });
    } else if (inpType === 'checkbox' && checkboxes.length < 120) {
      const id = getAttr(attrs, 'id');
      const name = getAttr(attrs, 'name');
      const className = getAttr(attrs, 'class');
      const value = getAttr(attrs, 'value');
      const ariaLabel = getAttr(attrs, 'aria-label');
      const checked =
        hasBooleanAttr(attrs, 'checked') ||
        hasBooleanAttr(attrs, 'defaultChecked') ||
        getAttr(attrs, 'aria-checked').toLowerCase() === 'true' ||
        getAttr(attrs, 'data-default-checked').toLowerCase() === 'true';
      const required =
        hasBooleanAttr(attrs, 'required') ||
        getAttr(attrs, 'aria-required').toLowerCase() === 'true';

      const explicitLabel = id ? labelByForId.get(id) ?? '' : '';
      let associatedText = `${explicitLabel} ${ariaLabel}`.replace(/\s+/g, ' ').trim();
      if (!associatedText) {
        const enclosing = enclosingLabels.find(
          (l) => inpMatch!.index >= l.start && inpMatch!.index <= l.end,
        );
        if (enclosing) {
          associatedText = enclosing.text;
        } else {
          associatedText = extractImmediatePostControlText(
            domHtml,
            inpMatch.index + inpMatch[0].length,
          );
        }
      }

      checkboxes.push({
        id,
        name,
        className,
        value,
        checked,
        required,
        dataAttributes: extractDataAttributesSummary(attrs),
        rawAttrs: attrs.slice(0, 400),
        associatedText,
      });
    }
  }

  // Capture custom ARIA switch / checkbox toggles & role="button" elements without regex backtracking
  const roleOpenTagRe = /<(button|div|span|label|summary)\b([^<>]{1,2048})>/gi;
  let roleTagMatch: RegExpExecArray | null;
  while ((roleTagMatch = roleOpenTagRe.exec(domHtml)) !== null) {
    const tagName = roleTagMatch[1].toLowerCase();
    const attrs = roleTagMatch[2] || '';
    const role = getAttr(attrs, 'role').toLowerCase();
    if (role !== 'switch' && role !== 'checkbox' && role !== 'button') continue;

    const afterOpen = roleTagMatch.index + roleTagMatch[0].length;
    const boundedSlice = domHtml.slice(afterOpen, Math.min(domHtml.length, afterOpen + 800));
    const closeTagIdx = boundedSlice.toLowerCase().indexOf(`</${tagName}`);
    const innerRaw = closeTagIdx >= 0 ? boundedSlice.slice(0, closeTagIdx) : '';
    const innerText = stripTagsPreserveAlt(innerRaw).slice(0, 240);
    const ariaLabel = getAttr(attrs, 'aria-label').slice(0, 200);

    if ((role === 'switch' || role === 'checkbox') && checkboxes.length < 120) {
      const id = getAttr(attrs, 'id');
      const explicitLabel = id ? labelByForId.get(id) ?? '' : '';
      const ariaChecked = getAttr(attrs, 'aria-checked').toLowerCase() === 'true';
      let associatedText = `${explicitLabel} ${ariaLabel} ${innerText}`.replace(/\s+/g, ' ').trim();
      if (!associatedText) {
        associatedText = extractImmediatePostControlText(
          domHtml,
          afterOpen + (closeTagIdx >= 0 ? closeTagIdx + tagName.length + 3 : 0),
        );
      }

      checkboxes.push({
        id,
        name: getAttr(attrs, 'name'),
        className: getAttr(attrs, 'class'),
        value: getAttr(attrs, 'value'),
        checked: ariaChecked || getAttr(attrs, 'data-default-checked').toLowerCase() === 'true',
        required: false,
        dataAttributes: extractDataAttributesSummary(attrs),
        rawAttrs: attrs.slice(0, 400),
        associatedText,
      });
    } else if (role === 'button' && tagName !== 'button' && controls.length < 350) {
      controls.push({
        tag: 'role-button',
        type: 'button',
        text: innerText,
        ariaLabel,
        id: getAttr(attrs, 'id'),
        className: getAttr(attrs, 'class'),
        name: getAttr(attrs, 'name'),
        dataAttributes: extractDataAttributesSummary(attrs),
      });
    }
  }

  // 9. Extract <form> elements linearly in O(N)
  const forms: ParsedForm[] = [];
  for (const formEl of scanPairedElementsLinear(domHtml, 'form', 50)) {
    const attrs = formEl.attrs;
    const inner = formEl.inner;
    const action = getAttr(attrs, 'action');
    const resolvedAction = action ? safeResolveUrl(action, pageUrl) : pageUrl;
    const method = (getAttr(attrs, 'method') || 'get').toLowerCase();
    const id = getAttr(attrs, 'id');
    const className = getAttr(attrs, 'class');

    const inputNamesAndTypes: string[] = [];
    const fieldRe = /<(input|select|textarea)\b([^<>]{0,2048})>/gi;
    let fm: RegExpExecArray | null;
    while ((fm = fieldRe.exec(inner)) !== null) {
      const tag = fm[1].toLowerCase();
      const fAttrs = fm[2] || '';
      const fType = (getAttr(fAttrs, 'type') || (tag === 'input' ? 'text' : tag)).toLowerCase();
      if (fType === 'hidden' || fType === 'submit' || fType === 'button') continue;
      const fName = getAttr(fAttrs, 'name');
      const fId = getAttr(fAttrs, 'id');
      const fPlaceholder = getAttr(fAttrs, 'placeholder');
      const fLabel = fId ? labelByForId.get(fId) ?? '' : '';
      const ident = fName || fId || fPlaceholder || fLabel || 'field';
      inputNamesAndTypes.push(`${ident.slice(0, 60)}:${fType}`);
      if (inputNamesAndTypes.length >= 80) break;
    }

    const buttonTexts: string[] = [];
    for (const ibm of scanPairedElementsLinear(inner, 'button', 40)) {
      const t = stripTagsPreserveAlt(ibm.inner) || getAttr(ibm.attrs, 'aria-label');
      if (t) buttonTexts.push(t.slice(0, 160));
    }
    const innerSubRe = /<input\b([^<>]{0,2048})>/gi;
    let ism: RegExpExecArray | null;
    while ((ism = innerSubRe.exec(inner)) !== null) {
      const tType = getAttr(ism[1] || '', 'type').toLowerCase();
      if (tType === 'submit' || tType === 'button') {
        const val = getAttr(ism[1] || '', 'value');
        if (val) buttonTexts.push(val.slice(0, 160));
      }
    }

    forms.push({
      action,
      resolvedAction,
      method,
      id,
      className,
      inputNamesAndTypes,
      buttonTexts,
      textSnippet: stripTagsPreserveAlt(inner).slice(0, 500),
    });
  }

  // 10. Clean visible text (strip remaining SVG bodies linearly, keep img[alt])
  const withoutSvg = stripPairedTagLinear(domHtml, 'svg');
  const visibleText = stripTagsPreserveAlt(withoutSvg);

  return {
    url: pageUrl,
    title,
    htmlLang,
    rawHtml: html,
    domHtml,
    visibleText,
    scripts,
    scriptUrls,
    inlineScripts,
    iframes,
    stylesheetUrls,
    jsonLdBlocks,
    hasSoftwareAppJsonLd,
    hasProductJsonLd,
    anchors,
    controls,
    checkboxes,
    forms,
  };
}
