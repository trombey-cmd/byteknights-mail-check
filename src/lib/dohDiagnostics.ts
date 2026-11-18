import type {
  BlacklistEntryResult,
  BlacklistModuleResult,
  CheckSeverity,
  DkimModuleResult,
  DkimSelectorResult,
  DmarcModuleResult,
  MxModuleResult,
  MxRecordResult,
  PortsModuleResult,
  PtrCheck,
  RecommendationItem,
  SpfLookupNode,
  SpfMechanism,
  SpfModuleResult,
} from '../types/mailcheck';

const DEFAULT_DKIM_SELECTORS = [
  'default',
  'google',
  'selector1',
  'selector2',
  'k1',
  's1',
  's2',
  'dkim',
  'mail',
  'smtp',
  'm1',
  'sig1',
  'protonmail',
  'zoho',
];

const DNSBL_ZONES: Array<{ id: string; name: string; zone: string; queryType: 'ip' | 'domain' }> = [
  { id: 'spamhaus-zen', name: 'Spamhaus ZEN', zone: 'zen.spamhaus.org', queryType: 'ip' },
  { id: 'spamcop', name: 'SpamCop', zone: 'bl.spamcop.net', queryType: 'ip' },
  { id: 'barracuda', name: 'Barracuda BRBL', zone: 'b.barracudacentral.org', queryType: 'ip' },
  { id: 'sorbs', name: 'SORBS DNSBL', zone: 'dnsbl.sorbs.net', queryType: 'ip' },
  { id: 'cbl', name: 'Abuseat CBL', zone: 'cbl.abuseat.org', queryType: 'ip' },
  { id: 'psbl', name: 'Surriel PSBL', zone: 'psbl.surriel.com', queryType: 'ip' },
  { id: 'uceprotect-1', name: 'UCEPROTECT L1', zone: 'dnsbl-1.uceprotect.net', queryType: 'ip' },
  { id: 'nix-spam', name: 'NiX Spam (Heise)', zone: 'ix.dnsbl.manitu.net', queryType: 'ip' },
  { id: 'spamhaus-dbl', name: 'Spamhaus DBL', zone: 'dbl.spamhaus.org', queryType: 'domain' },
];

interface DohAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface DohResponse {
  Status: number;
  Answer?: DohAnswer[];
}

const DNS_TYPE_A = 1;
const DNS_TYPE_PTR = 12;
const DNS_TYPE_MX = 15;
const DNS_TYPE_TXT = 16;
const DNS_TYPE_AAAA = 28;

export function normalizeTargetInput(rawInput: string): { domain: string; isIp: boolean } {
  let cleaned = rawInput.trim().toLowerCase();
  cleaned = cleaned.replace(/^https?:\/\//, '');
  cleaned = cleaned.split('/')[0] ?? cleaned;
  cleaned = cleaned.split('?')[0] ?? cleaned;

  if (cleaned.includes('@')) {
    const parts = cleaned.split('@');
    cleaned = parts[parts.length - 1] ?? cleaned;
  }

  cleaned = cleaned.replace(/:\d+$/, '').replace(/\.+$/, '');
  const isIp = isIpv4(cleaned);
  return { domain: cleaned, isIp };
}

function isIpv4(val: string): boolean {
  return /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/.test(val);
}

export function isValidTarget(value: string): boolean {
  if (!value || value.length > 253) return false;
  if (isIpv4(value)) return true;
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(value);
}

async function queryDoh(name: string, type: 'A' | 'AAAA' | 'MX' | 'TXT' | 'PTR'): Promise<DohResponse> {
  const endpoints = [
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
    `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`,
  ];

  for (const url of endpoints) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4000);
      const res = await fetch(url, {
        headers: { Accept: 'application/dns-json' },
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (res.ok) {
        return (await res.json()) as DohResponse;
      }
    } catch {
      // try next DoH provider
    }
  }
  return { Status: 2 };
}

function parseTxtData(raw: string): string {
  const trimmed = raw.trim();
  const matches = trimmed.match(/"((?:[^"\\]|\\.)*)"/g);
  if (matches && matches.length > 0) {
    return matches
      .map((segment) => segment.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\'))
      .join('');
  }
  return trimmed.replace(/^"|"$/g, '');
}

async function resolveA(name: string): Promise<string[]> {
  const res = await queryDoh(name, 'A');
  return (res.Answer ?? [])
    .filter((a) => a.type === DNS_TYPE_A)
    .map((a) => a.data.trim());
}

async function resolveAAAA(name: string): Promise<string[]> {
  const res = await queryDoh(name, 'AAAA');
  return (res.Answer ?? [])
    .filter((a) => a.type === DNS_TYPE_AAAA)
    .map((a) => a.data.trim());
}

async function resolveTxt(name: string): Promise<string[]> {
  const res = await queryDoh(name, 'TXT');
  return (res.Answer ?? [])
    .filter((a) => a.type === DNS_TYPE_TXT)
    .map((a) => parseTxtData(a.data));
}

async function resolvePtr(ip: string): Promise<string[]> {
  if (!isIpv4(ip)) return [];
  const reversed = ip.split('.').reverse().join('.') + '.in-addr.arpa';
  const res = await queryDoh(reversed, 'PTR');
  return (res.Answer ?? [])
    .filter((a) => a.type === DNS_TYPE_PTR)
    .map((a) => a.data.trim().replace(/\.+$/, '').toLowerCase());
}

async function checkMxDoh(domain: string): Promise<MxModuleResult> {
  const start = Date.now();
  const res = await queryDoh(domain, 'MX');

  if (res.Status === 3) {
    return {
      status: 'error',
      summary: 'Domain nicht auflösbar (NXDOMAIN)',
      records: [],
      fallbackA: [],
      durationMs: Date.now() - start,
      error: 'NXDOMAIN',
    };
  }

  const parsedMx = (res.Answer ?? [])
    .filter((a) => a.type === DNS_TYPE_MX)
    .map((a) => {
      const parts = a.data.trim().split(/\s+/);
      const priority = Number.parseInt(parts[0] ?? '0', 10);
      const exchange = (parts[1] ?? '').replace(/\.+$/, '').toLowerCase();
      return { priority: Number.isNaN(priority) ? 0 : priority, exchange };
    })
    .filter((m) => m.exchange.length > 0)
    .sort((a, b) => a.priority - b.priority);

  if (parsedMx.length === 0) {
    const fallbackA = await resolveA(domain);
    return {
      status: fallbackA.length > 0 ? 'warn' : 'error',
      summary:
        fallbackA.length > 0
          ? 'Kein MX-Record, aber A-Record vorhanden (Fallback)'
          : 'Keine MX-Records gefunden',
      records: [],
      fallbackA,
      durationMs: Date.now() - start,
    };
  }

  const records: MxRecordResult[] = await Promise.all(
    parsedMx.map(async (mx) => {
      const mxStart = Date.now();
      const [ipv4, ipv6] = await Promise.all([resolveA(mx.exchange), resolveAAAA(mx.exchange)]);
      const ptr: PtrCheck[] = await Promise.all(
        ipv4.slice(0, 2).map(async (ip) => {
          const hostnames = await resolvePtr(ip);
          let fcrdnsMatch = false;
          for (const host of hostnames) {
            const forward = await resolveA(host);
            if (forward.includes(ip)) {
              fcrdnsMatch = true;
              break;
            }
          }
          return { ip, hostnames, fcrdnsMatch };
        })
      );
      return {
        exchange: mx.exchange,
        priority: mx.priority,
        ipv4,
        ipv6,
        ptr,
        latencyMs: Date.now() - mxStart,
      };
    })
  );

  const hasMissingA = records.some((r) => r.ipv4.length === 0 && r.ipv6.length === 0);
  const hasMissingPtr = records.some((r) => r.ptr.some((p) => p.hostnames.length === 0 || !p.fcrdnsMatch));

  let status: CheckSeverity = 'ok';
  let summary = `${records.length} MX-Server · FCrDNS gültig`;
  if (hasMissingA) {
    status = 'error';
    summary = 'MX-Ziel ohne gültige IP-Adresse';
  } else if (hasMissingPtr) {
    status = 'warn';
    summary = `${records.length} MX-Server · PTR/FCrDNS unvollständig`;
  } else if (records.length === 1) {
    summary = '1 MX-Server mit gültigem FCrDNS';
  }

  return {
    status,
    summary,
    records,
    fallbackA: [],
    durationMs: Date.now() - start,
  };
}

function parseSpfMechanisms(record: string): SpfMechanism[] {
  const tokens = record.trim().split(/\s+/).slice(1);
  return tokens.map((raw) => {
    let qualifier: '+' | '-' | '~' | '?' = '+';
    let body = raw;
    if (raw.startsWith('+') || raw.startsWith('-') || raw.startsWith('~') || raw.startsWith('?')) {
      qualifier = raw[0] as '+' | '-' | '~' | '?';
      body = raw.slice(1);
    }
    let type = body.toLowerCase();
    let value = '';
    if (body.includes(':')) {
      const idx = body.indexOf(':');
      type = body.slice(0, idx).toLowerCase();
      value = body.slice(idx + 1);
    } else if (body.includes('=')) {
      const idx = body.indexOf('=');
      type = body.slice(0, idx).toLowerCase();
      value = body.slice(idx + 1);
    }
    return {
      raw,
      qualifier,
      type,
      value,
      causesLookup: ['include', 'a', 'mx', 'ptr', 'exists', 'redirect'].includes(type),
    };
  });
}

async function countSpfLookupsDoh(
  domain: string,
  visited: Set<string>,
  depth: number,
  chain: SpfLookupNode[]
): Promise<{ lookups: number; record: string | null; allRecords: string[] }> {
  if (depth > 8 || visited.has(domain.toLowerCase())) {
    return { lookups: 0, record: null, allRecords: [] };
  }
  visited.add(domain.toLowerCase());

  const txtStrings = await resolveTxt(domain);
  const spfRecords = txtStrings.filter((t) => /^v=spf1(\s|$)/i.test(t.trim()));
  if (spfRecords.length === 0) {
    return { lookups: 0, record: null, allRecords: [] };
  }

  const primary = spfRecords[0] ?? null;
  if (!primary) return { lookups: 0, record: null, allRecords: spfRecords };

  const mechs = parseSpfMechanisms(primary);
  let totalLookups = 0;
  let localLookups = 0;

  for (const mech of mechs) {
    if (mech.causesLookup) {
      totalLookups += 1;
      localLookups += 1;
    }
  }

  chain.push({ domain, depth, lookups: localLookups });

  for (const mech of mechs) {
    if ((mech.type === 'include' || mech.type === 'redirect') && mech.value) {
      const targetDomain = mech.value.replace(/^.*:/, '').trim();
      if (targetDomain && !targetDomain.includes('%{')) {
        const sub = await countSpfLookupsDoh(targetDomain, visited, depth + 1, chain);
        totalLookups += sub.lookups;
      }
    }
  }

  return { lookups: totalLookups, record: primary, allRecords: spfRecords };
}

async function checkSpfDoh(domain: string): Promise<SpfModuleResult> {
  const start = Date.now();
  const chain: SpfLookupNode[] = [];
  const { lookups, record, allRecords } = await countSpfLookupsDoh(domain, new Set<string>(), 0, chain);
  const issues: string[] = [];

  if (!record) {
    return {
      status: 'error',
      summary: 'Kein SPF-Record (v=spf1) vorhanden',
      record: null,
      allRecords: [],
      mechanisms: [],
      allQualifier: null,
      lookupCount: 0,
      lookupLimit: 10,
      lookupChain: [],
      durationMs: Date.now() - start,
      issues: ['Es wurde kein TXT-Eintrag mit „v=spf1“ gefunden.'],
    };
  }

  if (allRecords.length > 1) {
    issues.push(`Mehrere SPF-Records gefunden (${allRecords.length}). Laut RFC 7208 ist maximal ein SPF-Eintrag zulässig.`);
  }

  const mechanisms = parseSpfMechanisms(record);
  const allMech = mechanisms.find((m) => m.type === 'all');
  const allQualifier = allMech ? `${allMech.qualifier}all` : null;

  if (!allMech) {
    issues.push('Kein abschließender „all“-Mechanismus (z. B. -all oder ~all) definiert.');
  } else if (allMech.qualifier === '+') {
    issues.push('Kritisch: „+all“ erlaubt jedem beliebigen Server den Versand im Namen Ihrer Domain.');
  } else if (allMech.qualifier === '?') {
    issues.push('„?all“ (Neutral) bietet keinen effektiven Schutz vor Spoofing.');
  }

  if (mechanisms.some((m) => m.type === 'ptr')) {
    issues.push('Der veraltete „ptr“-Mechanismus sollte laut RFC 7208 vermieden werden.');
  }

  if (lookups > 10) {
    issues.push(`DNS-Lookup-Limit überschritten: ${lookups} von maximal 10 erlaubten Lookups.`);
  } else if (lookups >= 8) {
    issues.push(`Hohe Anzahl an DNS-Lookups (${lookups}/10).`);
  }

  let status: CheckSeverity = 'ok';
  if (allRecords.length > 1 || allQualifier === '+all' || lookups > 10) {
    status = 'error';
  } else if (issues.length > 0) {
    status = 'warn';
  }

  return {
    status,
    summary: `${allQualifier ? `${allQualifier} · ` : ''}${lookups}/10 Lookups`,
    record,
    allRecords,
    mechanisms,
    allQualifier,
    lookupCount: lookups,
    lookupLimit: 10,
    lookupChain: chain,
    durationMs: Date.now() - start,
    issues,
  };
}

function estimateKeyBitsBrowser(pubKeyBase64: string, keyType: string | null): number | null {
  try {
    const clean = pubKeyBase64.replace(/\s+/g, '');
    if (!clean) return null;
    const raw = atob(clean);
    const len = raw.length;
    if (keyType?.toLowerCase() === 'ed25519') return len * 8;
    if (len >= 500) return 4096;
    if (len >= 250) return 2048;
    if (len >= 130) return 1024;
    if (len >= 70) return 512;
    return len * 8;
  } catch {
    return null;
  }
}

export async function probeDkimSelectorDoh(domain: string, selector: string): Promise<DkimSelectorResult> {
  const cleanSelector = selector.trim().toLowerCase();
  const fqdn = `${cleanSelector}._domainkey.${domain}`;
  const txtStrings = await resolveTxt(fqdn);
  const rawRecord = txtStrings.find((t) => /v=DKIM1|k=|p=/i.test(t)) ?? txtStrings[0] ?? null;

  if (!rawRecord) {
    return {
      selector: cleanSelector,
      fqdn,
      found: false,
      record: null,
      version: null,
      keyType: null,
      keyBits: null,
      publicKeyPreview: null,
      flags: [],
      revoked: false,
      status: 'info',
      note: 'Kein Eintrag unter diesem Selektor',
    };
  }

  const tags: Record<string, string> = {};
  for (const part of rawRecord.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx > 0) {
      tags[trimmed.slice(0, eqIdx).trim().toLowerCase()] = trimmed.slice(eqIdx + 1).trim();
    }
  }

  const version = tags['v'] ?? 'DKIM1';
  const keyType = tags['k'] ?? 'rsa';
  const pubKey = tags['p'] ?? '';
  const revoked = 'p' in tags && pubKey.length === 0;
  const flags = tags['t'] ? tags['t'].split(':').map((f) => f.trim()).filter(Boolean) : [];
  const keyBits = pubKey ? estimateKeyBitsBrowser(pubKey, keyType) : null;
  const publicKeyPreview = pubKey ? `${pubKey.slice(0, 26)}…${pubKey.slice(-10)}` : null;

  let status: CheckSeverity = 'ok';
  let note = keyBits ? `${keyType.toUpperCase()} ${keyBits} Bit` : `${keyType.toUpperCase()} aktiv`;

  if (revoked) {
    status = 'warn';
    note = 'Schlüssel widerrufen (p= leer)';
  } else if (flags.includes('y')) {
    status = 'warn';
    note = `${note} · Testmodus (t=y)`;
  } else if (keyBits !== null && keyType.toLowerCase() === 'rsa' && keyBits < 1024) {
    status = 'error';
    note = `Unsichere Schlüssellänge (${keyBits} Bit < 1024)`;
  } else if (keyBits !== null && keyType.toLowerCase() === 'rsa' && keyBits < 2048) {
    status = 'warn';
    note = `${keyBits} Bit (2048 Bit empfohlen)`;
  }

  return {
    selector: cleanSelector,
    fqdn,
    found: true,
    record: rawRecord,
    version,
    keyType,
    keyBits,
    publicKeyPreview,
    flags,
    revoked,
    status,
    note,
  };
}

async function checkDkimDoh(domain: string, customSelectors: string[]): Promise<DkimModuleResult> {
  const start = Date.now();
  const merged = Array.from(
    new Set([
      ...customSelectors.map((s) => s.trim().toLowerCase()).filter(Boolean),
      ...DEFAULT_DKIM_SELECTORS,
    ])
  );

  const wcName = `__wc_${Math.random().toString(36).slice(2, 8)}`;
  const [wildcardProbe, results] = await Promise.all([
    probeDkimSelectorDoh(domain, wcName),
    Promise.all(merged.map((sel) => probeDkimSelectorDoh(domain, sel))),
  ]);

  const wildcardRecord = wildcardProbe.found ? wildcardProbe.record : null;
  const distinctFound = results.filter((r) => r.found && r.record !== wildcardRecord);
  const found = wildcardRecord
    ? distinctFound.length > 0
      ? distinctFound
      : [{ ...wildcardProbe, selector: '* (Wildcard)', fqdn: `*._domainkey.${domain}`, note: `${wildcardProbe.note} · Wildcard-DNS` }]
    : results.filter((r) => r.found);

  let status: CheckSeverity = 'ok';
  let summary = '';
  if (found.length === 0) {
    status = 'warn';
    summary = `Keine Standard-Selektoren gefunden (${merged.length} geprüft)`;
  } else {
    const hasError = found.some((f) => f.status === 'error');
    const hasWarn = found.some((f) => f.status === 'warn');
    status = hasError ? 'error' : hasWarn ? 'warn' : 'ok';
    summary =
      wildcardRecord && distinctFound.length === 0
        ? 'Wildcard-DKIM aktiv (*._domainkey)'
        : `${found.length} aktive${found.length === 1 ? 'r' : ''} Selektor${found.length === 1 ? '' : 'en'} (${found.map((f) => f.selector).slice(0, 3).join(', ')})`;
  }

  const ordered = [
    ...found,
    ...results.filter((r) => !r.found && customSelectors.includes(r.selector)),
  ];

  return {
    status,
    summary,
    testedSelectors: merged,
    foundCount: found.length,
    selectors: ordered.length > 0 ? ordered : results.slice(0, 6),
    durationMs: Date.now() - start,
  };
}

async function checkDmarcDoh(domain: string): Promise<DmarcModuleResult> {
  const start = Date.now();
  const [dmarcStrings, mtaStsStrings, tlsRptStrings] = await Promise.all([
    resolveTxt(`_dmarc.${domain}`),
    resolveTxt(`_mta-sts.${domain}`),
    resolveTxt(`_smtp._tls.${domain}`),
  ]);

  const dmarcRecord = dmarcStrings.find((s) => /^v=DMARC1/i.test(s.trim())) ?? null;
  const mtaStsRecord = mtaStsStrings.find((s) => /v=STSv1/i.test(s)) ?? null;
  const mtaStsIdMatch = mtaStsRecord?.match(/id=([^;\s]+)/i);
  const tlsRptRecord = tlsRptStrings.find((s) => /v=TLSRPTv1/i.test(s)) ?? null;
  const tlsRptRuaMatch = tlsRptRecord?.match(/rua=([^;\s]+)/i);
  const tlsRptRua = tlsRptRuaMatch?.[1] ? tlsRptRuaMatch[1].split(',').map((s) => s.trim()) : [];

  if (!dmarcRecord) {
    return {
      status: 'error',
      summary: 'Kein DMARC-Eintrag (_dmarc) gefunden',
      record: null,
      policy: null,
      subdomainPolicy: null,
      pct: null,
      adkim: null,
      aspf: null,
      rua: [],
      ruf: [],
      fo: null,
      mtaSts: { found: Boolean(mtaStsRecord), record: mtaStsRecord, id: mtaStsIdMatch?.[1] ?? null },
      tlsRpt: { found: Boolean(tlsRptRecord), record: tlsRptRecord, rua: tlsRptRua },
      durationMs: Date.now() - start,
      issues: ['Kein TXT-Record unter _dmarc.' + domain + ' vorhanden.'],
    };
  }

  const tags: Record<string, string> = {};
  for (const part of dmarcRecord.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx > 0) {
      tags[trimmed.slice(0, eqIdx).trim().toLowerCase()] = trimmed.slice(eqIdx + 1).trim();
    }
  }

  const policy = tags['p']?.toLowerCase() ?? null;
  const subdomainPolicy = tags['sp']?.toLowerCase() ?? null;
  const pct = tags['pct'] ? Number.parseInt(tags['pct'], 10) : 100;
  const adkim = tags['adkim']?.toLowerCase() ?? 'r';
  const aspf = tags['aspf']?.toLowerCase() ?? 'r';
  const rua = tags['rua'] ? tags['rua'].split(',').map((s) => s.trim()).filter(Boolean) : [];
  const ruf = tags['ruf'] ? tags['ruf'].split(',').map((s) => s.trim()).filter(Boolean) : [];
  const fo = tags['fo'] ?? null;

  const issues: string[] = [];
  if (!policy) issues.push('Pflicht-Tag „p=“ fehlt im DMARC-Record.');
  else if (policy === 'none') issues.push('Policy steht auf „p=none“ (nur Beobachtung, keine Ablehnung gefälschter Mails).');
  if (rua.length === 0) issues.push('Keine „rua=“-Adresse für aggregierte DMARC-Berichte hinterlegt.');
  if (pct !== null && pct < 100) issues.push(`Policy greift aktuell nur für ${pct}% der Nachrichten (pct=${pct}).`);

  let status: CheckSeverity = 'ok';
  if (!policy) status = 'error';
  else if (policy === 'none' || issues.length > 0) status = 'warn';

  return {
    status,
    summary: policy ? `p=${policy}${rua.length > 0 ? ' · Reporting aktiv' : ' · Ohne rua'}` : 'Ungültige DMARC-Syntax',
    record: dmarcRecord,
    policy,
    subdomainPolicy,
    pct: Number.isNaN(pct) ? 100 : pct,
    adkim,
    aspf,
    rua,
    ruf,
    fo,
    mtaSts: { found: Boolean(mtaStsRecord), record: mtaStsRecord, id: mtaStsIdMatch?.[1] ?? null },
    tlsRpt: { found: Boolean(tlsRptRecord), record: tlsRptRecord, rua: tlsRptRua },
    durationMs: Date.now() - start,
    issues,
  };
}

async function checkBlacklistsDoh(domain: string, ip: string | null): Promise<BlacklistModuleResult> {
  const start = Date.now();
  const reversedIp = ip && isIpv4(ip) ? ip.split('.').reverse().join('.') : null;

  const entries: BlacklistEntryResult[] = await Promise.all(
    DNSBL_ZONES.map(async (rbl) => {
      const rblStart = Date.now();
      if (rbl.queryType === 'ip' && !reversedIp) {
        return {
          id: rbl.id,
          name: rbl.name,
          zone: rbl.zone,
          queryType: rbl.queryType,
          queryTarget: 'Keine IPv4-Adresse',
          state: 'error',
          status: 'info',
          returnCode: null,
          txtReason: null,
          latencyMs: 0,
        };
      }

      const queryHost = rbl.queryType === 'ip' ? `${reversedIp}.${rbl.zone}` : `${domain}.${rbl.zone}`;
      const res = await queryDoh(queryHost, 'A');
      const answers = (res.Answer ?? []).filter((a) => a.type === DNS_TYPE_A).map((a) => a.data.trim());

      if (res.Status === 0 && answers.length > 0) {
        const code = answers[0] ?? null;
        if (code && code.startsWith('127.255.255.')) {
          return {
            id: rbl.id,
            name: rbl.name,
            zone: rbl.zone,
            queryType: rbl.queryType,
            queryTarget: queryHost,
            state: 'blocked_resolver',
            status: 'info',
            returnCode: code,
            txtReason: 'Abfrage über öffentlichen DoH-Resolver gedrosselt',
            latencyMs: Date.now() - rblStart,
          };
        }
        const txtReasons = await resolveTxt(queryHost);
        return {
          id: rbl.id,
          name: rbl.name,
          zone: rbl.zone,
          queryType: rbl.queryType,
          queryTarget: queryHost,
          state: 'listed',
          status: 'error',
          returnCode: code,
          txtReason: txtReasons.join(' | ') || null,
          latencyMs: Date.now() - rblStart,
        };
      }

      if (res.Status === 3 || (res.Status === 0 && answers.length === 0)) {
        return {
          id: rbl.id,
          name: rbl.name,
          zone: rbl.zone,
          queryType: rbl.queryType,
          queryTarget: queryHost,
          state: 'clean',
          status: 'ok',
          returnCode: null,
          txtReason: null,
          latencyMs: Date.now() - rblStart,
        };
      }

      return {
        id: rbl.id,
        name: rbl.name,
        zone: rbl.zone,
        queryType: rbl.queryType,
        queryTarget: queryHost,
        state: 'error',
        status: 'info',
        returnCode: null,
        txtReason: `DNS Status ${res.Status}`,
        latencyMs: Date.now() - rblStart,
      };
    })
  );

  const listedCount = entries.filter((e) => e.state === 'listed').length;
  const cleanCount = entries.filter((e) => e.state === 'clean').length;

  let status: CheckSeverity = 'ok';
  let summary = `${cleanCount}/${entries.length} sauber · 0 Listungen`;
  if (listedCount > 0) {
    status = 'error';
    summary = `${listedCount} Blacklist-Listung${listedCount > 1 ? 'en' : ''} erkannt`;
  } else if (!ip) {
    status = 'warn';
    summary = 'Keine IPv4-Adresse für IP-DNSBL verfügbar';
  }

  return {
    status,
    summary,
    checkedIp: ip,
    checkedDomain: domain,
    listedCount,
    totalChecked: entries.length,
    entries,
    durationMs: Date.now() - start,
  };
}

function buildRecommendationsClient(
  domain: string,
  mx: MxModuleResult,
  spf: SpfModuleResult,
  dkim: DkimModuleResult,
  dmarc: DmarcModuleResult,
  blacklists: BlacklistModuleResult
): RecommendationItem[] {
  const recs: RecommendationItem[] = [];

  if (mx.status === 'error') {
    recs.push({
      id: 'mx-missing',
      module: 'MX',
      severity: 'error',
      title: 'MX-Einträge konfigurieren',
      description: 'Ohne gültige MX-Records können externe Mailserver E-Mails für diese Domain nicht zuverlässig zustellen.',
      suggestedRecord: `${domain}. IN MX 10 mail.${domain}.`,
    });
  } else if (mx.records.some((r) => r.ptr.some((p) => !p.fcrdnsMatch))) {
    recs.push({
      id: 'mx-ptr',
      module: 'MX',
      severity: 'warn',
      title: 'Reverse DNS (PTR / FCrDNS) abgleichen',
      description: 'Mindestens eine MX-IP besitzt keinen vorwärts-bestätigten PTR-Eintrag.',
    });
  }

  if (!spf.record) {
    recs.push({
      id: 'spf-missing',
      module: 'SPF',
      severity: 'error',
      title: 'SPF-Record veröffentlichen',
      description: 'Legen Sie einen TXT-Eintrag für autorisierte Versandserver an.',
      suggestedRecord: `v=spf1 mx -all`,
    });
  } else if (spf.allQualifier === '~all' || spf.allQualifier === '?all' || spf.allQualifier === '+all') {
    recs.push({
      id: 'spf-all',
      module: 'SPF',
      severity: spf.allQualifier === '+all' ? 'error' : 'warn',
      title: `SPF-Abschluss von „${spf.allQualifier}“ auf „-all“ verschärfen`,
      description: 'Ein hartes „-all“ (Fail) weist unautorisierte Server eindeutig ab.',
    });
  }

  if (dkim.foundCount === 0) {
    recs.push({
      id: 'dkim-none',
      module: 'DKIM',
      severity: 'warn',
      title: 'DKIM-Selektor prüfen oder aktivieren',
      description: 'Keiner der Standard-Selektoren lieferte einen öffentlichen DKIM-Schlüssel.',
    });
  }

  if (!dmarc.record) {
    recs.push({
      id: 'dmarc-missing',
      module: 'DMARC',
      severity: 'error',
      title: 'DMARC-Richtlinie anlegen',
      description: 'Veröffentlichen Sie einen _dmarc TXT-Record für SPF/DKIM-Alignment und Reporting.',
      suggestedRecord: `_dmarc.${domain}. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@${domain}; adkim=s; aspf=s"`,
    });
  } else if (dmarc.policy === 'none') {
    recs.push({
      id: 'dmarc-none',
      module: 'DMARC',
      severity: 'warn',
      title: 'DMARC-Policy auf „quarantine“ oder „reject“ anheben',
      description: 'Mit „p=none“ werden gefälschte E-Mails lediglich protokolliert, aber nicht blockiert.',
    });
  }

  if (blacklists.listedCount > 0) {
    recs.push({
      id: 'rbl-listed',
      module: 'Blacklists',
      severity: 'error',
      title: 'Blacklist-Eintragung beheben (Delisting)',
      description: `Es wurden ${blacklists.listedCount} Listungen gefunden.`,
    });
  }

  return recs;
}

export interface DohStreamCallbacks {
  onInit: (meta: { id: string; input: string; domain: string; customHost: string | null; customSelectors: string[]; startedAt: string }) => void;
  onMx: (mx: MxModuleResult) => void;
  onSpf: (spf: SpfModuleResult) => void;
  onDkim: (dkim: DkimModuleResult) => void;
  onDmarc: (dmarc: DmarcModuleResult) => void;
  onPorts: (ports: PortsModuleResult) => void;
  onBlacklists: (bl: BlacklistModuleResult) => void;
  onComplete: (payload: { completedAt: string; totalDurationMs: number; recommendations: RecommendationItem[] }) => void;
}

export async function runLiveDohCheck(
  rawInput: string,
  customSelectors: string[],
  customHost: string | null,
  callbacks: DohStreamCallbacks,
  signal?: AbortSignal
): Promise<void> {
  const startTime = Date.now();
  const parsed = normalizeTargetInput(rawInput);

  callbacks.onInit({
    id: crypto.randomUUID(),
    input: rawInput,
    domain: parsed.domain,
    customHost,
    customSelectors,
    startedAt: new Date(startTime).toISOString(),
  });

  if (signal?.aborted) return;

  const mxPromise = checkMxDoh(parsed.domain).then((mx) => {
    if (!signal?.aborted) callbacks.onMx(mx);
    return mx;
  });
  const spfPromise = checkSpfDoh(parsed.domain).then((spf) => {
    if (!signal?.aborted) callbacks.onSpf(spf);
    return spf;
  });
  const dkimPromise = checkDkimDoh(parsed.domain, customSelectors).then((dkim) => {
    if (!signal?.aborted) callbacks.onDkim(dkim);
    return dkim;
  });
  const dmarcPromise = checkDmarcDoh(parsed.domain).then((dmarc) => {
    if (!signal?.aborted) callbacks.onDmarc(dmarc);
    return dmarc;
  });

  const mx = await mxPromise;
  if (signal?.aborted) return;

  const primaryHost = customHost ?? mx.records[0]?.exchange ?? parsed.domain;
  let primaryIp = mx.records[0]?.ipv4[0] ?? mx.fallbackA[0] ?? (parsed.isIp ? parsed.domain : null);
  if (!primaryIp && primaryHost) {
    const ips = await resolveA(primaryHost);
    primaryIp = ips[0] ?? null;
  }

  const portsResult: PortsModuleResult = {
    status: 'info',
    summary: 'TCP-Portscan benötigt Node.js-Backend (Cloudflare Static Mode)',
    targetHost: primaryHost,
    targetIp: primaryIp,
    openCount: 0,
    ports: [],
    durationMs: 0,
  };
  callbacks.onPorts(portsResult);

  const blPromise = checkBlacklistsDoh(parsed.domain, primaryIp).then((bl) => {
    if (!signal?.aborted) callbacks.onBlacklists(bl);
    return bl;
  });

  const [spf, dkim, dmarc, bl] = await Promise.all([spfPromise, dkimPromise, dmarcPromise, blPromise]);
  if (signal?.aborted) return;

  const recommendations = buildRecommendationsClient(parsed.domain, mx, spf, dkim, dmarc, bl);
  callbacks.onComplete({
    completedAt: new Date().toISOString(),
    totalDurationMs: Date.now() - startTime,
    recommendations,
  });
}
