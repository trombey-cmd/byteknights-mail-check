import { Resolver } from 'node:dns/promises';
import net from 'node:net';
import tls from 'node:tls';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import express from 'express';
import dotenv from 'dotenv';
import type {
  BlacklistEntryResult,
  BlacklistModuleResult,
  CheckSeverity,
  DkimModuleResult,
  DkimSelectorResult,
  DmarcModuleResult,
  MxModuleResult,
  MxRecordResult,
  PortCheckResult,
  PortsModuleResult,
  PtrCheck,
  RecommendationItem,
  SpfLookupNode,
  SpfMechanism,
  SpfModuleResult,
  TlsDetails,
} from './src/types/mailcheck.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

function createResolver(): Resolver {
  const resolver = new Resolver({ timeout: 3500, tries: 1 });
  return resolver;
}

function normalizeTarget(rawInput: string): { domain: string; customHost: string | null; isIp: boolean } {
  let cleaned = rawInput.trim().toLowerCase();
  cleaned = cleaned.replace(/^https?:\/\//, '');
  cleaned = cleaned.split('/')[0] ?? cleaned;
  cleaned = cleaned.split('?')[0] ?? cleaned;

  if (cleaned.includes('@')) {
    const parts = cleaned.split('@');
    cleaned = parts[parts.length - 1] ?? cleaned;
  }

  cleaned = cleaned.replace(/:\d+$/, '').replace(/\.+$/, '');

  const isIp = net.isIP(cleaned) !== 0;
  return {
    domain: cleaned,
    customHost: null,
    isIp,
  };
}

function isValidDomainOrHost(value: string): boolean {
  if (!value || value.length > 253) return false;
  if (net.isIP(value) !== 0) return true;
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(value);
}

function isPrivateOrReservedIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return true;
    const [a, b] = parts;
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b !== undefined && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b !== undefined && b >= 64 && b <= 127) return true;
    if (a >= 224) return true;
    return false;
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '::' || lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd')) {
      return true;
    }
    return false;
  }
  return true;
}

async function resolveSafe<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await fn();
  } catch {
    return fallback;
  }
}

async function checkMx(domain: string): Promise<MxModuleResult> {
  const start = Date.now();
  const resolver = createResolver();

  try {
    const rawMx = await resolver.resolveMx(domain);
    const sorted = [...rawMx].sort((a, b) => a.priority - b.priority);

    if (sorted.length === 0) {
      const fallbackA = await resolveSafe(() => resolver.resolve4(domain), []);
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
      sorted.map(async (mx) => {
        const mxStart = Date.now();
        const exchange = mx.exchange.replace(/\.+$/, '').toLowerCase();
        const [ipv4, ipv6] = await Promise.all([
          resolveSafe(() => resolver.resolve4(exchange), []),
          resolveSafe(() => resolver.resolve6(exchange), []),
        ]);

        const ptrChecks: PtrCheck[] = await Promise.all(
          ipv4.slice(0, 2).map(async (ip) => {
            const hostnames = await resolveSafe(() => resolver.reverse(ip), []);
            const normalizedHosts = hostnames.map((h) => h.replace(/\.+$/, '').toLowerCase());
            let fcrdnsMatch = false;
            if (normalizedHosts.length > 0) {
              for (const ptrHost of normalizedHosts) {
                const forwardIps = await resolveSafe(() => resolver.resolve4(ptrHost), []);
                if (forwardIps.includes(ip)) {
                  fcrdnsMatch = true;
                  break;
                }
              }
            }
            return {
              ip,
              hostnames: normalizedHosts,
              fcrdnsMatch,
            };
          })
        );

        return {
          exchange,
          priority: mx.priority,
          ipv4,
          ipv6,
          ptr: ptrChecks,
          latencyMs: Date.now() - mxStart,
        };
      })
    );

    const hasMissingA = records.some((r) => r.ipv4.length === 0 && r.ipv6.length === 0);
    const hasMissingPtr = records.some((r) => r.ptr.some((p) => p.hostnames.length === 0 || !p.fcrdnsMatch));
    const singleMx = records.length === 1;

    let status: CheckSeverity = 'ok';
    let summary = `${records.length} MX-Server aufgelöst`;

    if (hasMissingA) {
      status = 'error';
      summary = 'MX-Ziel ohne gültige IP-Adresse';
    } else if (hasMissingPtr) {
      status = 'warn';
      summary = `${records.length} MX-Server · PTR/FCrDNS unvollständig`;
    } else if (singleMx) {
      status = 'ok';
      summary = '1 MX-Server mit gültigem FCrDNS';
    } else {
      summary = `${records.length} MX-Server · FCrDNS gültig`;
    }

    return {
      status,
      summary,
      records,
      fallbackA: [],
      durationMs: Date.now() - start,
    };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    const fallbackA = await resolveSafe(() => resolver.resolve4(domain), []);
    if (fallbackA.length > 0 && (code === 'ENODATA' || code === 'ENOTFOUND')) {
      return {
        status: 'warn',
        summary: 'Kein MX-Record, A-Record Fallback aktiv',
        records: [],
        fallbackA,
        durationMs: Date.now() - start,
      };
    }

    return {
      status: 'error',
      summary: code === 'ENOTFOUND' ? 'Domain nicht auflösbar (NXDOMAIN)' : 'MX-Abfrage fehlgeschlagen',
      records: [],
      fallbackA: [],
      durationMs: Date.now() - start,
      error: (err as Error).message,
    };
  }
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

    const causesLookup = ['include', 'a', 'mx', 'ptr', 'exists', 'redirect'].includes(type);
    return {
      raw,
      qualifier,
      type,
      value,
      causesLookup,
    };
  });
}

async function countSpfLookups(
  domain: string,
  resolver: Resolver,
  visited: Set<string>,
  depth: number,
  chain: SpfLookupNode[]
): Promise<{ lookups: number; record: string | null; allRecords: string[] }> {
  if (depth > 8 || visited.has(domain.toLowerCase())) {
    return { lookups: 0, record: null, allRecords: [] };
  }
  visited.add(domain.toLowerCase());

  const txtChunks = await resolveSafe(() => resolver.resolveTxt(domain), []);
  const txtStrings = txtChunks.map((chunks) => chunks.join(''));
  const spfRecords = txtStrings.filter((t) => /^v=spf1(\s|$)/i.test(t.trim()));

  if (spfRecords.length === 0) {
    return { lookups: 0, record: null, allRecords: [] };
  }

  const primary = spfRecords[0] ?? null;
  if (!primary) {
    return { lookups: 0, record: null, allRecords: spfRecords };
  }

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
        const sub = await countSpfLookups(targetDomain, resolver, visited, depth + 1, chain);
        totalLookups += sub.lookups;
      }
    }
  }

  return { lookups: totalLookups, record: primary, allRecords: spfRecords };
}

async function checkSpf(domain: string): Promise<SpfModuleResult> {
  const start = Date.now();
  const resolver = createResolver();
  const chain: SpfLookupNode[] = [];
  const visited = new Set<string>();

  const { lookups, record, allRecords } = await countSpfLookups(domain, resolver, visited, 0, chain);
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
    issues.push(`DNS-Lookup-Limit überschritten: ${lookups} von maximal 10 erlaubten Lookups (PermError-Risiko).`);
  } else if (lookups >= 8) {
    issues.push(`Hohe Anzahl an DNS-Lookups (${lookups}/10). Erweiterungen könnten das Limit sprengen.`);
  }

  let status: CheckSeverity = 'ok';
  if (allRecords.length > 1 || allQualifier === '+all' || lookups > 10) {
    status = 'error';
  } else if (issues.length > 0 || allQualifier === '~all' || !allQualifier) {
    status = issues.length > 0 ? 'warn' : 'ok';
  }

  const summaryParts: string[] = [];
  if (allQualifier) summaryParts.push(allQualifier);
  summaryParts.push(`${lookups}/10 Lookups`);

  return {
    status,
    summary: summaryParts.join(' · '),
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

function estimateDkimKeyBits(publicKeyBase64: string, keyType: string | null): number | null {
  try {
    const clean = publicKeyBase64.replace(/\s+/g, '');
    if (!clean) return null;
    const buf = Buffer.from(clean, 'base64');
    if (keyType?.toLowerCase() === 'ed25519') {
      return buf.length * 8;
    }
    // SubjectPublicKeyInfo RSA DER overhead is typically 24-38 bytes
    if (buf.length >= 500) return 4096;
    if (buf.length >= 250) return 2048;
    if (buf.length >= 130) return 1024;
    if (buf.length >= 70) return 512;
    return buf.length * 8;
  } catch {
    return null;
  }
}

async function probeSingleDkimSelector(domain: string, selector: string, resolver: Resolver): Promise<DkimSelectorResult> {
  const cleanSelector = selector.trim().toLowerCase();
  const fqdn = `${cleanSelector}._domainkey.${domain}`;
  const txtChunks = await resolveSafe(() => resolver.resolveTxt(fqdn), []);

  if (txtChunks.length === 0) {
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

  const rawRecord = txtChunks.map((c) => c.join('')).join(' ');
  const tags: Record<string, string> = {};
  for (const part of rawRecord.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx > 0) {
      const k = trimmed.slice(0, eqIdx).trim().toLowerCase();
      const v = trimmed.slice(eqIdx + 1).trim();
      tags[k] = v;
    }
  }

  const version = tags['v'] ?? 'DKIM1';
  const keyType = tags['k'] ?? 'rsa';
  const pubKey = tags['p'] ?? '';
  const revoked = 'p' in tags && pubKey.length === 0;
  const flags = tags['t'] ? tags['t'].split(':').map((f) => f.trim()).filter(Boolean) : [];
  const keyBits = pubKey ? estimateDkimKeyBits(pubKey, keyType) : null;
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

async function checkDkim(domain: string, customSelectors: string[]): Promise<DkimModuleResult> {
  const start = Date.now();
  const resolver = createResolver();
  const merged = Array.from(
    new Set([
      ...customSelectors.map((s) => s.trim().toLowerCase()).filter(Boolean),
      ...DEFAULT_DKIM_SELECTORS,
    ])
  );

  const wildcardProbeName = `__wc_${crypto.randomBytes(3).toString('hex')}`;
  const [wildcardProbe, results] = await Promise.all([
    probeSingleDkimSelector(domain, wildcardProbeName, resolver),
    Promise.all(merged.map((sel) => probeSingleDkimSelector(domain, sel, resolver))),
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
    summary = wildcardRecord && distinctFound.length === 0
      ? `Wildcard-DKIM aktiv (*._domainkey)`
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

async function checkDmarc(domain: string): Promise<DmarcModuleResult> {
  const start = Date.now();
  const resolver = createResolver();

  const [dmarcChunks, mtaStsChunks, tlsRptChunks] = await Promise.all([
    resolveSafe(() => resolver.resolveTxt(`_dmarc.${domain}`), []),
    resolveSafe(() => resolver.resolveTxt(`_mta-sts.${domain}`), []),
    resolveSafe(() => resolver.resolveTxt(`_smtp._tls.${domain}`), []),
  ]);

  const dmarcStrings = dmarcChunks.map((c) => c.join(''));
  const dmarcRecord = dmarcStrings.find((s) => /^v=DMARC1/i.test(s.trim())) ?? null;

  const mtaStsRecord = mtaStsChunks.map((c) => c.join('')).find((s) => /v=STSv1/i.test(s)) ?? null;
  const mtaStsIdMatch = mtaStsRecord?.match(/id=([^;\s]+)/i);

  const tlsRptRecord = tlsRptChunks.map((c) => c.join('')).find((s) => /v=TLSRPTv1/i.test(s)) ?? null;
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
  if (!policy) {
    issues.push('Pflicht-Tag „p=“ fehlt im DMARC-Record.');
  } else if (policy === 'none') {
    issues.push('Policy steht auf „p=none“ (nur Beobachtung, keine Ablehnung gefälschter Mails).');
  }

  if (rua.length === 0) {
    issues.push('Keine „rua=“-Adresse für aggregierte DMARC-Berichte hinterlegt.');
  }

  if (pct !== null && pct < 100) {
    issues.push(`Policy greift aktuell nur für ${pct}% der Nachrichten (pct=${pct}).`);
  }

  let status: CheckSeverity = 'ok';
  if (!policy) {
    status = 'error';
  } else if (policy === 'none' || issues.length > 0) {
    status = 'warn';
  }

  const summary = policy
    ? `p=${policy}${rua.length > 0 ? ' · Reporting aktiv' : ' · Ohne rua'}`
    : 'Ungültige DMARC-Syntax';

  return {
    status,
    summary,
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

function extractTlsDetails(socket: tls.TLSSocket): TlsDetails {
  const cipher = socket.getCipher();
  const cert = socket.getPeerCertificate();
  let daysRemaining: number | null = null;
  let validTo: string | null = null;

  if (cert?.valid_to) {
    const exp = new Date(cert.valid_to);
    if (!Number.isNaN(exp.getTime())) {
      validTo = exp.toISOString();
      daysRemaining = Math.floor((exp.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
    }
  }

  const rawIssuer = cert?.issuer?.O ?? cert?.issuer?.CN ?? null;
  const issuer = Array.isArray(rawIssuer) ? (rawIssuer[0] ?? null) : rawIssuer;

  return {
    protocol: socket.getProtocol(),
    cipher: cipher?.name ?? null,
    subject: cert?.subject?.CN ? (Array.isArray(cert.subject.CN) ? (cert.subject.CN[0] ?? null) : cert.subject.CN) : null,
    issuer,
    validTo,
    daysRemaining,
    authorized: socket.authorized,
  };
}

function probePlainPortWithStartTls(
  host: string,
  port: number,
  service: string,
  protocol: PortCheckResult['protocol']
): Promise<PortCheckResult> {
  return new Promise((resolve) => {
    const start = Date.now();
    let settled = false;
    let stage: 'greeting' | 'ehlo' | 'starttls' | 'imap_cap' = 'greeting';
    let buffer = '';
    let banner: string | null = null;
    const ehloCapabilities: string[] = [];
    let startTlsSupported = false;

    const socket = net.createConnection({ host, port });
    socket.setTimeout(3500);

    const finish = (result: PortCheckResult) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        // ignore
      }
      resolve(result);
    };

    socket.on('timeout', () => {
      finish({
        port,
        service,
        protocol,
        state: 'timeout',
        status: port === 25 ? 'warn' : 'info',
        latencyMs: null,
        banner,
        ehloCapabilities,
        startTlsSupported,
        tlsActive: false,
        tlsInfo: null,
        note: 'Zeitüberschreitung (gefiltert oder Firewall)',
      });
    });

    socket.on('error', (err) => {
      const code = (err as NodeJS.ErrnoException).code;
      finish({
        port,
        service,
        protocol,
        state: code === 'ECONNREFUSED' ? 'closed' : 'error',
        status: port === 25 ? 'error' : 'info',
        latencyMs: null,
        banner: null,
        ehloCapabilities: [],
        startTlsSupported: false,
        tlsActive: false,
        tlsInfo: null,
        note: code === 'ECONNREFUSED' ? 'Verbindung abgelehnt (Port geschlossen)' : err.message,
      });
    });

    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      const lines = buffer.split(/\r?\n/);

      if (protocol === 'IMAP') {
        const firstLine = lines[0]?.trim();
        if (firstLine && stage === 'greeting') {
          banner = firstLine.slice(0, 140);
          stage = 'imap_cap';
          buffer = '';
          socket.write('a1 CAPABILITY\r\n');
          return;
        }
        if (stage === 'imap_cap' && buffer.includes('a1 OK')) {
          const caps = buffer.match(/\* CAPABILITY ([^\r\n]+)/i)?.[1]?.split(/\s+/) ?? [];
          startTlsSupported = caps.some((c) => c.toUpperCase() === 'STARTTLS');
          try {
            socket.write('a2 LOGOUT\r\n');
          } catch {
            // ignore
          }
          finish({
            port,
            service,
            protocol,
            state: 'open',
            status: startTlsSupported ? 'ok' : 'warn',
            latencyMs: Date.now() - start,
            banner,
            ehloCapabilities: caps.slice(0, 10),
            startTlsSupported,
            tlsActive: false,
            tlsInfo: null,
            note: startTlsSupported ? 'Offen · STARTTLS unterstützt' : 'Offen · Kein STARTTLS erkannt',
          });
        }
        return;
      }

      // SMTP / Submission
      if (stage === 'greeting') {
        const readyLine = lines.find((l) => /^220\s/.test(l));
        if (readyLine) {
          banner = readyLine.trim().slice(0, 160);
          stage = 'ehlo';
          buffer = '';
          socket.write('EHLO mailtest.local\r\n');
        }
        return;
      }

      if (stage === 'ehlo') {
        const complete = lines.some((l) => /^250\s/.test(l));
        if (complete) {
          for (const l of lines) {
            const match = l.match(/^250[- ](.+)$/);
            if (match?.[1]) {
              const cap = match[1].trim();
              if (!ehloCapabilities.includes(cap)) {
                ehloCapabilities.push(cap);
              }
            }
          }
          startTlsSupported = ehloCapabilities.some((c) => c.toUpperCase().startsWith('STARTTLS'));

          if (startTlsSupported) {
            stage = 'starttls';
            buffer = '';
            socket.write('STARTTLS\r\n');
          } else {
            try {
              socket.write('QUIT\r\n');
            } catch {
              // ignore
            }
            finish({
              port,
              service,
              protocol,
              state: 'open',
              status: 'warn',
              latencyMs: Date.now() - start,
              banner,
              ehloCapabilities: ehloCapabilities.slice(0, 10),
              startTlsSupported: false,
              tlsActive: false,
              tlsInfo: null,
              note: 'Offen · STARTTLS wird nicht angekündigt',
            });
          }
        }
        return;
      }

      if (stage === 'starttls') {
        const tlsReady = lines.find((l) => /^220\s/.test(l));
        if (tlsReady) {
          socket.removeAllListeners('data');
          socket.removeAllListeners('timeout');
          socket.removeAllListeners('error');

          const tlsSocket = tls.connect(
            {
              socket,
              servername: host,
              rejectUnauthorized: false,
            },
            () => {
              const tlsInfo = extractTlsDetails(tlsSocket);
              try {
                tlsSocket.write('QUIT\r\n');
              } catch {
                // ignore
              }
              if (!settled) {
                settled = true;
                tlsSocket.destroy();
                const certStatus: CheckSeverity =
                  tlsInfo.daysRemaining !== null && tlsInfo.daysRemaining < 14
                    ? 'warn'
                    : tlsInfo.authorized === false
                      ? 'warn'
                      : 'ok';
                resolve({
                  port,
                  service,
                  protocol,
                  state: 'open',
                  status: certStatus,
                  latencyMs: Date.now() - start,
                  banner,
                  ehloCapabilities: ehloCapabilities.slice(0, 10),
                  startTlsSupported: true,
                  tlsActive: true,
                  tlsInfo,
                  note: `Offen · STARTTLS (${tlsInfo.protocol ?? 'TLS'})`,
                });
              }
            }
          );

          tlsSocket.setTimeout(3000);
          tlsSocket.on('timeout', () => {
            if (!settled) {
              settled = true;
              tlsSocket.destroy();
              resolve({
                port,
                service,
                protocol,
                state: 'open',
                status: 'warn',
                latencyMs: Date.now() - start,
                banner,
                ehloCapabilities: ehloCapabilities.slice(0, 10),
                startTlsSupported: true,
                tlsActive: false,
                tlsInfo: null,
                note: 'Offen · STARTTLS-Handshake Timeout',
              });
            }
          });
          tlsSocket.on('error', () => {
            if (!settled) {
              settled = true;
              tlsSocket.destroy();
              resolve({
                port,
                service,
                protocol,
                state: 'open',
                status: 'warn',
                latencyMs: Date.now() - start,
                banner,
                ehloCapabilities: ehloCapabilities.slice(0, 10),
                startTlsSupported: true,
                tlsActive: false,
                tlsInfo: null,
                note: 'Offen · STARTTLS-Handshake fehlgeschlagen',
              });
            }
          });
        }
      }
    });
  });
}

function probeImplicitTlsPort(
  host: string,
  port: number,
  service: string,
  protocol: PortCheckResult['protocol']
): Promise<PortCheckResult> {
  return new Promise((resolve) => {
    const start = Date.now();
    let settled = false;
    let banner: string | null = null;
    let tlsInfo: TlsDetails | null = null;

    const tlsSocket = tls.connect({
      host,
      port,
      servername: host,
      rejectUnauthorized: false,
    });
    tlsSocket.setTimeout(3500);

    const finish = (result: PortCheckResult) => {
      if (settled) return;
      settled = true;
      try {
        tlsSocket.destroy();
      } catch {
        // ignore
      }
      resolve(result);
    };

    tlsSocket.on('secureConnect', () => {
      tlsInfo = extractTlsDetails(tlsSocket);
      // Wait briefly for greeting banner (220, * OK, +OK)
      setTimeout(() => {
        if (!settled) {
          finish({
            port,
            service,
            protocol,
            state: 'open',
            status: tlsInfo?.authorized === false ? 'warn' : 'ok',
            latencyMs: Date.now() - start,
            banner,
            ehloCapabilities: [],
            startTlsSupported: false,
            tlsActive: true,
            tlsInfo,
            note: `Offen · ${tlsInfo?.protocol ?? 'TLS'} aktiv`,
          });
        }
      }, 650);
    });

    tlsSocket.on('data', (chunk) => {
      const line = chunk.toString('utf8').split(/\r?\n/)[0]?.trim();
      if (line && !banner) {
        banner = line.slice(0, 160);
        if (tlsInfo) {
          finish({
            port,
            service,
            protocol,
            state: 'open',
            status: tlsInfo.authorized === false ? 'warn' : 'ok',
            latencyMs: Date.now() - start,
            banner,
            ehloCapabilities: [],
            startTlsSupported: false,
            tlsActive: true,
            tlsInfo,
            note: `Offen · ${tlsInfo.protocol ?? 'TLS'} aktiv`,
          });
        }
      }
    });

    tlsSocket.on('timeout', () => {
      finish({
        port,
        service,
        protocol,
        state: 'timeout',
        status: 'info',
        latencyMs: null,
        banner: null,
        ehloCapabilities: [],
        startTlsSupported: false,
        tlsActive: false,
        tlsInfo: null,
        note: 'Zeitüberschreitung (gefiltert oder nicht genutzt)',
      });
    });

    tlsSocket.on('error', (err) => {
      const code = (err as NodeJS.ErrnoException).code;
      finish({
        port,
        service,
        protocol,
        state: code === 'ECONNREFUSED' ? 'closed' : 'error',
        status: 'info',
        latencyMs: null,
        banner: null,
        ehloCapabilities: [],
        startTlsSupported: false,
        tlsActive: false,
        tlsInfo: null,
        note: code === 'ECONNREFUSED' ? 'Geschlossen (nicht aktiv)' : err.message,
      });
    });
  });
}

async function checkPorts(targetHost: string | null): Promise<PortsModuleResult> {
  const start = Date.now();
  if (!targetHost) {
    return {
      status: 'error',
      summary: 'Kein Ziel-Host für Port-Prüfung verfügbar',
      targetHost: null,
      targetIp: null,
      openCount: 0,
      ports: [],
      durationMs: 0,
    };
  }

  const resolver = createResolver();
  let targetIp: string | null = net.isIP(targetHost) !== 0 ? targetHost : null;
  if (!targetIp) {
    const ips = await resolveSafe(() => resolver.resolve4(targetHost), []);
    targetIp = ips[0] ?? null;
  }

  if (targetIp && isPrivateOrReservedIp(targetIp)) {
    return {
      status: 'error',
      summary: 'Private oder reservierte IP-Adressen sind für Port-Scans gesperrt',
      targetHost,
      targetIp,
      openCount: 0,
      ports: [],
      durationMs: Date.now() - start,
    };
  }

  const probes = await Promise.all([
    probePlainPortWithStartTls(targetHost, 25, 'SMTP (Eingehend)', 'SMTP'),
    probeImplicitTlsPort(targetHost, 465, 'SMTPS (Implizites TLS)', 'SMTPS'),
    probePlainPortWithStartTls(targetHost, 587, 'SMTP Submission', 'Submission'),
    probePlainPortWithStartTls(targetHost, 143, 'IMAP (STARTTLS)', 'IMAP'),
    probeImplicitTlsPort(targetHost, 993, 'IMAPS (TLS)', 'IMAPS'),
    probeImplicitTlsPort(targetHost, 995, 'POP3S (TLS)', 'POP3S'),
  ]);

  const openCount = probes.filter((p) => p.state === 'open').length;
  const smtp25 = probes.find((p) => p.port === 25);
  const anyTlsOpen = probes.some((p) => p.state === 'open' && p.tlsActive);

  let status: CheckSeverity = 'ok';
  let summary = `${openCount} von ${probes.length} Ports erreichbar`;

  if (openCount === 0) {
    status = 'warn';
    summary = 'Keine Mail-Ports erreichbar (evtl. Firewall-Filter)';
  } else if (smtp25?.state === 'open' && !smtp25.startTlsSupported) {
    status = 'warn';
    summary = `${openCount}/6 Ports offen · Port 25 ohne STARTTLS`;
  } else if (anyTlsOpen) {
    summary = `${openCount}/6 Ports offen · TLS aktiv`;
  }

  return {
    status,
    summary,
    targetHost,
    targetIp,
    openCount,
    ports: probes,
    durationMs: Date.now() - start,
  };
}

async function checkBlacklists(domain: string, ip: string | null): Promise<BlacklistModuleResult> {
  const start = Date.now();
  const resolver = createResolver();

  const reversedIp = ip && net.isIPv4(ip) ? ip.split('.').reverse().join('.') : null;

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

      try {
        const answers = await resolver.resolve4(queryHost);
        const code = answers[0] ?? null;

        // Spamhaus returns 127.255.255.252/254/255 when queried via open public DNS resolvers
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
            txtReason: 'Abfrage über öffentlichen Resolver vom RBL-Betreiber gedrosselt',
            latencyMs: Date.now() - rblStart,
          };
        }

        const txtChunks = await resolveSafe(() => resolver.resolveTxt(queryHost), []);
        const txtReason = txtChunks.map((c) => c.join('')).join(' | ') || null;

        return {
          id: rbl.id,
          name: rbl.name,
          zone: rbl.zone,
          queryType: rbl.queryType,
          queryTarget: queryHost,
          state: 'listed',
          status: 'error',
          returnCode: code,
          txtReason,
          latencyMs: Date.now() - rblStart,
        };
      } catch (err) {
        const code = (err as NodeJS.ErrnoException)?.code;
        if (code === 'ENOTFOUND' || code === 'ENODATA') {
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
          txtReason: code ?? 'DNS-Timeout',
          latencyMs: Date.now() - rblStart,
        };
      }
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

function buildRecommendations(
  domain: string,
  mx: MxModuleResult,
  spf: SpfModuleResult,
  dkim: DkimModuleResult,
  dmarc: DmarcModuleResult,
  ports: PortsModuleResult,
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
      description: 'Mindestens eine MX-IP besitzt keinen vorwärts-bestätigten PTR-Eintrag. Viele Empfänger-Server lehnen Mails ohne gültiges FCrDNS ab.',
    });
  }

  if (!spf.record) {
    recs.push({
      id: 'spf-missing',
      module: 'SPF',
      severity: 'error',
      title: 'SPF-Record veröffentlichen',
      description: 'Legen Sie einen TXT-Eintrag für autorisierte Versandserver an, um Absender-Spoofing zu verhindern.',
      suggestedRecord: `v=spf1 mx -all`,
    });
  } else if (spf.allQualifier === '~all' || spf.allQualifier === '?all' || spf.allQualifier === '+all') {
    recs.push({
      id: 'spf-all',
      module: 'SPF',
      severity: spf.allQualifier === '+all' ? 'error' : 'warn',
      title: `SPF-Abschluss von „${spf.allQualifier}“ auf „-all“ verschärfen`,
      description: 'Ein hartes „-all“ (Fail) weist unautorisierte Server eindeutig ab, sobald alle legitimen Sender enthalten sind.',
    });
  }

  if (spf.lookupCount > 10) {
    recs.push({
      id: 'spf-lookups',
      module: 'SPF',
      severity: 'error',
      title: 'SPF DNS-Lookups unter 10 reduzieren',
      description: `Aktuell benötigt Ihr SPF-Record ${spf.lookupCount} Lookups. Entfernen Sie nicht genutzte „include:“-Einträge oder nutzen Sie direkte ip4/ip6-Angaben.`,
    });
  }

  if (dkim.foundCount === 0) {
    recs.push({
      id: 'dkim-none',
      module: 'DKIM',
      severity: 'warn',
      title: 'DKIM-Selektor prüfen oder aktivieren',
      description: 'Keiner der Standard-Selektoren lieferte einen öffentlichen DKIM-Schlüssel. Falls Sie einen individuellen Selektor nutzen, testen Sie diesen oben direkt.',
    });
  }

  if (!dmarc.record) {
    recs.push({
      id: 'dmarc-missing',
      module: 'DMARC',
      severity: 'error',
      title: 'DMARC-Richtlinie anlegen',
      description: 'Veröffentlichen Sie einen _dmarc TXT-Record, um SPF/DKIM-Ausrichtung zu erzwingen und Zustellberichte zu erhalten.',
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

  const smtp25 = ports.ports.find((p) => p.port === 25);
  if (smtp25?.state === 'open' && !smtp25.startTlsSupported) {
    recs.push({
      id: 'port25-tls',
      module: 'Ports',
      severity: 'warn',
      title: 'STARTTLS auf Port 25 aktivieren',
      description: 'Der SMTP-Server auf Port 25 kündigt derzeit kein STARTTLS für Transportverschlüsselung an.',
    });
  }

  if (blacklists.listedCount > 0) {
    recs.push({
      id: 'rbl-listed',
      module: 'Blacklists',
      severity: 'error',
      title: 'Blacklist-Eintragung beheben (Delisting)',
      description: `Es wurden ${blacklists.listedCount} Listungen gefunden. Prüfen Sie ausgehende Mail-Logs auf kompromittierte Konten und beantragen Sie anschließend ein Delisting.`,
    });
  }

  return recs;
}

async function startServer() {
  const app = express();
  app.use(express.json());

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, timestamp: new Date().toISOString() });
  });

  app.get('/api/check/stream', async (req, res) => {
    const rawTarget = String(req.query.target ?? '').trim();
    const rawSelectors = String(req.query.selectors ?? '').trim();
    const rawCustomHost = String(req.query.host ?? '').trim();

    const parsed = normalizeTarget(rawTarget);
    if (!parsed.domain || !isValidDomainOrHost(parsed.domain)) {
      res.status(400).json({ error: 'Bitte geben Sie eine gültige Domain, E-Mail-Adresse oder einen Hostnamen ein.' });
      return;
    }

    const customSelectors = rawSelectors
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter((s) => /^[a-z0-9._-]{1,63}$/.test(s));

    const customHost = rawCustomHost && isValidDomainOrHost(rawCustomHost) ? rawCustomHost : null;

    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    let closed = false;
    req.on('close', () => {
      closed = true;
    });

    const sendEvent = (event: string, data: unknown) => {
      if (closed) return;
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    const startTime = Date.now();
    const checkId = crypto.randomUUID();

    sendEvent('init', {
      id: checkId,
      input: rawTarget,
      domain: parsed.domain,
      customHost,
      customSelectors,
      startedAt: new Date(startTime).toISOString(),
    });

    const mxPromise = checkMx(parsed.domain).then((mxResult) => {
      sendEvent('mx', mxResult);
      return mxResult;
    });

    const spfPromise = checkSpf(parsed.domain).then((spfResult) => {
      sendEvent('spf', spfResult);
      return spfResult;
    });

    const dkimPromise = checkDkim(parsed.domain, customSelectors).then((dkimResult) => {
      sendEvent('dkim', dkimResult);
      return dkimResult;
    });

    const dmarcPromise = checkDmarc(parsed.domain).then((dmarcResult) => {
      sendEvent('dmarc', dmarcResult);
      return dmarcResult;
    });

    const mxResult = await mxPromise;

    const primaryHost = customHost ?? mxResult.records[0]?.exchange ?? (parsed.isIp ? parsed.domain : null) ?? parsed.domain;
    let primaryIp = mxResult.records[0]?.ipv4[0] ?? mxResult.fallbackA[0] ?? (parsed.isIp ? parsed.domain : null);

    if (!primaryIp && primaryHost) {
      const resolver = createResolver();
      const ips = await resolveSafe(() => resolver.resolve4(primaryHost), []);
      primaryIp = ips[0] ?? null;
    }

    const portsPromise = checkPorts(primaryHost).then((portsResult) => {
      sendEvent('ports', portsResult);
      return portsResult;
    });

    const blacklistsPromise = checkBlacklists(parsed.domain, primaryIp).then((blResult) => {
      sendEvent('blacklists', blResult);
      return blResult;
    });

    const [spfResult, dkimResult, dmarcResult, portsResult, blResult] = await Promise.all([
      spfPromise,
      dkimPromise,
      dmarcPromise,
      portsPromise,
      blacklistsPromise,
    ]);

    const recommendations = buildRecommendations(
      parsed.domain,
      mxResult,
      spfResult,
      dkimResult,
      dmarcResult,
      portsResult,
      blResult
    );

    sendEvent('complete', {
      completedAt: new Date().toISOString(),
      totalDurationMs: Date.now() - startTime,
      recommendations,
    });

    res.end();
  });

  app.post('/api/dkim/probe', async (req, res) => {
    const domain = normalizeTarget(String(req.body?.domain ?? '')).domain;
    const selector = String(req.body?.selector ?? '').trim().toLowerCase();

    if (!isValidDomainOrHost(domain) || !/^[a-z0-9._-]{1,63}$/.test(selector)) {
      res.status(400).json({ error: 'Ungültige Domain oder ungültiger Selektor.' });
      return;
    }

    const resolver = createResolver();
    const result = await probeSingleDkimSelector(domain, selector, resolver);
    res.json(result);
  });

  app.post('/api/ports/probe', async (req, res) => {
    const host = normalizeTarget(String(req.body?.host ?? '')).domain;
    if (!isValidDomainOrHost(host)) {
      res.status(400).json({ error: 'Ungültiger Hostname oder ungültige IP-Adresse.' });
      return;
    }

    const result = await checkPorts(host);
    res.json(result);
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const port = Number(process.env.PORT ?? 3000);
  app.listen(port, '0.0.0.0', () => {
    console.log(`Mail Prüfsystem listening on http://0.0.0.0:${port}`);
  });
}

startServer();
