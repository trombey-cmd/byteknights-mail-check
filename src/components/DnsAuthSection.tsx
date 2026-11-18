import { useState } from 'react';
import { Plus, Search } from 'lucide-react';
import type { DkimSelectorResult, FullCheckReport } from '../types/mailcheck';
import { probeDkimSelectorDoh } from '../lib/dohDiagnostics';
import { StatusIndicator } from './StatusIndicator';
import { CopyButton } from './CopyButton';

interface DnsAuthSectionProps {
  report: FullCheckReport;
  isLoading: boolean;
  backendMode?: 'node' | 'static';
  onAddDkimResult: (result: DkimSelectorResult) => void;
}

function SkeletonBlock() {
  return (
    <div className="space-y-2.5 py-2" aria-busy="true">
      <div className="h-4 w-2/3 animate-pulse rounded bg-slate-200/80 dark:bg-slate-800" />
      <div className="h-4 w-1/2 animate-pulse rounded bg-slate-200/60 dark:bg-slate-800/70" />
    </div>
  );
}

export function DnsAuthSection({ report, isLoading, backendMode = 'node', onAddDkimResult }: DnsAuthSectionProps) {
  const [customSelector, setCustomSelector] = useState('');
  const [probingSelector, setProbingSelector] = useState(false);
  const [probeError, setProbeError] = useState<string | null>(null);

  const handleProbeSelector = async (e: React.FormEvent) => {
    e.preventDefault();
    const sel = customSelector.trim().toLowerCase();
    if (!sel) return;
    if (!/^[a-z0-9._-]{1,63}$/.test(sel)) {
      setProbeError('Ungültiges Selektor-Format.');
      return;
    }
    setProbingSelector(true);
    setProbeError(null);

    try {
      if (backendMode === 'static') {
        const dohResult = await probeDkimSelectorDoh(report.domain, sel);
        onAddDkimResult(dohResult);
        setCustomSelector('');
        return;
      }

      const res = await fetch('/api/dkim/probe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: report.domain, selector: sel }),
      });
      const contentType = res.headers.get('content-type') ?? '';
      if (contentType.includes('application/json')) {
        const data = await res.json();
        if (!res.ok) {
          setProbeError(data.error ?? 'Selektor-Abfrage fehlgeschlagen.');
        } else {
          onAddDkimResult(data as DkimSelectorResult);
          setCustomSelector('');
        }
      } else {
        const dohResult = await probeDkimSelectorDoh(report.domain, sel);
        onAddDkimResult(dohResult);
        setCustomSelector('');
      }
    } catch {
      try {
        const dohResult = await probeDkimSelectorDoh(report.domain, sel);
        onAddDkimResult(dohResult);
        setCustomSelector('');
      } catch {
        setProbeError('Netzwerkfehler bei der DKIM-Abfrage.');
      }
    } finally {
      setProbingSelector(false);
    }
  };

  const mx = report.mx;
  const spf = report.spf;
  const dkim = report.dkim;
  const dmarc = report.dmarc;

  return (
    <div className="space-y-6">
      {/* 1. MX & Reverse DNS */}
      <section
        id="section-mx"
        className="rounded-lg border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900"
      >
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 px-5 py-4 dark:border-slate-800">
          <div>
            <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
              1. MX-Records & Reverse DNS (FCrDNS)
            </h2>
            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
              Zustellende Mail-Exchanger für <span className="font-mono text-slate-700 dark:text-slate-300">{report.domain}</span>
              {mx ? ` · ${mx.durationMs} ms` : ''}
            </p>
          </div>
          <StatusIndicator status={mx?.status ?? (isLoading ? 'pending' : 'info')} label={mx?.summary} />
        </div>

        <div className="p-5">
          {!mx && isLoading ? (
            <SkeletonBlock />
          ) : mx && mx.records.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[680px] text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-200 text-xs font-medium text-slate-500 dark:border-slate-800 dark:text-slate-400">
                    <th className="pb-2.5 pr-4">Prio</th>
                    <th className="pb-2.5 pr-4">Mailserver (Exchange)</th>
                    <th className="pb-2.5 pr-4">IPv4 / IPv6</th>
                    <th className="pb-2.5 pr-4">Reverse DNS (PTR)</th>
                    <th className="pb-2.5 text-right">Latenz</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                  {mx.records.map((rec) => {
                    const ptrSummary = rec.ptr[0];
                    return (
                      <tr key={`${rec.priority}-${rec.exchange}`} className="align-top">
                        <td className="py-3 pr-4 font-mono text-xs font-semibold text-slate-700 tabular-nums dark:text-slate-300">
                          {rec.priority}
                        </td>
                        <td className="py-3 pr-4 font-mono text-xs font-medium text-slate-900 dark:text-slate-100">
                          {rec.exchange}
                        </td>
                        <td className="py-3 pr-4 font-mono text-xs text-slate-600 dark:text-slate-300">
                          <div>{rec.ipv4.length > 0 ? rec.ipv4.join(', ') : 'Keine IPv4'}</div>
                          {rec.ipv6.length > 0 && (
                            <div className="mt-0.5 text-slate-400 dark:text-slate-500">
                              {rec.ipv6.join(', ')}
                            </div>
                          )}
                        </td>
                        <td className="py-3 pr-4 text-xs">
                          {ptrSummary && ptrSummary.hostnames.length > 0 ? (
                            <div className="space-y-0.5">
                              <div className="font-mono text-slate-800 dark:text-slate-200">
                                {ptrSummary.hostnames.join(', ')}
                              </div>
                              <StatusIndicator
                                status={ptrSummary.fcrdnsMatch ? 'ok' : 'warn'}
                                label={ptrSummary.fcrdnsMatch ? 'FCrDNS bestätigt' : 'FCrDNS stimmt nicht überein'}
                              />
                            </div>
                          ) : (
                            <StatusIndicator status="warn" label="Kein PTR-Eintrag" />
                          )}
                        </td>
                        <td className="py-3 text-right font-mono text-xs text-slate-500 tabular-nums dark:text-slate-400">
                          {rec.latencyMs} ms
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-sm text-slate-600 dark:text-slate-400">
              {mx?.fallbackA.length
                ? `Kein expliziter MX-Record gefunden. Fallback über A-Record: ${mx.fallbackA.join(', ')}`
                : mx?.error ?? 'Keine MX-Einträge für diese Domain veröffentlicht.'}
            </div>
          )}
        </div>
      </section>

      {/* 2. SPF */}
      <section
        id="section-spf"
        className="rounded-lg border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900"
      >
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 px-5 py-4 dark:border-slate-800">
          <div>
            <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
              2. SPF (Sender Policy Framework)
            </h2>
            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
              Autorisierte Versandserver & DNS-Lookup-Budget nach RFC 7208
              {spf ? ` · ${spf.durationMs} ms` : ''}
            </p>
          </div>
          <StatusIndicator status={spf?.status ?? (isLoading ? 'pending' : 'info')} label={spf?.summary} />
        </div>

        <div className="space-y-5 p-5">
          {!spf && isLoading ? (
            <SkeletonBlock />
          ) : spf ? (
            <>
              {spf.record ? (
                <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 pb-4 dark:border-slate-800/80">
                  <code className="block max-w-full break-all font-mono text-xs leading-relaxed text-slate-800 dark:text-slate-200">
                    {spf.record}
                  </code>
                  <CopyButton value={spf.record} label="SPF kopieren" />
                </div>
              ) : (
                <p className="text-sm text-red-700 dark:text-red-400">
                  Kein SPF-Record („v=spf1“) gefunden.
                </p>
              )}

              {spf.record && (
                <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
                  {/* Lookup Budget */}
                  <div className="space-y-2.5 lg:col-span-4">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-medium text-slate-700 dark:text-slate-300">
                        Rekursive DNS-Lookups
                      </span>
                      <span
                        className={`font-mono font-semibold tabular-nums ${
                          spf.lookupCount > 10
                            ? 'text-red-700 dark:text-red-400'
                            : spf.lookupCount >= 8
                              ? 'text-amber-700 dark:text-amber-400'
                              : 'text-emerald-700 dark:text-emerald-400'
                        }`}
                      >
                        {spf.lookupCount} / {spf.lookupLimit}
                      </span>
                    </div>
                    <div className="h-2 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                      <div
                        className={`h-full transition-all ${
                          spf.lookupCount > 10
                            ? 'bg-red-600'
                            : spf.lookupCount >= 8
                              ? 'bg-amber-500'
                              : 'bg-emerald-600'
                        }`}
                        style={{ width: `${Math.min(100, (spf.lookupCount / spf.lookupLimit) * 100)}%` }}
                      />
                    </div>
                    {spf.lookupChain.length > 0 && (
                      <ul className="space-y-1 pt-1 text-xs text-slate-500 dark:text-slate-400">
                        {spf.lookupChain.map((node, i) => (
                          <li key={`${node.domain}-${i}`} className="flex items-center justify-between font-mono">
                            <span className="truncate pr-2">
                              {'· '.repeat(node.depth)}
                              {node.domain}
                            </span>
                            <span className="shrink-0 tabular-nums">{node.lookups} Lkp</span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>

                  {/* Mechanisms */}
                  <div className="lg:col-span-8">
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs">
                        <thead>
                          <tr className="border-b border-slate-200 font-medium text-slate-500 dark:border-slate-800 dark:text-slate-400">
                            <th className="pb-2 pr-4">Mechanismus</th>
                            <th className="pb-2 pr-4">Typ</th>
                            <th className="pb-2 pr-4">Wert</th>
                            <th className="pb-2 text-right">DNS-Lookup</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                          {spf.mechanisms.map((mech, idx) => (
                            <tr key={`${mech.raw}-${idx}`}>
                              <td className="py-2 pr-4 font-mono font-medium text-slate-900 dark:text-slate-100">
                                {mech.raw}
                              </td>
                              <td className="py-2 pr-4 text-slate-600 dark:text-slate-400">
                                {mech.type.toUpperCase()}
                              </td>
                              <td className="py-2 pr-4 font-mono text-slate-700 dark:text-slate-300">
                                {mech.value || '—'}
                              </td>
                              <td className="py-2 text-right font-mono text-slate-500 dark:text-slate-400">
                                {mech.causesLookup ? 'Ja (+1)' : 'Nein'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {spf.issues.length > 0 && (
                <ul className="space-y-1.5 border-t border-slate-100 pt-3 text-xs text-amber-800 dark:border-slate-800/80 dark:text-amber-300">
                  {spf.issues.map((issue, idx) => (
                    <li key={idx}>• {issue}</li>
                  ))}
                </ul>
              )}
            </>
          ) : null}
        </div>
      </section>

      {/* 3. DKIM */}
      <section
        id="section-dkim"
        className="rounded-lg border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900"
      >
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 px-5 py-4 dark:border-slate-800">
          <div>
            <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
              3. DKIM (DomainKeys Identified Mail)
            </h2>
            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
              Geprüfte Selektoren: {dkim ? `${dkim.testedSelectors.length} abgefragt · ${dkim.durationMs} ms` : 'Lädt…'}
            </p>
          </div>
          <StatusIndicator status={dkim?.status ?? (isLoading ? 'pending' : 'info')} label={dkim?.summary} />
        </div>

        <div className="space-y-4 p-5">
          {/* Interactive custom selector probe */}
          <form onSubmit={handleProbeSelector} className="flex flex-wrap items-center gap-2">
            <label htmlFor="custom-dkim-selector" className="sr-only">
              Eigenen DKIM-Selektor prüfen
            </label>
            <div className="relative min-w-[240px] flex-1 sm:max-w-xs">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" aria-hidden="true" />
              <input
                id="custom-dkim-selector"
                type="text"
                value={customSelector}
                onChange={(e) => setCustomSelector(e.target.value)}
                placeholder="Eigenen Selektor testen (z. B. mail2026)"
                className="w-full rounded-md border border-slate-200 bg-slate-50 py-1.5 pl-8 pr-3 font-mono text-xs text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100 dark:focus:border-blue-500"
              />
            </div>
            <button
              type="submit"
              disabled={probingSelector || !customSelector.trim()}
              className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-800 transition-colors hover:bg-slate-50 disabled:opacity-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700 whitespace-nowrap shrink-0"
            >
              <Plus className="h-3.5 w-3.5" aria-hidden="true" />
              <span>{probingSelector ? 'Prüfe…' : 'Selektor prüfen'}</span>
            </button>
            {probeError && <span className="text-xs text-red-600 dark:text-red-400">{probeError}</span>}
          </form>

          {!dkim && isLoading ? (
            <SkeletonBlock />
          ) : dkim ? (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[680px] text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-200 font-medium text-slate-500 dark:border-slate-800 dark:text-slate-400">
                    <th className="pb-2.5 pr-4">Selektor</th>
                    <th className="pb-2.5 pr-4">DNS-Ziel</th>
                    <th className="pb-2.5 pr-4">Status</th>
                    <th className="pb-2.5 pr-4">Schlüssel / Typ</th>
                    <th className="pb-2.5 text-right">Public Key Auszug</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                  {dkim.selectors.map((sel) => (
                    <tr key={sel.selector} className="align-top">
                      <td className="py-2.5 pr-4 font-mono font-semibold text-slate-900 dark:text-slate-100">
                        {sel.selector}
                      </td>
                      <td className="py-2.5 pr-4 font-mono text-slate-600 dark:text-slate-400">
                        {sel.fqdn}
                      </td>
                      <td className="py-2.5 pr-4">
                        <StatusIndicator
                          status={sel.found ? sel.status : 'info'}
                          label={sel.found ? 'Gefunden' : 'Nicht gesetzt'}
                        />
                      </td>
                      <td className="py-2.5 pr-4 text-slate-700 dark:text-slate-300">
                        {sel.note}
                      </td>
                      <td className="py-2.5 text-right font-mono text-slate-500 dark:text-slate-400">
                        {sel.publicKeyPreview ? (
                          <div className="inline-flex items-center gap-2">
                            <span>{sel.publicKeyPreview}</span>
                            {sel.record && <CopyButton value={sel.record} label="TXT" />}
                          </div>
                        ) : (
                          '—'
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </div>
      </section>

      {/* 4. DMARC & Transport Security */}
      <section
        id="section-dmarc"
        className="rounded-lg border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900"
      >
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 px-5 py-4 dark:border-slate-800">
          <div>
            <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
              4. DMARC, MTA-STS & TLS-RPT
            </h2>
            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
              Domain-Ausrichtung und Transport-Reporting unter <span className="font-mono">_dmarc.{report.domain}</span>
              {dmarc ? ` · ${dmarc.durationMs} ms` : ''}
            </p>
          </div>
          <StatusIndicator status={dmarc?.status ?? (isLoading ? 'pending' : 'info')} label={dmarc?.summary} />
        </div>

        <div className="space-y-5 p-5">
          {!dmarc && isLoading ? (
            <SkeletonBlock />
          ) : dmarc ? (
            <>
              {dmarc.record ? (
                <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 pb-4 dark:border-slate-800/80">
                  <code className="block max-w-full break-all font-mono text-xs leading-relaxed text-slate-800 dark:text-slate-200">
                    {dmarc.record}
                  </code>
                  <CopyButton value={dmarc.record} label="DMARC kopieren" />
                </div>
              ) : (
                <p className="text-sm text-red-700 dark:text-red-400">
                  Kein DMARC-Record unter <span className="font-mono">_dmarc.{report.domain}</span> vorhanden.
                </p>
              )}

              <div className="grid grid-cols-2 gap-x-6 gap-y-4 text-xs sm:grid-cols-3 lg:grid-cols-6">
                <div>
                  <div className="text-slate-500 dark:text-slate-400">Policy (p)</div>
                  <div className="mt-1 font-mono text-sm font-semibold text-slate-900 dark:text-slate-100">
                    {dmarc.policy ?? '—'}
                  </div>
                </div>
                <div>
                  <div className="text-slate-500 dark:text-slate-400">Subdomain (sp)</div>
                  <div className="mt-1 font-mono text-sm font-semibold text-slate-900 dark:text-slate-100">
                    {dmarc.subdomainPolicy ?? dmarc.policy ?? '—'}
                  </div>
                </div>
                <div>
                  <div className="text-slate-500 dark:text-slate-400">Quote (pct)</div>
                  <div className="mt-1 font-mono text-sm font-semibold text-slate-900 tabular-nums dark:text-slate-100">
                    {dmarc.pct !== null ? `${dmarc.pct}%` : '—'}
                  </div>
                </div>
                <div>
                  <div className="text-slate-500 dark:text-slate-400">DKIM-Ausrichtung</div>
                  <div className="mt-1 font-mono text-sm font-semibold text-slate-900 dark:text-slate-100">
                    {dmarc.adkim === 's' ? 's (strikt)' : dmarc.adkim === 'r' ? 'r (relaxed)' : '—'}
                  </div>
                </div>
                <div>
                  <div className="text-slate-500 dark:text-slate-400">SPF-Ausrichtung</div>
                  <div className="mt-1 font-mono text-sm font-semibold text-slate-900 dark:text-slate-100">
                    {dmarc.aspf === 's' ? 's (strikt)' : dmarc.aspf === 'r' ? 'r (relaxed)' : '—'}
                  </div>
                </div>
                <div>
                  <div className="text-slate-500 dark:text-slate-400">RUA-Berichte</div>
                  <div className="mt-1 truncate font-mono text-xs font-medium text-slate-800 dark:text-slate-200" title={dmarc.rua.join(', ')}>
                    {dmarc.rua.length > 0 ? dmarc.rua.join(', ') : 'Nicht konfiguriert'}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-4 border-t border-slate-100 pt-4 text-xs sm:grid-cols-2 dark:border-slate-800/80">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="font-medium text-slate-800 dark:text-slate-200">MTA-STS (_mta-sts)</div>
                    <div className="mt-0.5 font-mono text-slate-500 dark:text-slate-400">
                      {dmarc.mtaSts.found ? dmarc.mtaSts.record : 'Kein _mta-sts TXT-Record'}
                    </div>
                  </div>
                  <StatusIndicator
                    status={dmarc.mtaSts.found ? 'ok' : 'info'}
                    label={dmarc.mtaSts.found ? 'Aktiv' : 'Optional'}
                  />
                </div>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="font-medium text-slate-800 dark:text-slate-200">SMTP TLS-RPT (_smtp._tls)</div>
                    <div className="mt-0.5 font-mono text-slate-500 dark:text-slate-400">
                      {dmarc.tlsRpt.found ? dmarc.tlsRpt.record : 'Kein _smtp._tls TXT-Record'}
                    </div>
                  </div>
                  <StatusIndicator
                    status={dmarc.tlsRpt.found ? 'ok' : 'info'}
                    label={dmarc.tlsRpt.found ? 'Aktiv' : 'Optional'}
                  />
                </div>
              </div>

              {dmarc.issues.length > 0 && (
                <ul className="space-y-1.5 border-t border-slate-100 pt-3 text-xs text-amber-800 dark:border-slate-800/80 dark:text-amber-300">
                  {dmarc.issues.map((issue, idx) => (
                    <li key={idx}>• {issue}</li>
                  ))}
                </ul>
              )}
            </>
          ) : null}
        </div>
      </section>
    </div>
  );
}
