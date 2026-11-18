import { useState } from 'react';
import { RefreshCw, Server } from 'lucide-react';
import type { PortsModuleResult } from '../types/mailcheck';
import { StatusIndicator } from './StatusIndicator';

interface PortsSectionProps {
  ports: PortsModuleResult | null;
  domain: string;
  isLoading: boolean;
  backendMode?: 'node' | 'static';
  onUpdatePorts: (next: PortsModuleResult) => void;
}

export function PortsSection({ ports, domain, isLoading, backendMode = 'node', onUpdatePorts }: PortsSectionProps) {
  const [customHost, setCustomHost] = useState('');
  const [probing, setProbing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleProbeHost = async (e: React.FormEvent) => {
    e.preventDefault();
    const target = customHost.trim();
    if (!target) return;
    if (backendMode === 'static') {
      setError('TCP-Portscan erfordert ein laufendes Node.js-Backend (im rein statischen Hosting nicht verfügbar).');
      return;
    }
    setProbing(true);
    setError(null);

    try {
      const res = await fetch('/api/ports/probe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host: target }),
      });
      const contentType = res.headers.get('content-type') ?? '';
      if (!contentType.includes('application/json')) {
        setError('TCP-Portscan erfordert ein laufendes Node.js-Backend (im rein statischen Hosting nicht verfügbar).');
        return;
      }
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? 'Port-Prüfung fehlgeschlagen.');
      } else {
        onUpdatePorts(data as PortsModuleResult);
      }
    } catch {
      setError('Netzwerkfehler bei der Port-Abfrage.');
    } finally {
      setProbing(false);
    }
  };

  return (
    <section
      id="section-ports"
      className="rounded-lg border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900"
    >
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 px-5 py-4 dark:border-slate-800">
        <div>
          <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
            5. Live Mail-Ports, Banner & TLS-Zertifikate
          </h2>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
            {ports?.targetHost ? (
              <>
                Geprüfter Host:{' '}
                <span className="font-mono text-slate-800 dark:text-slate-200">{ports.targetHost}</span>
                {ports.targetIp ? ` (${ports.targetIp})` : ''} · {ports.durationMs} ms
              </>
            ) : (
              `TCP-Verbindungsprüfung für ${domain}`
            )}
          </p>
        </div>
        <StatusIndicator status={ports?.status ?? (isLoading ? 'pending' : 'info')} label={ports?.summary} />
      </div>

      <div className="space-y-4 p-5">
        <form onSubmit={handleProbeHost} className="flex flex-wrap items-center gap-2">
          <label htmlFor="custom-port-host" className="sr-only">
            Anderen Mail-Host prüfen
          </label>
          <div className="relative min-w-[240px] flex-1 sm:max-w-xs">
            <Server className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" aria-hidden="true" />
            <input
              id="custom-port-host"
              type="text"
              value={customHost}
              onChange={(e) => setCustomHost(e.target.value)}
              placeholder={`Anderer Host (z. B. mail.${domain})`}
              className="w-full rounded-md border border-slate-200 bg-slate-50 py-1.5 pl-8 pr-3 font-mono text-xs text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100 dark:focus:border-blue-500"
            />
          </div>
          <button
            type="submit"
            disabled={probing || !customHost.trim()}
            className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-800 transition-colors hover:bg-slate-50 disabled:opacity-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700 whitespace-nowrap shrink-0"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${probing ? 'animate-spin' : ''}`} aria-hidden="true" />
            <span>{probing ? 'Prüfe Ports…' : 'Host-Ports testen'}</span>
          </button>
          {error && <span className="text-xs text-red-600 dark:text-red-400">{error}</span>}
        </form>

        {!ports && isLoading ? (
          <div className="space-y-2.5 py-2" aria-busy="true">
            <div className="h-4 w-3/4 animate-pulse rounded bg-slate-200/80 dark:bg-slate-800" />
            <div className="h-4 w-2/3 animate-pulse rounded bg-slate-200/60 dark:bg-slate-800/70" />
          </div>
        ) : ports && ports.ports.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[780px] text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 font-medium text-slate-500 dark:border-slate-800 dark:text-slate-400">
                  <th className="pb-2.5 pr-4">Port</th>
                  <th className="pb-2.5 pr-4">Dienst</th>
                  <th className="pb-2.5 pr-4">Status</th>
                  <th className="pb-2.5 pr-4">TLS / Zertifikat</th>
                  <th className="pb-2.5 pr-4">Server-Banner / Fähigkeiten</th>
                  <th className="pb-2.5 text-right">Latenz</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                {ports.ports.map((p) => (
                  <tr key={p.port} className="align-top">
                    <td className="py-3 pr-4 font-mono font-semibold text-slate-900 tabular-nums dark:text-slate-100">
                      {p.port}
                    </td>
                    <td className="py-3 pr-4 text-slate-700 dark:text-slate-300">
                      <div className="font-medium">{p.service}</div>
                      <div className="text-slate-500 dark:text-slate-400">{p.protocol}</div>
                    </td>
                    <td className="py-3 pr-4">
                      <StatusIndicator
                        status={p.status}
                        label={
                          p.state === 'open'
                            ? 'Offen'
                            : p.state === 'closed'
                              ? 'Geschlossen'
                              : p.state === 'timeout'
                                ? 'Gefiltert / Timeout'
                                : 'Fehler'
                        }
                      />
                      <div className="mt-0.5 text-slate-500 dark:text-slate-400">{p.note}</div>
                    </td>
                    <td className="py-3 pr-4 text-slate-700 dark:text-slate-300">
                      {p.tlsInfo ? (
                        <div className="space-y-0.5">
                          <div className="font-mono font-medium text-slate-800 dark:text-slate-200">
                            {p.tlsInfo.protocol ?? 'TLS'} · {p.tlsInfo.cipher ?? 'Standard'}
                          </div>
                          <div className="text-slate-500 dark:text-slate-400">
                            {p.tlsInfo.issuer ? `${p.tlsInfo.issuer} · ` : ''}
                            {p.tlsInfo.daysRemaining !== null
                              ? `Gültig ${p.tlsInfo.daysRemaining} Tage`
                              : 'Zertifikat aktiv'}
                            {p.tlsInfo.authorized === false ? ' (Self-signed/Mismatch)' : ''}
                          </div>
                        </div>
                      ) : p.startTlsSupported ? (
                        <span className="font-mono text-slate-600 dark:text-slate-400">STARTTLS angekündigt</span>
                      ) : (
                        <span className="text-slate-400 dark:text-slate-500">—</span>
                      )}
                    </td>
                    <td className="max-w-xs py-3 pr-4">
                      {p.banner ? (
                        <div className="truncate font-mono text-slate-700 dark:text-slate-300" title={p.banner}>
                          {p.banner}
                        </div>
                      ) : (
                        <span className="text-slate-400 dark:text-slate-500">Kein Banner</span>
                      )}
                      {p.ehloCapabilities.length > 0 && (
                        <div
                          className="mt-1 truncate font-mono text-[11px] text-slate-500 dark:text-slate-400"
                          title={p.ehloCapabilities.join(' · ')}
                        >
                          EHLO: {p.ehloCapabilities.slice(0, 5).join(' · ')}
                        </div>
                      )}
                    </td>
                    <td className="py-3 text-right font-mono text-slate-500 tabular-nums dark:text-slate-400">
                      {p.latencyMs !== null ? `${p.latencyMs} ms` : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-xs text-slate-500 dark:text-slate-400">
            {ports?.summary ?? 'Keine Port-Ergebnisse verfügbar.'}
          </p>
        )}
      </div>
    </section>
  );
}
