import type { FullCheckReport, CheckSeverity } from '../types/mailcheck';
import { StatusIndicator } from './StatusIndicator';

export type ModuleKey = 'mx' | 'spf' | 'dkim' | 'dmarc' | 'ports' | 'blacklists';

interface ModuleSummaryGridProps {
  report: FullCheckReport | null;
  isLoading: boolean;
  onSelectModule: (key: ModuleKey) => void;
}

interface SummaryCardConfig {
  key: ModuleKey;
  title: string;
  subtitle: string;
  status: CheckSeverity;
  metric: string;
  durationMs: number | null;
}

export function ModuleSummaryGrid({ report, isLoading, onSelectModule }: ModuleSummaryGridProps) {
  const items: SummaryCardConfig[] = [
    {
      key: 'mx',
      title: 'MX-Records',
      subtitle: report?.mx?.summary ?? (isLoading ? 'Löse Mail-Exchanger auf…' : 'Bereit zur Prüfung'),
      status: report?.mx?.status ?? (isLoading ? 'pending' : 'info'),
      metric: report?.mx ? `${report.mx.records.length} Server` : '—',
      durationMs: report?.mx?.durationMs ?? null,
    },
    {
      key: 'spf',
      title: 'SPF-Richtlinie',
      subtitle: report?.spf?.summary ?? (isLoading ? 'Prüfe v=spf1 & Lookups…' : 'Bereit zur Prüfung'),
      status: report?.spf?.status ?? (isLoading ? 'pending' : 'info'),
      metric: report?.spf ? `${report.spf.lookupCount}/10 Lookups` : '—',
      durationMs: report?.spf?.durationMs ?? null,
    },
    {
      key: 'dkim',
      title: 'DKIM-Signaturen',
      subtitle: report?.dkim?.summary ?? (isLoading ? 'Teste Standard-Selektoren…' : 'Bereit zur Prüfung'),
      status: report?.dkim?.status ?? (isLoading ? 'pending' : 'info'),
      metric: report?.dkim ? `${report.dkim.foundCount} aktiv` : '—',
      durationMs: report?.dkim?.durationMs ?? null,
    },
    {
      key: 'dmarc',
      title: 'DMARC & Policy',
      subtitle: report?.dmarc?.summary ?? (isLoading ? 'Lese _dmarc TXT-Record…' : 'Bereit zur Prüfung'),
      status: report?.dmarc?.status ?? (isLoading ? 'pending' : 'info'),
      metric: report?.dmarc?.policy ? `p=${report.dmarc.policy}` : report?.dmarc ? 'fehlt' : '—',
      durationMs: report?.dmarc?.durationMs ?? null,
    },
    {
      key: 'ports',
      title: 'Mail-Ports & TLS',
      subtitle: report?.ports?.summary ?? (isLoading ? 'Prüfe TCP & STARTTLS…' : 'Bereit zur Prüfung'),
      status: report?.ports?.status ?? (isLoading ? 'pending' : 'info'),
      metric: report?.ports ? `${report.ports.openCount}/6 offen` : '—',
      durationMs: report?.ports?.durationMs ?? null,
    },
    {
      key: 'blacklists',
      title: 'Blacklists (DNSBL)',
      subtitle: report?.blacklists?.summary ?? (isLoading ? 'Frage 9 RBL-Zonen ab…' : 'Bereit zur Prüfung'),
      status: report?.blacklists?.status ?? (isLoading ? 'pending' : 'info'),
      metric: report?.blacklists ? `${report.blacklists.listedCount} gelistet` : '—',
      durationMs: report?.blacklists?.durationMs ?? null,
    },
  ];

  return (
    <section aria-label="Prüfübersicht" className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {items.map((item) => (
        <button
          key={item.key}
          type="button"
          onClick={() => onSelectModule(item.key)}
          className="group flex flex-col justify-between gap-3 rounded-lg border border-slate-200 bg-white p-4 text-left transition-colors duration-150 hover:border-slate-300 hover:bg-slate-50/70 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 dark:border-slate-800 dark:bg-slate-900 dark:hover:border-slate-700 dark:hover:bg-slate-800/60"
        >
          <div className="flex items-center justify-between gap-3">
            <span className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
              {item.title}
            </span>
            <StatusIndicator status={item.status} />
          </div>

          <p className="truncate text-xs text-slate-600 dark:text-slate-400" title={item.subtitle}>
            {item.subtitle}
          </p>

          <div className="flex items-center justify-between border-t border-slate-100 pt-2.5 text-xs text-slate-500 dark:border-slate-800/80 dark:text-slate-400">
            <span className="font-mono font-medium text-slate-800 tabular-nums dark:text-slate-200">
              {item.metric}
            </span>
            <span className="font-mono tabular-nums">
              {item.durationMs !== null ? `${item.durationMs} ms` : '—'}
            </span>
          </div>
        </button>
      ))}
    </section>
  );
}
