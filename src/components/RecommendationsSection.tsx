import { CheckCircle2 } from 'lucide-react';
import type { FullCheckReport } from '../types/mailcheck';
import { StatusIndicator } from './StatusIndicator';
import { CopyButton } from './CopyButton';

interface RecommendationsSectionProps {
  report: FullCheckReport;
  isLoading: boolean;
}

export function RecommendationsSection({ report, isLoading }: RecommendationsSectionProps) {
  const recs = report.recommendations;

  return (
    <section
      id="section-recommendations"
      className="rounded-lg border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900"
    >
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 px-5 py-4 dark:border-slate-800">
        <div>
          <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
            Diagnose-Auswertung & Handlungsempfehlungen
          </h2>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
            Konkrete Optimierungsvorschläge basierend auf den Live-Ergebnissen für{' '}
            <span className="font-mono text-slate-700 dark:text-slate-300">{report.domain}</span>
          </p>
        </div>
        {!isLoading && (
          <StatusIndicator
            status={recs.length === 0 ? 'ok' : recs.some((r) => r.severity === 'error') ? 'error' : 'warn'}
            label={recs.length === 0 ? 'Keine kritischen Befunde' : `${recs.length} Empfehlung${recs.length === 1 ? '' : 'en'}`}
          />
        )}
      </div>

      <div className="p-5">
        {isLoading ? (
          <div className="space-y-2.5 py-2" aria-busy="true">
            <div className="h-4 w-1/2 animate-pulse rounded bg-slate-200/80 dark:bg-slate-800" />
            <div className="h-4 w-2/3 animate-pulse rounded bg-slate-200/60 dark:bg-slate-800/70" />
          </div>
        ) : recs.length === 0 ? (
          <div className="flex items-start gap-3 text-sm text-slate-700 dark:text-slate-300">
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
            <div>
              <div className="font-medium text-slate-900 dark:text-slate-100">
                Alle geprüften Mail-Standards sind sauber konfiguriert.
              </div>
              <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                MX, SPF, DKIM, DMARC, Transportverschlüsselung und DNSBL-Reputation zeigen keine akuten Mängel.
              </p>
            </div>
          </div>
        ) : (
          <ul className="divide-y divide-slate-100 dark:divide-slate-800/80">
            {recs.map((rec) => (
              <li key={rec.id} className="py-4 first:pt-0 last:pb-0">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5 text-sm font-medium text-slate-900 dark:text-slate-100">
                    <StatusIndicator status={rec.severity} label={rec.module} />
                    <span>{rec.title}</span>
                  </div>
                </div>
                <p className="mt-1.5 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
                  {rec.description}
                </p>
                {rec.suggestedRecord && (
                  <div className="mt-2.5 flex flex-wrap items-center justify-between gap-2 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 dark:border-slate-800 dark:bg-slate-950">
                    <code className="break-all font-mono text-xs text-slate-800 dark:text-slate-200">
                      {rec.suggestedRecord}
                    </code>
                    <CopyButton value={rec.suggestedRecord} label="Vorschlag kopieren" />
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
