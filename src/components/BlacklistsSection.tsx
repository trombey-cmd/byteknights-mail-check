import { useMemo, useState } from 'react';
import type { BlacklistModuleResult } from '../types/mailcheck';
import { StatusIndicator } from './StatusIndicator';

interface BlacklistsSectionProps {
  blacklists: BlacklistModuleResult | null;
  domain: string;
  isLoading: boolean;
}

type BlacklistFilter = 'all' | 'listed' | 'clean';

export function BlacklistsSection({ blacklists, domain, isLoading }: BlacklistsSectionProps) {
  const [filter, setFilter] = useState<BlacklistFilter>('all');

  const filteredEntries = useMemo(() => {
    if (!blacklists) return [];
    if (filter === 'listed') return blacklists.entries.filter((e) => e.state === 'listed');
    if (filter === 'clean') return blacklists.entries.filter((e) => e.state === 'clean');
    return blacklists.entries;
  }, [blacklists, filter]);

  return (
    <section
      id="section-blacklists"
      className="rounded-lg border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900"
    >
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 px-5 py-4 dark:border-slate-800">
        <div>
          <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
            6. Live Blacklist- & Reputationsprüfung (DNSBL / RBL)
          </h2>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
            {blacklists ? (
              <>
                Geprüfte IP:{' '}
                <span className="font-mono text-slate-800 dark:text-slate-200">
                  {blacklists.checkedIp ?? 'Keine IPv4'}
                </span>{' '}
                · Domain: <span className="font-mono">{blacklists.checkedDomain}</span> · {blacklists.durationMs} ms
              </>
            ) : (
              `Prüfe RBL-Datenbanken für ${domain}…`
            )}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {blacklists && (
            <div className="flex items-center gap-1 rounded-md bg-slate-100 p-0.5 dark:bg-slate-800">
              <button
                type="button"
                onClick={() => setFilter('all')}
                className={`rounded px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  filter === 'all'
                    ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-slate-100'
                    : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200'
                }`}
              >
                Alle ({blacklists.entries.length})
              </button>
              <button
                type="button"
                onClick={() => setFilter('listed')}
                className={`rounded px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  filter === 'listed'
                    ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-slate-100'
                    : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200'
                }`}
              >
                Gelistet ({blacklists.listedCount})
              </button>
              <button
                type="button"
                onClick={() => setFilter('clean')}
                className={`rounded px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  filter === 'clean'
                    ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-slate-100'
                    : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200'
                }`}
              >
                Sauber ({blacklists.entries.filter((e) => e.state === 'clean').length})
              </button>
            </div>
          )}
          <StatusIndicator status={blacklists?.status ?? (isLoading ? 'pending' : 'info')} label={blacklists?.summary} />
        </div>
      </div>

      <div className="p-5">
        {!blacklists && isLoading ? (
          <div className="space-y-2.5 py-2" aria-busy="true">
            <div className="h-4 w-3/4 animate-pulse rounded bg-slate-200/80 dark:bg-slate-800" />
            <div className="h-4 w-1/2 animate-pulse rounded bg-slate-200/60 dark:bg-slate-800/70" />
          </div>
        ) : filteredEntries.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[680px] text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 font-medium text-slate-500 dark:border-slate-800 dark:text-slate-400">
                  <th className="pb-2.5 pr-4">Blacklist-Anbieter</th>
                  <th className="pb-2.5 pr-4">Abgefragtes Ziel</th>
                  <th className="pb-2.5 pr-4">Status</th>
                  <th className="pb-2.5 pr-4">Rückgabe / Detail</th>
                  <th className="pb-2.5 text-right">Latenz</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                {filteredEntries.map((entry) => (
                  <tr key={entry.id}>
                    <td className="py-2.5 pr-4">
                      <div className="font-medium text-slate-900 dark:text-slate-100">{entry.name}</div>
                      <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400">{entry.zone}</div>
                    </td>
                    <td className="py-2.5 pr-4 font-mono text-slate-600 dark:text-slate-400">
                      {entry.queryTarget}
                    </td>
                    <td className="py-2.5 pr-4">
                      <StatusIndicator
                        status={entry.status}
                        label={
                          entry.state === 'clean'
                            ? 'Nicht gelistet'
                            : entry.state === 'listed'
                              ? 'Gelistet'
                              : entry.state === 'blocked_resolver'
                                ? 'Resolver gedrosselt'
                                : 'Nicht prüfbar'
                        }
                      />
                    </td>
                    <td className="py-2.5 pr-4 font-mono text-slate-600 dark:text-slate-300">
                      {entry.returnCode ? (
                        <span>
                          {entry.returnCode}
                          {entry.txtReason ? ` · ${entry.txtReason}` : ''}
                        </span>
                      ) : entry.txtReason ? (
                        entry.txtReason
                      ) : (
                        '—'
                      )}
                    </td>
                    <td className="py-2.5 text-right font-mono text-slate-500 tabular-nums dark:text-slate-400">
                      {entry.latencyMs} ms
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Keine Einträge entsprechen dem ausgewählten Filter.
          </p>
        )}
      </div>
    </section>
  );
}
