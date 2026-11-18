import { useCallback, useEffect, useRef, useState } from 'react';
import { Download, Loader2, Moon, Play, Search, Sun, X } from 'lucide-react';
import type {
  BlacklistModuleResult,
  DkimModuleResult,
  DkimSelectorResult,
  DmarcModuleResult,
  FullCheckReport,
  MxModuleResult,
  PortsModuleResult,
  RecommendationItem,
  SpfModuleResult,
} from './types/mailcheck';
import {
  isValidTarget,
  normalizeTargetInput,
  runLiveDohCheck,
} from './lib/dohDiagnostics';
import { ModuleSummaryGrid, type ModuleKey } from './components/ModuleSummaryGrid';
import { DnsAuthSection } from './components/DnsAuthSection';
import { PortsSection } from './components/PortsSection';
import { BlacklistsSection } from './components/BlacklistsSection';
import { RecommendationsSection } from './components/RecommendationsSection';
import { CopyButton } from './components/CopyButton';

type ViewTab = 'all' | 'dns' | 'ports' | 'blacklists' | 'raw';

const PRESET_DOMAINS = ['it-virtuoso.de', 'mailbox.org', 'hetzner.com', 'google.com'];
const HISTORY_STORAGE_KEY = 'mailtest_recent_domains_v1';
const THEME_STORAGE_KEY = 'mailtest_theme_v1';

export default function App() {
  const [darkMode, setDarkMode] = useState<boolean>(() => {
    if (typeof window === 'undefined') return false;
    const saved = localStorage.getItem(THEME_STORAGE_KEY);
    if (saved === 'dark') return true;
    if (saved === 'light') return false;
    return window.matchMedia?.('(prefers-color-scheme: dark)').matches ?? false;
  });

  const [targetInput, setTargetInput] = useState('it-virtuoso.de');
  const [selectorsInput, setSelectorsInput] = useState('');
  const [customHostInput, setCustomHostInput] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);

  const [activeTab, setActiveTab] = useState<ViewTab>('all');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [report, setReport] = useState<FullCheckReport | null>(null);

  const [recentDomains, setRecentDomains] = useState<string[]>(() => {
    if (typeof window === 'undefined') return [];
    try {
      const parsed = JSON.parse(localStorage.getItem(HISTORY_STORAGE_KEY) ?? '[]');
      return Array.isArray(parsed) ? parsed.slice(0, 5) : [];
    } catch {
      return [];
    }
  });

  const [backendMode, setBackendMode] = useState<'node' | 'static'>('node');
  const runtimeModeRef = useRef<'node' | 'static' | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const domainInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    const root = document.documentElement;
    if (darkMode) {
      root.classList.add('dark');
      localStorage.setItem(THEME_STORAGE_KEY, 'dark');
    } else {
      root.classList.remove('dark');
      localStorage.setItem(THEME_STORAGE_KEY, 'light');
    }
  }, [darkMode]);

  const stopActiveStream = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
  }, []);

  const recordRecentDomain = useCallback((domain: string) => {
    setRecentDomains((prev) => {
      const next = [domain, ...prev.filter((d) => d !== domain)].slice(0, 5);
      try {
        localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(next));
      } catch {
        // ignore storage quota
      }
      return next;
    });
  }, []);

  const runLiveCheck = useCallback(
    async (overrideTarget?: string) => {
      const rawTarget = (overrideTarget ?? targetInput).trim();
      if (!rawTarget) {
        setErrorMsg('Bitte geben Sie eine Domain, E-Mail-Adresse oder einen Hostnamen ein.');
        return;
      }

      const normalized = normalizeTargetInput(rawTarget);
      if (!normalized.domain || !isValidTarget(normalized.domain)) {
        setErrorMsg('Bitte geben Sie eine gültige Domain, E-Mail-Adresse oder einen Hostnamen ein.');
        return;
      }

      stopActiveStream();
      setErrorMsg(null);
      setIsLoading(true);
      if (overrideTarget) {
        setTargetInput(overrideTarget);
      }

      const controller = new AbortController();
      abortControllerRef.current = controller;

      const handleEvent = (event: string, data: unknown) => {
        if (event === 'init') {
          const meta = data as {
            id: string;
            input: string;
            domain: string;
            customHost: string | null;
            customSelectors: string[];
            startedAt: string;
          };
          recordRecentDomain(meta.domain);
          setReport({
            id: meta.id,
            input: meta.input,
            domain: meta.domain,
            customHost: meta.customHost,
            customSelectors: meta.customSelectors,
            startedAt: meta.startedAt,
            completedAt: null,
            totalDurationMs: null,
            mx: null,
            spf: null,
            dkim: null,
            dmarc: null,
            ports: null,
            blacklists: null,
            recommendations: [],
          });
        } else if (event === 'mx') {
          setReport((prev) => (prev ? { ...prev, mx: data as MxModuleResult } : prev));
        } else if (event === 'spf') {
          setReport((prev) => (prev ? { ...prev, spf: data as SpfModuleResult } : prev));
        } else if (event === 'dkim') {
          setReport((prev) => (prev ? { ...prev, dkim: data as DkimModuleResult } : prev));
        } else if (event === 'dmarc') {
          setReport((prev) => (prev ? { ...prev, dmarc: data as DmarcModuleResult } : prev));
        } else if (event === 'ports') {
          setReport((prev) => (prev ? { ...prev, ports: data as PortsModuleResult } : prev));
        } else if (event === 'blacklists') {
          setReport((prev) => (prev ? { ...prev, blacklists: data as BlacklistModuleResult } : prev));
        } else if (event === 'complete') {
          const payload = data as {
            completedAt: string;
            totalDurationMs: number;
            recommendations: RecommendationItem[];
          };
          setReport((prev) =>
            prev
              ? {
                  ...prev,
                  completedAt: payload.completedAt,
                  totalDurationMs: payload.totalDurationMs,
                  recommendations: payload.recommendations,
                }
              : prev
          );
        }
      };

      const runDohFallback = async () => {
        const selectors = selectorsInput
          .split(',')
          .map((s) => s.trim().toLowerCase())
          .filter(Boolean);
        const host = customHostInput.trim() || null;

        await runLiveDohCheck(
          rawTarget,
          selectors,
          host,
          {
            onInit: (meta) => handleEvent('init', meta),
            onMx: (mx) => handleEvent('mx', mx),
            onSpf: (spf) => handleEvent('spf', spf),
            onDkim: (dkim) => handleEvent('dkim', dkim),
            onDmarc: (dmarc) => handleEvent('dmarc', dmarc),
            onPorts: (ports) => handleEvent('ports', ports),
            onBlacklists: (bl) => handleEvent('blacklists', bl),
            onComplete: (payload) => handleEvent('complete', payload),
          },
          controller.signal
        );
      };

      const detectRuntimeMode = async (): Promise<'node' | 'static'> => {
        if (runtimeModeRef.current) return runtimeModeRef.current;
        try {
          const rtRes = await fetch('/runtime.json', { cache: 'no-store' });
          const ct = rtRes.headers.get('content-type') ?? '';
          if (rtRes.ok && ct.includes('application/json')) {
            const rt = (await rtRes.json()) as { mode?: string };
            const resolved: 'node' | 'static' = rt.mode === 'node' ? 'node' : 'static';
            runtimeModeRef.current = resolved;
            setBackendMode(resolved);
            return resolved;
          }
        } catch {
          // fallback to static DoH if runtime descriptor cannot be read
        }
        runtimeModeRef.current = 'static';
        setBackendMode('static');
        return 'static';
      };

      try {
        const mode = await detectRuntimeMode();
        if (controller.signal.aborted) return;

        if (mode === 'static') {
          await runDohFallback();
          return;
        }

        const res = await fetch('/api/check/ndjson', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target: rawTarget,
            selectors: selectorsInput.trim(),
            host: customHostInput.trim(),
          }),
          signal: controller.signal,
        });

        const contentType = res.headers.get('content-type') ?? '';
        if (res.ok && contentType.includes('application/x-ndjson') && res.body) {
          const reader = res.body.getReader();
          const decoder = new TextDecoder();
          let buffer = '';

          while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop() ?? '';
            for (const line of lines) {
              const trimmed = line.trim();
              if (!trimmed) continue;
              const parsedLine = JSON.parse(trimmed) as { event: string; data: unknown };
              handleEvent(parsedLine.event, parsedLine.data);
            }
          }
          if (buffer.trim()) {
            const parsedLine = JSON.parse(buffer.trim()) as { event: string; data: unknown };
            handleEvent(parsedLine.event, parsedLine.data);
          }
        } else if (res.status === 400 && contentType.includes('application/json')) {
          const errJson = (await res.json()) as { error?: string };
          setErrorMsg(errJson.error ?? 'Ungültige Eingabe.');
        } else {
          await runDohFallback();
        }
      } catch (err) {
        if ((err as Error)?.name === 'AbortError') return;
        try {
          await runDohFallback();
        } catch {
          setErrorMsg('Die Live-Prüfung konnte nicht durchgeführt werden. Bitte prüfen Sie Ihre Netzwerkverbindung.');
        }
      } finally {
        if (abortControllerRef.current === controller) {
          abortControllerRef.current = null;
          setIsLoading(false);
        }
      }
    },
    [targetInput, selectorsInput, customHostInput, stopActiveStream, recordRecentDomain]
  );

  useEffect(() => {
    runLiveCheck('it-virtuoso.de');
    return () => stopActiveStream();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    runLiveCheck();
  };

  const handleSelectModule = (key: ModuleKey) => {
    if (key === 'ports') {
      setActiveTab('all');
      setTimeout(() => document.getElementById('section-ports')?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 40);
    } else if (key === 'blacklists') {
      setActiveTab('all');
      setTimeout(() => document.getElementById('section-blacklists')?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 40);
    } else {
      setActiveTab('all');
      setTimeout(() => document.getElementById(`section-${key}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 40);
    }
  };

  const handleNavAnchor = (tab: ViewTab, elementId: string) => {
    setActiveTab(tab);
    setTimeout(() => {
      document.getElementById(elementId)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 40);
  };

  const handleExportJson = () => {
    if (!report) {
      domainInputRef.current?.focus();
      return;
    }
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `mailcheck-${report.domain}-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const handleAddDkimResult = (newSel: DkimSelectorResult) => {
    setReport((prev) => {
      if (!prev || !prev.dkim) return prev;
      const existing = prev.dkim.selectors.filter((s) => s.selector !== newSel.selector);
      const updatedSelectors = [newSel, ...existing];
      const tested = Array.from(new Set([...prev.dkim.testedSelectors, newSel.selector]));
      const foundCount = updatedSelectors.filter((s) => s.found).length;
      return {
        ...prev,
        dkim: {
          ...prev.dkim,
          testedSelectors: tested,
          foundCount,
          selectors: updatedSelectors,
          status: newSel.found ? (newSel.status === 'error' ? 'error' : prev.dkim.status) : prev.dkim.status,
          summary: `${foundCount} aktive${foundCount === 1 ? 'r' : ''} Selektor${foundCount === 1 ? '' : 'en'}`,
        },
      };
    });
  };

  const handleUpdatePorts = (nextPorts: PortsModuleResult) => {
    setReport((prev) => (prev ? { ...prev, ports: nextPorts } : prev));
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
      {/* Top Bar Contract: strictly 1 row, 3 zones separated by gap-8 */}
      <header className="border-b border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
        <div className="mx-auto flex max-w-[1200px] items-center justify-between gap-8 px-4 py-3.5 sm:px-6">
          {/* Zone 1: Single-line Brand Wordmark */}
          <a
            href="#top"
            className="font-display text-base font-bold tracking-tight text-slate-900 dark:text-slate-100 whitespace-nowrap shrink-0"
          >
            Mail Prüfsystem
          </a>

          {/* Zone 2: 5 concise single-line text nav links */}
          <nav aria-label="Hauptnavigation" className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-600 dark:text-slate-300">
            <button
              type="button"
              onClick={() => handleNavAnchor('all', 'overview-grid')}
              className="hover:text-slate-900 hover:underline underline-offset-4 dark:hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Übersicht
            </button>
            <button
              type="button"
              onClick={() => handleNavAnchor('dns', 'section-mx')}
              className="hover:text-slate-900 hover:underline underline-offset-4 dark:hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              DNS &amp; Auth
            </button>
            <button
              type="button"
              onClick={() => handleNavAnchor('ports', 'section-ports')}
              className="hover:text-slate-900 hover:underline underline-offset-4 dark:hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Ports &amp; TLS
            </button>
            <button
              type="button"
              onClick={() => handleNavAnchor('blacklists', 'section-blacklists')}
              className="hover:text-slate-900 hover:underline underline-offset-4 dark:hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Blacklists
            </button>
            <button
              type="button"
              onClick={() => handleNavAnchor('raw', 'section-recommendations')}
              className="hover:text-slate-900 hover:underline underline-offset-4 dark:hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Empfehlungen
            </button>
          </nav>

          {/* Zone 3: 1 primary action */}
          <div className="flex items-center shrink-0">
            <button
              type="button"
              onClick={handleExportJson}
              className="inline-flex items-center gap-1.5 rounded-md bg-slate-900 px-3.5 py-2 text-xs font-medium text-white transition-colors hover:bg-slate-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 dark:bg-blue-600 dark:hover:bg-blue-500 whitespace-nowrap shrink-0"
            >
              <Download className="h-3.5 w-3.5" aria-hidden="true" />
              <span>{report ? 'JSON Export' : 'Prüfung starten'}</span>
            </button>
          </div>
        </div>
      </header>

      <main id="top" className="mx-auto max-w-[1200px] space-y-6 px-4 py-8 sm:px-6">
        {/* Hero & Dominant Diagnostic Command Anchor */}
        <section className="rounded-lg border border-slate-200 bg-white p-5 sm:p-6 dark:border-slate-800 dark:bg-slate-900">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="max-w-2xl">
              <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900 text-balance sm:text-3xl dark:text-slate-100">
                Mail-Infrastruktur live prüfen
              </h1>
              <p className="mt-1.5 text-sm leading-relaxed text-slate-600 dark:text-slate-400">
                Echtzeit-Diagnose für MX-Records, SPF, DKIM, DMARC, Mail-Ports, STARTTLS und DNSBL-Blacklists.
              </p>
            </div>

            {/* Workspace Toolbar Control: Light/Dark Theme Switch */}
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setDarkMode((prev) => !prev)}
                aria-label={darkMode ? 'Zum hellen Design wechseln' : 'Zum dunklen Design wechseln'}
                className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-700 transition-colors hover:bg-slate-100 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700 whitespace-nowrap shrink-0"
              >
                {darkMode ? (
                  <>
                    <Sun className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Helles Design</span>
                  </>
                ) : (
                  <>
                    <Moon className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Dunkles Design</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Search & Live Trigger Form */}
          <form onSubmit={handleFormSubmit} className="mt-5 space-y-3">
            <div className="flex flex-col gap-2.5 sm:flex-row">
              <div className="relative flex-1">
                <Search
                  className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400"
                  aria-hidden="true"
                />
                <input
                  ref={domainInputRef}
                  type="text"
                  value={targetInput}
                  onChange={(e) => setTargetInput(e.target.value)}
                  placeholder="Domain, E-Mail-Adresse oder Hostname (z. B. it-virtuoso.de)"
                  aria-label="Domain, E-Mail-Adresse oder Hostname"
                  className="w-full rounded-md border border-slate-300 bg-white py-2.5 pl-10 pr-9 font-mono text-sm text-slate-900 placeholder:font-sans placeholder:text-slate-400 focus:border-blue-600 focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100 dark:focus:border-blue-500"
                />
                {targetInput && (
                  <button
                    type="button"
                    onClick={() => {
                      setTargetInput('');
                      domainInputRef.current?.focus();
                    }}
                    aria-label="Eingabe löschen"
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded p-1 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200"
                  >
                    <X className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                )}
              </div>

              <button
                type="button"
                onClick={() => setShowAdvanced((v) => !v)}
                className="rounded-md border border-slate-200 bg-slate-50 px-3.5 py-2.5 text-xs font-medium text-slate-700 transition-colors hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700 whitespace-nowrap shrink-0"
              >
                {showAdvanced ? 'Optionen ausblenden' : 'Erweiterte Optionen'}
              </button>

              {isLoading ? (
                <button
                  type="button"
                  onClick={() => {
                    stopActiveStream();
                    setIsLoading(false);
                  }}
                  className="inline-flex items-center justify-center gap-2 rounded-md border border-red-300 bg-red-50 px-5 py-2.5 text-sm font-medium text-red-700 transition-colors hover:bg-red-100 dark:border-red-900 dark:bg-red-950/60 dark:text-red-300 whitespace-nowrap shrink-0"
                >
                  <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                  <span>Abbrechen</span>
                </button>
              ) : (
                <button
                  type="submit"
                  className="inline-flex items-center justify-center gap-2 rounded-md bg-blue-600 px-5 py-2.5 text-sm font-medium text-white transition-colors hover:bg-blue-700 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 whitespace-nowrap shrink-0"
                >
                  <Play className="h-4 w-4" aria-hidden="true" />
                  <span>Jetzt live prüfen</span>
                </button>
              )}
            </div>

            {showAdvanced && (
              <div className="grid grid-cols-1 gap-3 border-t border-slate-100 pt-3 sm:grid-cols-2 dark:border-slate-800">
                <div>
                  <label htmlFor="adv-selectors" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                    Zusätzliche DKIM-Selektoren (kommagetrennt)
                  </label>
                  <input
                    id="adv-selectors"
                    type="text"
                    value={selectorsInput}
                    onChange={(e) => setSelectorsInput(e.target.value)}
                    placeholder="z. B. mail2026, key1, dkim-prod"
                    className="mt-1 w-full rounded-md border border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-blue-600 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
                  />
                </div>
                <div>
                  <label htmlFor="adv-host" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                    Abweichender Mail-Host für Port-Test
                  </label>
                  <input
                    id="adv-host"
                    type="text"
                    value={customHostInput}
                    onChange={(e) => setCustomHostInput(e.target.value)}
                    placeholder="z. B. smtp.example.de (Standard: primärer MX)"
                    className="mt-1 w-full rounded-md border border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-blue-600 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
                  />
                </div>
              </div>
            )}
          </form>

          {errorMsg && (
            <p role="alert" className="mt-3 text-xs font-medium text-red-700 dark:text-red-400">
              {errorMsg}
            </p>
          )}

          {/* Presets & Recent History as clean inline text buttons */}
          <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-3 text-xs text-slate-500 dark:border-slate-800/80 dark:text-slate-400">
            <div className="flex flex-wrap items-center gap-2">
              <span>Beispiele:</span>
              {PRESET_DOMAINS.map((preset) => (
                <button
                  key={preset}
                  type="button"
                  onClick={() => runLiveCheck(preset)}
                  className={`font-mono transition-colors hover:text-slate-900 hover:underline underline-offset-4 dark:hover:text-slate-100 whitespace-nowrap shrink-0 ${
                    report?.domain === preset ? 'font-semibold text-blue-600 dark:text-blue-400' : ''
                  }`}
                >
                  {preset}
                </button>
              ))}
            </div>

            {recentDomains.length > 0 && (
              <div className="flex flex-wrap items-center gap-2">
                <span>Zuletzt geprüft:</span>
                {recentDomains.map((dom, idx) => (
                  <span key={dom} className="inline-flex items-center gap-2">
                    {idx > 0 && <span aria-hidden="true">·</span>}
                    <button
                      type="button"
                      onClick={() => runLiveCheck(dom)}
                      className="font-mono hover:text-slate-900 hover:underline underline-offset-4 dark:hover:text-slate-100 whitespace-nowrap shrink-0"
                    >
                      {dom}
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>
        </section>

        {/* How Diagnostics Work: MX, SPF, DKIM, DMARC */}
        <section
          aria-labelledby="how-diagnostics-work-heading"
          className="rounded-lg border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900"
        >
          <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-slate-200 px-5 py-3.5 dark:border-slate-800">
            <h2
              id="how-diagnostics-work-heading"
              className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100"
            >
              So funktioniert die Diagnose
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Zusammenspiel der vier DNS-Standards für sichere E-Mail-Zustellbarkeit
            </p>
          </div>

          <div className="grid grid-cols-1 divide-y divide-slate-100 sm:grid-cols-2 sm:divide-y-0 lg:grid-cols-4 lg:divide-x dark:divide-slate-800">
            <div className="flex flex-col justify-between gap-2.5 p-5">
              <div>
                <h3 className="font-display text-xs font-semibold text-slate-900 dark:text-slate-100">
                  01. MX (Mail Exchanger)
                </h3>
                <p className="mt-1.5 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
                  Benennt die zuständigen Ziel-Mailserver Ihrer Domain inklusive Priorität. Passende IPv4/IPv6-Ziele und ein bestätigter Reverse-DNS-Eintrag (FCrDNS) sichern die Annahme durch Gegenstellen.
                </p>
              </div>
              {report && (
                <button
                  type="button"
                  onClick={() => handleSelectModule('mx')}
                  className="self-start text-xs font-medium text-blue-600 hover:underline underline-offset-4 dark:text-blue-400 whitespace-nowrap shrink-0"
                >
                  MX-Ergebnis ansehen
                </button>
              )}
            </div>

            <div className="flex flex-col justify-between gap-2.5 border-t border-slate-100 p-5 sm:border-t-0 sm:border-l lg:border-l-0 dark:border-slate-800">
              <div>
                <h3 className="font-display text-xs font-semibold text-slate-900 dark:text-slate-100">
                  02. SPF (Sender Policy)
                </h3>
                <p className="mt-1.5 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
                  Legt per DNS-TXT-Eintrag fest, welche Server und Netze E-Mails für Ihre Domain versenden dürfen. Das verhindert einfaches Absender-Spoofing und prüft das Limit von 10 DNS-Lookups.
                </p>
              </div>
              {report && (
                <button
                  type="button"
                  onClick={() => handleSelectModule('spf')}
                  className="self-start text-xs font-medium text-blue-600 hover:underline underline-offset-4 dark:text-blue-400 whitespace-nowrap shrink-0"
                >
                  SPF-Ergebnis ansehen
                </button>
              )}
            </div>

            <div className="flex flex-col justify-between gap-2.5 border-t border-slate-100 p-5 lg:border-t-0 dark:border-slate-800">
              <div>
                <h3 className="font-display text-xs font-semibold text-slate-900 dark:text-slate-100">
                  03. DKIM (Signatur)
                </h3>
                <p className="mt-1.5 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
                  Signiert ausgehende Nachrichten kryptografisch. Über den unter einem Selektor veröffentlichten öffentlichen Schlüssel prüft der Empfänger Authentizität und Unverändertheit der Mail.
                </p>
              </div>
              {report && (
                <button
                  type="button"
                  onClick={() => handleSelectModule('dkim')}
                  className="self-start text-xs font-medium text-blue-600 hover:underline underline-offset-4 dark:text-blue-400 whitespace-nowrap shrink-0"
                >
                  DKIM-Ergebnis ansehen
                </button>
              )}
            </div>

            <div className="flex flex-col justify-between gap-2.5 border-t border-slate-100 p-5 sm:border-l lg:border-t-0 lg:border-l-0 dark:border-slate-800">
              <div>
                <h3 className="font-display text-xs font-semibold text-slate-900 dark:text-slate-100">
                  04. DMARC (Richtlinie)
                </h3>
                <p className="mt-1.5 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
                  Verbindet SPF und DKIM über Domain-Alignment und weist Empfänger an, wie gefälschte Mails behandelt werden sollen (beobachten, Quarantäne oder Ablehnung) inklusive Zustellberichten.
                </p>
              </div>
              {report && (
                <button
                  type="button"
                  onClick={() => handleSelectModule('dmarc')}
                  className="self-start text-xs font-medium text-blue-600 hover:underline underline-offset-4 dark:text-blue-400 whitespace-nowrap shrink-0"
                >
                  DMARC-Ergebnis ansehen
                </button>
              )}
            </div>
          </div>
        </section>

        {/* Active Target Metadata Line + Summary Grid */}
        {report && (
          <>
            <div id="overview-grid" className="space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-slate-500 dark:text-slate-400">
                <div className="flex flex-wrap items-center gap-2">
                  <span>Ziel-Domain:</span>
                  <span className="font-mono font-semibold text-slate-900 dark:text-slate-100">
                    {report.domain}
                  </span>
                  <span aria-hidden="true">·</span>
                  <span>
                    Gestartet: {new Date(report.startedAt).toLocaleTimeString('de-DE')}
                  </span>
                  {report.totalDurationMs !== null && (
                    <>
                      <span aria-hidden="true">·</span>
                      <span className="font-mono tabular-nums">
                        Gesamtdauer: {report.totalDurationMs} ms
                      </span>
                    </>
                  )}
                </div>

                {/* Segmented View Tabs */}
                <div className="flex flex-wrap items-center gap-1 rounded-md bg-slate-200/70 p-0.5 dark:bg-slate-800">
                  {(
                    [
                      { id: 'all', label: 'Alle Module' },
                      { id: 'dns', label: 'DNS & Auth' },
                      { id: 'ports', label: 'Ports & TLS' },
                      { id: 'blacklists', label: 'Blacklists' },
                      { id: 'raw', label: 'Empfehlungen & JSON' },
                    ] as Array<{ id: ViewTab; label: string }>
                  ).map((tab) => (
                    <button
                      key={tab.id}
                      type="button"
                      onClick={() => setActiveTab(tab.id)}
                      className={`rounded px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                        activeTab === tab.id
                          ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-slate-100'
                          : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200'
                      }`}
                    >
                      {tab.label}
                    </button>
                  ))}
                </div>
              </div>

              <ModuleSummaryGrid
                report={report}
                isLoading={isLoading}
                onSelectModule={handleSelectModule}
              />
            </div>

            {(activeTab === 'all' || activeTab === 'dns') && (
              <DnsAuthSection
                report={report}
                isLoading={isLoading}
                backendMode={backendMode}
                onAddDkimResult={handleAddDkimResult}
              />
            )}

            {(activeTab === 'all' || activeTab === 'ports') && (
              <PortsSection
                ports={report.ports}
                domain={report.domain}
                isLoading={isLoading}
                backendMode={backendMode}
                onUpdatePorts={handleUpdatePorts}
              />
            )}

            {(activeTab === 'all' || activeTab === 'blacklists') && (
              <BlacklistsSection
                blacklists={report.blacklists}
                domain={report.domain}
                isLoading={isLoading}
              />
            )}

            {(activeTab === 'all' || activeTab === 'raw') && (
              <div className="space-y-6">
                <RecommendationsSection report={report} isLoading={isLoading} />

                {activeTab === 'raw' && (
                  <section className="rounded-lg border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
                    <div className="flex items-center justify-between gap-4 border-b border-slate-200 px-5 py-4 dark:border-slate-800">
                      <div>
                        <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
                          Vollständiger JSON-Diagnosebericht
                        </h2>
                        <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                          Maschinenlesbare Rohdaten für Dokumentation und Ticket-Systeme
                        </p>
                      </div>
                      <CopyButton value={JSON.stringify(report, null, 2)} label="JSON kopieren" />
                    </div>
                    <pre className="max-h-[420px] overflow-auto p-5 font-mono text-xs leading-relaxed text-slate-700 dark:text-slate-300">
                      {JSON.stringify(report, null, 2)}
                    </pre>
                  </section>
                )}
              </div>
            )}
          </>
        )}

        {/* Empty State (if cleared and no active report) */}
        {!report && !isLoading && (
          <section className="rounded-lg border border-slate-200 bg-white p-10 text-center dark:border-slate-800 dark:bg-slate-900">
            <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
              Bereit für eine Live-Mailprüfung
            </h2>
            <p className="mx-auto mt-1.5 max-w-md text-xs leading-relaxed text-slate-500 dark:text-slate-400">
              Geben Sie oben eine Domain oder E-Mail-Adresse ein, um MX, SPF, DKIM, DMARC, Mail-Ports und DNSBL-Blacklists in Echtzeit zu prüfen.
            </p>
            <button
              type="button"
              onClick={() => runLiveCheck('it-virtuoso.de')}
              className="mt-4 inline-flex items-center gap-1.5 rounded-md bg-blue-600 px-4 py-2 text-xs font-medium text-white transition-colors hover:bg-blue-700"
            >
              <Play className="h-3.5 w-3.5" aria-hidden="true" />
              <span>it-virtuoso.de prüfen</span>
            </button>
          </section>
        )}
      </main>

      <footer className="mt-10 border-t border-slate-200 bg-white py-5 dark:border-slate-800 dark:bg-slate-900">
        <div className="mx-auto flex max-w-[1200px] flex-wrap items-center justify-between gap-4 px-4 text-xs text-slate-500 sm:px-6 dark:text-slate-400">
          <span>Mail Prüfsystem · Live-Diagnose für E-Mail-Infrastruktur</span>
          <span>MX · SPF · DKIM · DMARC · STARTTLS · DNSBL</span>
        </div>
      </footer>
    </div>
  );
}
