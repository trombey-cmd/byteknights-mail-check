import { AlertTriangle, CheckCircle2, Info, Loader2, XCircle } from 'lucide-react';
import type { CheckSeverity } from '../types/mailcheck';

interface StatusIndicatorProps {
  status: CheckSeverity;
  label?: string;
}

const DEFAULT_LABELS: Record<CheckSeverity, string> = {
  ok: 'Bestanden',
  warn: 'Warnung',
  error: 'Fehler',
  info: 'Hinweis',
  pending: 'Prüft…',
};

export function StatusIndicator({ status, label }: StatusIndicatorProps) {
  const text = label ?? DEFAULT_LABELS[status];

  switch (status) {
    case 'ok':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-400 whitespace-nowrap shrink-0">
          <CheckCircle2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span>{text}</span>
        </span>
      );
    case 'warn':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-amber-700 dark:text-amber-400 whitespace-nowrap shrink-0">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span>{text}</span>
        </span>
      );
    case 'error':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-red-700 dark:text-red-400 whitespace-nowrap shrink-0">
          <XCircle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span>{text}</span>
        </span>
      );
    case 'pending':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-500 dark:text-slate-400 whitespace-nowrap shrink-0">
          <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" aria-hidden="true" />
          <span>{text}</span>
        </span>
      );
    case 'info':
    default:
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 dark:text-slate-400 whitespace-nowrap shrink-0">
          <Info className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span>{text}</span>
        </span>
      );
  }
}
