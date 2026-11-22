import React from 'react';
import { Download, Play, RefreshCw, ShieldCheck } from 'lucide-react';
import type {
  AuditRunState,
  CodePreset,
  ExportFormat,
  WorkbenchLocale,
} from '../types/workbench';

export interface CommandBarProps {
  versionLabel: string;
  locale: WorkbenchLocale;
  presets: CodePreset[];
  selectedPresetId: string;
  runState: AuditRunState;
  canExport: boolean;
  onLocaleChange: (nextLocale: WorkbenchLocale) => void;
  onSelectPreset: (presetId: string) => void;
  onRunAudit: () => void;
  onExport: (format: ExportFormat) => void;
}

const LABELS: Record<
  WorkbenchLocale,
  {
    modeBadge: string;
    presetLabel: string;
    runAudit: string;
    running: string;
    exportJson: string;
    exportSarif: string;
    langGroupLabel: string;
  }
> = {
  en: {
    modeBadge: 'Single-File Browser',
    presetLabel: 'Preset',
    runAudit: 'Run Audit',
    running: 'Auditing...',
    exportJson: 'JSON',
    exportSarif: 'SARIF',
    langGroupLabel: 'Language switcher',
  },
  id: {
    modeBadge: 'Single-File Browser',
    presetLabel: 'Preset',
    runAudit: 'Jalankan Audit',
    running: 'Mengaudit...',
    exportJson: 'JSON',
    exportSarif: 'SARIF',
    langGroupLabel: 'Pengalih bahasa',
  },
};

export const CommandBar: React.FC<CommandBarProps> = ({
  versionLabel,
  locale,
  presets,
  selectedPresetId,
  runState,
  canExport,
  onLocaleChange,
  onSelectPreset,
  onRunAudit,
  onExport,
}) => {
  const copy = LABELS[locale];
  const isRunning = runState === 'running';

  return (
    <header className="sticky top-0 z-40 border-b border-slate-800 bg-[#0D1117] px-4 py-2.5 lg:px-6">
      <div className="mx-auto flex max-w-[1600px] flex-wrap items-center justify-between gap-3">
        {/* Identity & Active Mode */}
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-md border border-slate-700 bg-slate-900 text-emerald-400">
            <ShieldCheck className="h-4 w-4" aria-hidden="true" />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold tracking-tight text-slate-100">
              DevGuard
            </span>
            <span className="rounded border border-slate-800 bg-slate-900 px-1.5 py-0.5 font-mono text-[11px] text-slate-400">
              {versionLabel}
            </span>
            <span className="hidden rounded border border-slate-700/80 bg-slate-900/90 px-2 py-0.5 font-mono text-[11px] text-slate-300 sm:inline-block">
              {copy.modeBadge}
            </span>
          </div>
        </div>

        {/* Workbench Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Preset Selector */}
          <div className="flex items-center gap-1.5">
            <label
              htmlFor="workbench-preset-select"
              className="text-xs font-medium text-slate-400"
            >
              {copy.presetLabel}
            </label>
            <select
              id="workbench-preset-select"
              value={selectedPresetId}
              onChange={(event) => onSelectPreset(event.target.value)}
              disabled={isRunning}
              className="h-8 rounded-md border border-slate-700 bg-[#0A0E17] px-2.5 text-xs text-slate-200 focus-visible:border-emerald-500 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {presets.map((preset) => (
                <option key={preset.id} value={preset.id}>
                  {preset.label} ({preset.language})
                </option>
              ))}
            </select>
          </div>

          {/* Locale Switcher */}
          <div
            role="group"
            aria-label={copy.langGroupLabel}
            className="flex items-center rounded-md border border-slate-800 bg-[#0A0E17] p-0.5 font-mono text-[11px]"
          >
            <button
              type="button"
              aria-pressed={locale === 'en'}
              onClick={() => onLocaleChange('en')}
              className={`rounded px-2 py-1 transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-400 ${
                locale === 'en'
                  ? 'bg-slate-800 font-semibold text-slate-100'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              EN
            </button>
            <button
              type="button"
              aria-pressed={locale === 'id'}
              onClick={() => onLocaleChange('id')}
              className={`rounded px-2 py-1 transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-400 ${
                locale === 'id'
                  ? 'bg-slate-800 font-semibold text-slate-100'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              ID
            </button>
          </div>

          {/* Export Actions */}
          <div className="flex items-center gap-1">
            <button
              type="button"
              disabled={!canExport || isRunning}
              onClick={() => onExport('json')}
              className="inline-flex h-8 items-center gap-1.5 rounded-md border border-slate-700 bg-slate-900 px-2.5 font-mono text-[11px] font-medium text-slate-200 transition-colors hover:border-slate-600 hover:bg-slate-800 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-400 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Download className="h-3 w-3 text-slate-400" aria-hidden="true" />
              <span>{copy.exportJson}</span>
            </button>
            <button
              type="button"
              disabled={!canExport || isRunning}
              onClick={() => onExport('sarif')}
              className="inline-flex h-8 items-center gap-1.5 rounded-md border border-slate-700 bg-slate-900 px-2.5 font-mono text-[11px] font-medium text-slate-200 transition-colors hover:border-slate-600 hover:bg-slate-800 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-400 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Download className="h-3 w-3 text-slate-400" aria-hidden="true" />
              <span>{copy.exportSarif}</span>
            </button>
          </div>

          {/* Primary Audit Trigger */}
          <button
            type="button"
            disabled={isRunning}
            onClick={onRunAudit}
            className="inline-flex h-8 items-center gap-1.5 rounded-md bg-emerald-600 px-3.5 text-xs font-semibold text-white transition-colors hover:bg-emerald-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400 focus-visible:ring-offset-1 focus-visible:ring-offset-[#0D1117] disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isRunning ? (
              <>
                <RefreshCw className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                <span>{copy.running}</span>
              </>
            ) : (
              <>
                <Play className="h-3.5 w-3.5 fill-current" aria-hidden="true" />
                <span>{copy.runAudit}</span>
              </>
            )}
          </button>
        </div>
      </div>
    </header>
  );
};
