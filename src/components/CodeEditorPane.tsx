import React, { useEffect, useRef } from 'react';
import { FileCode2, Trash2 } from 'lucide-react';
import { UI_TEXT } from '../i18n';
import type { AuditRunState, WorkbenchLocale } from '../types/workbench';

export interface CodeEditorPaneProps {
  code: string;
  fileName: string;
  language: string;
  activeLine: number | null;
  runState: AuditRunState;
  timeoutMs: number;
  onCodeChange: (nextCode: string) => void;
  onFileNameChange: (nextFileName: string) => void;
  onClearCode: () => void;
  onRunShortcut: () => void;
  locale?: WorkbenchLocale;
}

const LINE_HEIGHT_PX = 22;

const PANE_COPY: Record<
  WorkbenchLocale,
  {
    fileNameLabel: string;
    fileNamePlaceholder: string;
    clearButton: string;
    editorLabel: string;
    shortcutHint: string;
    linesLabel: string;
    activeLineLabel: string;
    timeoutLabel: string;
    stateLabel: Record<AuditRunState, string>;
  }
> = {
  en: {
    fileNameLabel: 'File path',
    fileNamePlaceholder: 'src/target.ts',
    clearButton: 'Clear',
    editorLabel: 'Source code editor',
    shortcutHint: 'Ctrl/Cmd + Enter to run',
    linesLabel: 'Lines',
    activeLineLabel: 'Focus',
    timeoutLabel: 'Timeout',
    stateLabel: {
      idle: 'IDLE',
      running: 'RUNNING',
      success: 'READY',
      error: 'ERROR',
    },
  },
  id: {
    fileNameLabel: 'Path berkas',
    fileNamePlaceholder: 'src/target.ts',
    clearButton: 'Bersihkan',
    editorLabel: 'Editor kode sumber',
    shortcutHint: 'Ctrl/Cmd + Enter untuk audit',
    linesLabel: 'Baris',
    activeLineLabel: 'Fokus',
    timeoutLabel: 'Batas Waktu',
    stateLabel: {
      idle: 'SIAGA',
      running: 'BERJALAN',
      success: 'SELESAI',
      error: 'GALAT',
    },
  },
};

export const CodeEditorPane: React.FC<CodeEditorPaneProps> = ({
  code,
  fileName,
  language,
  activeLine,
  runState,
  timeoutMs,
  onCodeChange,
  onFileNameChange,
  onClearCode,
  onRunShortcut,
  locale = 'en',
}) => {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const gutterRef = useRef<HTMLDivElement>(null);
  const t = UI_TEXT[locale];
  const copy = PANE_COPY[locale];

  const lines = code.split('\n');
  const lineCount = Math.max(1, lines.length);

  const syncScroll = () => {
    if (gutterRef.current && textareaRef.current) {
      gutterRef.current.scrollTop = textareaRef.current.scrollTop;
    }
  };

  useEffect(() => {
    if (activeLine === null || activeLine < 1 || !textareaRef.current) {
      return;
    }
    const clampedLine = Math.min(activeLine, lineCount);
    let charOffset = 0;
    for (let i = 0; i < clampedLine - 1; i++) {
      charOffset += lines[i].length + 1;
    }
    const el = textareaRef.current;
    el.focus();
    el.setSelectionRange(charOffset, charOffset);
    const scrollTarget = Math.max(0, (clampedLine - 1) * LINE_HEIGHT_PX - 66);
    el.scrollTop = scrollTarget;
    if (gutterRef.current) {
      gutterRef.current.scrollTop = scrollTarget;
    }
  }, [activeLine, lineCount]);

  const handleKeyDown = (event: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      event.preventDefault();
      onRunShortcut();
    }
  };

  const handleGutterClick = (lineNumber: number) => {
    if (!textareaRef.current) return;
    const clampedLine = Math.min(lineNumber, lineCount);
    let charOffset = 0;
    for (let i = 0; i < clampedLine - 1; i++) {
      charOffset += lines[i].length + 1;
    }
    textareaRef.current.focus();
    textareaRef.current.setSelectionRange(charOffset, charOffset);
  };

  return (
    <section
      aria-label={copy.editorLabel}
      className="flex min-h-[540px] flex-col rounded-lg border border-slate-800 bg-[#0D1117]"
    >
      {/* Pane Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 px-3.5 py-2.5">
        <div className="flex min-w-0 flex-1 items-center gap-2">
          <FileCode2 className="h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
          <label htmlFor="workbench-file-name" className="sr-only">
            {copy.fileNameLabel}
          </label>
          <input
            id="workbench-file-name"
            type="text"
            value={fileName}
            onChange={(event) => onFileNameChange(event.target.value)}
            placeholder={copy.fileNamePlaceholder}
            spellCheck={false}
            className="min-w-0 flex-1 rounded border border-slate-800 bg-[#0A0E17] px-2 py-1 font-mono text-xs text-slate-100 placeholder:text-slate-500 focus-visible:border-emerald-500 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-500"
          />
          <span className="shrink-0 rounded border border-slate-800 bg-slate-900 px-2 py-0.5 font-mono text-[11px] text-slate-300">
            {language}
          </span>
        </div>

        <button
          type="button"
          onClick={onClearCode}
          disabled={runState === 'running' || code.length === 0}
          className="inline-flex items-center gap-1.5 rounded border border-slate-700 bg-slate-900 px-2.5 py-1 text-[11px] font-medium text-slate-300 transition-colors hover:border-slate-600 hover:bg-slate-800 hover:text-slate-100 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-400 disabled:cursor-not-allowed disabled:opacity-40"
        >
          <Trash2 className="h-3 w-3 text-slate-400" aria-hidden="true" />
          <span>{copy.clearButton}</span>
        </button>
      </div>

      {/* Mode Transparency Context Strip */}
      <div className="border-b border-slate-800 bg-[#0A0E17]/80 px-3.5 py-2 text-[11px] leading-relaxed text-slate-400">
        {t.editor.browserModeNoticeBeforeMono}
        <code className="font-mono text-slate-200">DG004</code>
        {t.editor.browserModeNoticeMiddle}
        <code className="font-mono text-slate-200">.devguard.json</code>
        {t.editor.browserModeNoticeAfterBase}
      </div>

      {/* Synchronized Gutter + Textarea */}
      <div className="relative flex flex-1 overflow-hidden bg-[#080B12] focus-within:ring-1 focus-within:ring-inset focus-within:ring-emerald-500/60">
        <div
          ref={gutterRef}
          aria-hidden="true"
          className="w-12 shrink-0 select-none overflow-hidden border-r border-slate-800 bg-[#06090F] py-3 text-right font-mono text-xs tabular-nums text-slate-500"
        >
          {Array.from({ length: lineCount }, (_, index) => {
            const lineNumber = index + 1;
            const isActive = activeLine === lineNumber;
            return (
              <div
                key={lineNumber}
                onClick={() => handleGutterClick(lineNumber)}
                style={{ height: `${LINE_HEIGHT_PX}px`, lineHeight: `${LINE_HEIGHT_PX}px` }}
                className={`cursor-pointer pr-2.5 transition-colors ${
                  isActive
                    ? 'border-r-2 border-emerald-400 bg-emerald-500/15 font-semibold text-emerald-300'
                    : 'hover:text-slate-300'
                }`}
              >
                {lineNumber}
              </div>
            );
          })}
        </div>

        <label htmlFor="workbench-code-input" className="sr-only">
          {copy.editorLabel}
        </label>
        <textarea
          id="workbench-code-input"
          ref={textareaRef}
          value={code}
          onChange={(event) => onCodeChange(event.target.value)}
          onScroll={syncScroll}
          onKeyDown={handleKeyDown}
          placeholder={t.editor.placeholder}
          spellCheck={false}
          wrap="off"
          style={{ lineHeight: `${LINE_HEIGHT_PX}px`, tabSize: 2 }}
          className="h-full min-h-[420px] w-full flex-1 resize-none overflow-auto bg-transparent px-3 py-3 font-mono text-xs text-slate-100 placeholder:text-slate-600 focus:outline-none"
        />
      </div>

      {/* Footer Status Strip */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-800 bg-[#0A0E17] px-3.5 py-2 font-mono text-[11px] text-slate-400">
        <div className="flex items-center gap-3">
          <span>
            {copy.linesLabel}: {lineCount}
          </span>
          {activeLine !== null && (
            <span className="text-emerald-400">
              {copy.activeLineLabel}: L{activeLine}
            </span>
          )}
          <span>
            {copy.timeoutLabel}: {Math.round(timeoutMs / 1000)}s
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-slate-500">{copy.shortcutHint}</span>
          <span className="rounded border border-slate-800 bg-slate-900 px-1.5 py-0.5 text-[10px] text-slate-300">
            {copy.stateLabel[runState]}
          </span>
        </div>
      </div>
    </section>
  );
};
