package report

import (
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const htmlTemplateStr = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VibeGuard Security Report — {{.ProjectName}}</title>
    <style>
        :root {
            --bg-page: #0b0f19;
            --bg-surface: #0f172a;
            --bg-card: #1e293b;
            --bg-muted: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --border-color: #334155;
            --border-subtle: #1e293b;

            --critical-bg: rgba(239, 68, 68, 0.12);
            --critical-border: rgba(239, 68, 68, 0.35);
            --critical-text: #f87171;

            --high-bg: rgba(249, 115, 22, 0.12);
            --high-border: rgba(249, 115, 22, 0.35);
            --high-text: #fb923c;

            --medium-bg: rgba(245, 158, 11, 0.12);
            --medium-border: rgba(245, 158, 11, 0.35);
            --medium-text: #fbbf24;

            --low-bg: rgba(14, 165, 233, 0.12);
            --low-border: rgba(14, 165, 233, 0.35);
            --low-text: #38bdf8;

            --info-bg: rgba(148, 163, 184, 0.12);
            --info-border: rgba(148, 163, 184, 0.35);
            --info-text: #cbd5e1;

            --passed-bg: rgba(16, 185, 129, 0.12);
            --passed-border: rgba(16, 185, 129, 0.4);
            --passed-text: #34d399;

            --blocked-bg: rgba(239, 68, 68, 0.12);
            --blocked-border: rgba(239, 68, 68, 0.4);
            --blocked-text: #f87171;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-page);
            color: var(--text-primary);
            line-height: 1.5;
            padding: 24px 16px;
        }

        .report-wrapper {
            max-width: 1240px;
            margin: 0 auto;
            background: var(--bg-surface);
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.4);
            overflow: hidden;
            border: 1px solid var(--border-color);
        }

        /* Top Executive Header */
        .exec-header {
            background: linear-gradient(135deg, #070b14 0%, #0f172a 100%);
            color: #ffffff;
            padding: 28px 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
            border-bottom: 1px solid var(--border-color);
        }

        .brand-section {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .shield-icon {
            width: 44px;
            height: 44px;
            background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
        }

        .shield-icon svg {
            width: 26px;
            height: 26px;
            fill: #ffffff;
        }

        .brand-text h1 {
            font-size: 24px;
            font-weight: 700;
            letter-spacing: -0.5px;
            margin-bottom: 4px;
            display: flex;
            align-items: center;
            gap: 10px;
            color: #ffffff;
        }

        .brand-text h1 .version-badge {
            font-size: 11px;
            font-weight: 600;
            background: rgba(255,255,255,0.15);
            padding: 2px 8px;
            border-radius: 12px;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .btn-action {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 18px;
            font-size: 14px;
            font-weight: 600;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.15s ease;
            text-decoration: none;
            border: 1px solid transparent;
        }

        .btn-pdf {
            background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
            color: #ffffff;
            box-shadow: 0 2px 8px rgba(37, 99, 235, 0.35);
        }

        .btn-pdf:hover {
            background: linear-gradient(135deg, #1d4ed8 0%, #1e40af 100%);
            box-shadow: 0 4px 12px rgba(37, 99, 235, 0.45);
            transform: translateY(-1px);
        }

        /* Metadata Strip */
        .meta-strip {
            background: #090d16;
            border-bottom: 1px solid var(--border-color);
            padding: 14px 32px;
            display: flex;
            flex-wrap: wrap;
            gap: 24px;
            font-size: 13px;
            color: var(--text-secondary);
        }

        .meta-item {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .meta-item strong {
            color: var(--text-primary);
        }

        .meta-item svg {
            width: 16px;
            height: 16px;
            fill: var(--text-muted);
        }

        /* Body Container */
        .content-body {
            padding: 32px;
        }

        /* Posture Banner */
        .posture-banner {
            border-radius: 10px;
            padding: 20px 24px;
            margin-bottom: 28px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
            border: 1px solid;
        }

        .posture-banner.passed {
            background-color: var(--passed-bg);
            border-color: var(--passed-border);
            color: var(--passed-text);
        }

        .posture-banner.blocked {
            background-color: var(--blocked-bg);
            border-color: var(--blocked-border);
            color: var(--blocked-text);
        }

        .posture-left {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .posture-icon {
            width: 44px;
            height: 44px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 22px;
        }

        .posture-banner.passed .posture-icon {
            background: rgba(16, 185, 129, 0.2);
            color: #34d399;
        }

        .posture-banner.blocked .posture-icon {
            background: rgba(239, 68, 68, 0.2);
            color: #f87171;
        }

        .posture-title {
            font-size: 18px;
            font-weight: 700;
        }

        .posture-reason {
            font-size: 14px;
            opacity: 0.9;
            margin-top: 2px;
        }

        .score-pill {
            padding: 8px 18px;
            border-radius: 30px;
            font-size: 20px;
            font-weight: 800;
            background: #1e293b;
            border: 1px solid var(--border-color);
            box-shadow: 0 2px 6px rgba(0,0,0,0.2);
            display: flex;
            align-items: center;
            gap: 6px;
            color: var(--text-primary);
        }

        /* Severity Cards Grid */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }

        .sev-card {
            padding: 18px 20px;
            border-radius: 10px;
            border: 1px solid;
            cursor: pointer;
            transition: all 0.15s ease;
            position: relative;
        }

        .sev-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.3);
        }

        .sev-card.active {
            outline: 2px solid #3b82f6;
            outline-offset: 2px;
        }

        .sev-card .sev-count {
            font-size: 28px;
            font-weight: 800;
            line-height: 1;
            margin-bottom: 4px;
        }

        .sev-card .sev-name {
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        .sev-card.critical { background: var(--critical-bg); border-color: var(--critical-border); color: var(--critical-text); }
        .sev-card.high     { background: var(--high-bg); border-color: var(--high-border); color: var(--high-text); }
        .sev-card.medium   { background: var(--medium-bg); border-color: var(--medium-border); color: var(--medium-text); }
        .sev-card.low      { background: var(--low-bg); border-color: var(--low-border); color: var(--low-text); }
        .sev-card.info     { background: var(--info-bg); border-color: var(--info-border); color: var(--info-text); }

        /* Controls / Filter Strip */
        .controls-strip {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
            margin-bottom: 20px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border-color);
        }

        .section-title {
            font-size: 18px;
            font-weight: 700;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .badge-count {
            font-size: 12px;
            font-weight: 600;
            background: #1e293b;
            color: #cbd5e1;
            padding: 2px 8px;
            border-radius: 10px;
            border: 1px solid var(--border-color);
        }

        .search-box {
            position: relative;
            min-width: 280px;
        }

        .search-box input {
            width: 100%;
            padding: 8px 14px 8px 34px;
            font-size: 13px;
            background: #1e293b;
            color: var(--text-primary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            outline: none;
            transition: border-color 0.15s;
        }

        .search-box input:focus {
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
        }

        .search-box svg {
            position: absolute;
            left: 10px;
            top: 50%;
            transform: translateY(-50%);
            width: 15px;
            height: 15px;
            fill: var(--text-muted);
        }

        /* Findings Table */
        .table-responsive {
            overflow-x: auto;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 36px;
            background: var(--bg-surface);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: left;
        }

        th {
            background: #1e293b;
            color: var(--text-secondary);
            font-weight: 700;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
        }

        td {
            padding: 14px 16px;
            border-bottom: 1px solid var(--border-subtle);
            vertical-align: top;
            color: #cbd5e1;
        }

        tr:last-child td {
            border-bottom: none;
        }

        tr:hover td {
            background-color: rgba(30, 41, 59, 0.5);
        }

        /* Badges */
        .pill {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            white-space: nowrap;
        }

        .pill.critical { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4); }
        .pill.high     { background: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.4); }
        .pill.medium   { background: rgba(245, 158, 11, 0.2); color: #fde047; border: 1px solid rgba(245, 158, 11, 0.4); }
        .pill.low      { background: rgba(14, 165, 233, 0.2); color: #7dd3fc; border: 1px solid rgba(14, 165, 233, 0.4); }
        .pill.info     { background: rgba(148, 163, 184, 0.2); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.4); }

        .cat-tag {
            font-size: 11px;
            color: var(--text-secondary);
            background: #1e293b;
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: 500;
            border: 1px solid var(--border-color);
        }

        .file-location {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 12px;
            color: #f1f5f9;
            font-weight: 600;
            word-break: break-all;
        }

        .evidence-box {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 12px;
            background: #030712;
            color: #38bdf8;
            padding: 6px 10px;
            border-radius: 6px;
            margin-top: 6px;
            display: inline-block;
            word-break: break-all;
            border: 1px solid #1e293b;
        }

        .rec-box {
            margin-top: 4px;
            color: #34d399;
            font-size: 12px;
            display: flex;
            align-items: flex-start;
            gap: 4px;
        }

        .rec-box svg {
            width: 14px;
            height: 14px;
            fill: #34d399;
            flex-shrink: 0;
            margin-top: 2px;
        }

        .empty-state {
            padding: 36px 20px;
            text-align: center;
            color: #34d399;
            background: rgba(16, 185, 129, 0.08);
            border: 1px dashed rgba(16, 185, 129, 0.3);
            border-radius: 8px;
            font-weight: 600;
            font-size: 14px;
        }

        /* Footer */
        .report-footer {
            padding: 20px 32px;
            background: #090d16;
            border-top: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
            font-size: 12px;
            color: var(--text-muted);
        }

        /* Print / PDF Styling */
        @media print {
            @page {
                size: A4 portrait;
                margin: 10mm 8mm;
            }

            body {
                background: #0b0f19 !important;
                padding: 0 !important;
                color: #f8fafc !important;
                -webkit-print-color-adjust: exact !important;
                print-color-adjust: exact !important;
            }

            .report-wrapper {
                background: #0f172a !important;
                box-shadow: none !important;
                border: 1px solid #334155 !important;
                max-width: 100% !important;
            }

            .exec-header {
                background: #070b14 !important;
                color: #ffffff !important;
                -webkit-print-color-adjust: exact !important;
                print-color-adjust: exact !important;
                padding: 16px 20px !important;
            }

            .no-print, .header-actions, .search-box, .btn-action {
                display: none !important;
            }

            .summary-grid {
                grid-template-columns: repeat(5, 1fr) !important;
                gap: 8px !important;
                margin-bottom: 20px !important;
            }

            .sev-card {
                padding: 10px !important;
                -webkit-print-color-adjust: exact !important;
                print-color-adjust: exact !important;
            }

            .sev-card .sev-count {
                font-size: 20px !important;
            }

            .table-responsive {
                overflow: visible !important;
                border: 1px solid #334155 !important;
                background: #0f172a !important;
            }

            table {
                page-break-inside: auto !important;
            }

            tr {
                page-break-inside: avoid !important;
                page-break-after: auto !important;
            }

            th, td {
                padding: 8px 10px !important;
                font-size: 11px !important;
            }

            th {
                background: #1e293b !important;
                color: #94a3b8 !important;
                -webkit-print-color-adjust: exact !important;
                print-color-adjust: exact !important;
            }

            td {
                color: #cbd5e1 !important;
                border-bottom: 1px solid #1e293b !important;
            }

            .evidence-box {
                background: #030712 !important;
                color: #38bdf8 !important;
                border: 1px solid #1e293b !important;
                -webkit-print-color-adjust: exact !important;
                print-color-adjust: exact !important;
            }
        }
    </style>
</head>
<body>
    <div class="report-wrapper">
        <!-- Executive Header -->
        <header class="exec-header">
            <div class="brand-section">
                <div class="shield-icon">
                    <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/></svg>
                </div>
                <div class="brand-text">
                    <h1>VibeGuard Security Report <span class="version-badge">v5.1.0</span></h1>
                    <div style="font-size: 13px; opacity: 0.85;">Enterprise Git Pre-Push Gate & Code Security Scanner</div>
                </div>
            </div>

            <div class="header-actions no-print">
                <button onclick="window.print()" class="btn-action btn-pdf" title="Export this report to PDF via print dialog">
                    <svg style="width: 16px; height: 16px; fill: currentColor;" viewBox="0 0 24 24"><path d="M19 8H5c-1.66 0-3 1.34-3 3v6h4v4h12v-4h4v-6c0-1.66-1.34-3-3-3zm-3 11H8v-5h8v5zm3-7c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1zm-1-9H6v4h12V3z"/></svg>
                    Export / Print PDF
                </button>
            </div>
        </header>

        <!-- Metadata Strip with Date & Time -->
        <div class="meta-strip">
            <div class="meta-item">
                <svg viewBox="0 0 24 24"><path d="M19 3h-1V1h-2v2H8V1H6v2H5c-1.11 0-1.99.9-1.99 2L3 19c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H5V8h14v11zM7 10h5v5H7z"/></svg>
                <span><strong>Scan Date & Time:</strong> {{if .Timestamp}}{{.Timestamp}}{{else}}{{.ScanTime}}{{end}}</span>
            </div>
            <div class="meta-item">
                <svg viewBox="0 0 24 24"><path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z"/></svg>
                <span><strong>Scan Duration:</strong> {{.ScanTime}}</span>
            </div>
            <div class="meta-item">
                <svg viewBox="0 0 24 24"><path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>
                <span><strong>Project:</strong> {{.ProjectName}}</span>
            </div>
            {{if .Branch}}
            <div class="meta-item">
                <svg viewBox="0 0 24 24"><path d="M21 6a3 3 0 0 0-3-3 3 3 0 0 0-3 3c0 1.3.84 2.4 2 2.82V12c0 1.66-1.34 3-3 3H9.83c-.41-1.16-1.52-2-2.83-2a3 3 0 0 0-3 3 3 3 0 0 0 3 3c1.3 0 2.4-.84 2.82-2H14c2.76 0 5-2.24 5-5V8.82c1.16-.41 2-1.51 2-2.82z"/></svg>
                <span><strong>Branch:</strong> {{.Branch}}</span>
            </div>
            {{end}}
            {{if .CommitHash}}
            <div class="meta-item">
                <svg viewBox="0 0 24 24"><path d="M19 13a6 6 0 1 1-6-6 6 6 0 0 1 6 6zm-6-4a4 4 0 1 0 4 4 4 4 0 0 0-4-4z"/></svg>
                <span><strong>Commit:</strong> {{.CommitHash}}</span>
            </div>
            {{end}}
            <div class="meta-item">
                <svg viewBox="0 0 24 24"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>
                <span><strong>Files Scanned:</strong> {{.FilesScanned}}</span>
            </div>
            {{if .SuppressedCount}}
            <div class="meta-item">
                <span><strong>Suppressed:</strong> {{.SuppressedCount}}</span>
            </div>
            {{end}}
        </div>

        <div class="content-body">
            <!-- Posture & Status Banner -->
            <div class="posture-banner {{if eq .GateResult.Status "PASSED"}}passed{{else}}blocked{{end}}">
                <div class="posture-left">
                    <div class="posture-icon">
                        {{if eq .GateResult.Status "PASSED"}}✓{{else}}✕{{end}}
                    </div>
                    <div>
                        <div class="posture-title">Deployment Gate: {{.GateResult.Status}}</div>
                        <div class="posture-reason">{{if .GateResult.Reason}}{{.GateResult.Reason}}{{else}}All security policy verifications cleared successfully.{{end}}</div>
                    </div>
                </div>
                <div class="score-pill">
                    <span>Score:</span>
                    <span style="{{if eq .GateResult.Status "PASSED"}}color: #34d399;{{else}}color: #f87171;{{end}}">{{.ScoreResult.Score}}/100</span>
                </div>
            </div>

            <!-- Severity Counters Grid -->
            <div class="summary-grid">
                <div class="sev-card critical" onclick="filterBySeverity('CRITICAL')">
                    <div class="sev-count">{{.ScoreResult.CriticalCount}}</div>
                    <div class="sev-name">Critical</div>
                </div>
                <div class="sev-card high" onclick="filterBySeverity('HIGH')">
                    <div class="sev-count">{{.ScoreResult.HighCount}}</div>
                    <div class="sev-name">High</div>
                </div>
                <div class="sev-card medium" onclick="filterBySeverity('MEDIUM')">
                    <div class="sev-count">{{.ScoreResult.MediumCount}}</div>
                    <div class="sev-name">Medium</div>
                </div>
                <div class="sev-card low" onclick="filterBySeverity('LOW')">
                    <div class="sev-count">{{.ScoreResult.LowCount}}</div>
                    <div class="sev-name">Low</div>
                </div>
                <div class="sev-card info" onclick="filterBySeverity('INFO')">
                    <div class="sev-count">{{.ScoreResult.InfoCount}}</div>
                    <div class="sev-name">Info</div>
                </div>
            </div>

            <!-- Code, Secrets & Config Findings -->
            <div class="controls-strip">
                <div class="section-title">
                    <span>Code, Secret & Configuration Findings</span>
                    <span class="badge-count" id="findings-count">{{len .Findings}}</span>
                </div>

                <div class="search-box no-print">
                    <svg viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
                    <input type="text" id="findingSearch" placeholder="Search by title, file, ID, rule..." onkeyup="filterFindings()">
                </div>
            </div>

            {{if .Findings}}
            <div class="table-responsive">
                <table id="findingsTable">
                    <thead>
                        <tr>
                            <th style="width: 100px;">Severity</th>
                            <th style="width: 130px;">Rule ID</th>
                            <th style="width: 250px;">Issue & Description</th>
                            <th>Location & Evidence</th>
                            <th style="width: 280px;">Remediation Guidance</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .Findings}}
                        <tr class="finding-row" data-severity="{{.Severity | upper}}">
                            <td>
                                <span class="pill {{.Severity | lower}}">{{.Severity}}</span>
                            </td>
                            <td>
                                <div style="font-weight: 700; font-family: monospace;">{{.ID}}</div>
                                <span class="cat-tag">{{.Category}}</span>
                                {{if .Confidence}}
                                <div style="font-size: 10px; color: var(--text-muted); margin-top: 2px;">Conf: {{.Confidence}}</div>
                                {{end}}
                            </td>
                            <td>
                                <div style="font-weight: 700; margin-bottom: 2px;">{{.Title}}</div>
                                <div style="font-size: 12px; color: var(--text-secondary);">{{.Description}}</div>
                            </td>
                            <td>
                                <div class="file-location">{{.File}}:{{.Line}}</div>
                                {{if .Evidence}}
                                <div class="evidence-box">{{.Evidence}}</div>
                                {{end}}
                            </td>
                            <td>
                                <div class="rec-box">
                                    <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
                                    <span>{{.Recommendation}}</span>
                                </div>
                            </td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
            {{else}}
            <div class="empty-state">
                ✓ Zero code vulnerabilities, hardcoded secrets, or misconfigurations detected.
            </div>
            {{end}}

            <!-- Dependency Vulnerabilities Section -->
            {{if .Dependencies}}
            <div class="controls-strip" style="margin-top: 28px;">
                <div class="section-title">
                    <span>Dependency Vulnerabilities (SCA via Google OSV)</span>
                    <span class="badge-count">{{len .Dependencies}} packages</span>
                </div>
            </div>

            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>Package</th>
                            <th>Installed Version</th>
                            <th>Ecosystem</th>
                            <th>Advisory ID</th>
                            <th>Vulnerability Summary</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .Dependencies}}
                            {{$pkg := .PackageName}}
                            {{$ver := .InstalledVersion}}
                            {{$eco := .Ecosystem}}
                            {{range .Vulnerabilities}}
                            <tr>
                                <td style="font-weight: 700;">{{$pkg}}</td>
                                <td><code>{{$ver}}</code></td>
                                <td><span class="cat-tag">{{$eco}}</span></td>
                                <td style="font-weight: 600; font-family: monospace; color: #38bdf8;">{{.ID}}</td>
                                <td>{{.Summary}}</td>
                            </tr>
                            {{end}}
                        {{end}}
                    </tbody>
                </table>
            </div>
            {{end}}
        </div>

        <!-- Footer -->
        <footer class="report-footer">
            <div>
                Generated autonomously by <strong>VibeGuard v5.1.0</strong> • Enterprise Pre-Push Security Gate
            </div>
            <div>
                Report Timestamp: {{if .Timestamp}}{{.Timestamp}}{{else}}{{.ScanTime}}{{end}}
            </div>
        </footer>
    </div>

    <!-- Client-side Interactive Filter Script -->
    <script>
        let currentFilter = 'ALL';

        function filterBySeverity(sev) {
            currentFilter = (currentFilter === sev) ? 'ALL' : sev;
            
            // Highlight active card
            document.querySelectorAll('.sev-card').forEach(card => {
                if (currentFilter !== 'ALL' && card.classList.contains(currentFilter.toLowerCase())) {
                    card.classList.add('active');
                } else {
                    card.classList.remove('active');
                }
            });

            applyFilters();
        }

        function filterFindings() {
            applyFilters();
        }

        function applyFilters() {
            const query = (document.getElementById('findingSearch') ? document.getElementById('findingSearch').value : '').toLowerCase();
            const rows = document.querySelectorAll('.finding-row');
            let visibleCount = 0;

            rows.forEach(row => {
                const rowSev = row.getAttribute('data-severity');
                const rowText = row.innerText.toLowerCase();
                
                const matchesSev = (currentFilter === 'ALL' || rowSev === currentFilter);
                const matchesQuery = !query || rowText.includes(query);

                if (matchesSev && matchesQuery) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            });

            const countBadge = document.getElementById('findings-count');
            if (countBadge) {
                countBadge.innerText = visibleCount;
            }
        }
    </script>
</body>
</html>`

func WriteHTMLReport(r *Report, outputPath string) error {
	absPath, err := filepath.Abs(filepath.Clean(outputPath))
	if err != nil {
		absPath = filepath.Clean(outputPath)
	}

	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Ensure timestamp is present if empty
	if r.Timestamp == "" {
		r.Timestamp = time.Now().Format("2006-01-02 15:04:05 MST")
	}

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"upper": func(s string) string {
			return strings.ToUpper(s)
		},
		"lower": func(s string) string {
			return strings.ToLower(s)
		},
		"js": func(s string) string {
			switch strings.ToUpper(s) {
			case "CRITICAL":
				return "critical"
			case "HIGH":
				return "high"
			case "MEDIUM":
				return "medium"
			case "LOW":
				return "low"
			case "INFO":
				return "info"
			default:
				return "info"
			}
		},
	}).Parse(htmlTemplateStr)
	if err != nil {
		return err
	}

	var f *os.File
	f, err = os.Create(absPath)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, r)
}
