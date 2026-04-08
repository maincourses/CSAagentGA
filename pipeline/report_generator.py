import json
import os
import csv
import html as html_lib
from datetime import datetime
from typing import List
from models.report import FinalReport, DefectReport


class ReportGenerator:
    """将 FinalReport 输出为 JSON、CSV 或 HTML 格式"""

    def __init__(self, output_dir: str = "data/reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(self, report: FinalReport, formats: List[str] = None) -> List[str]:
        formats = formats or ["json", "html"]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        generated_files = []

        if "json" in formats:
            path = self._write_json(report, timestamp)
            generated_files.append(path)
        if "csv" in formats:
            path = self._write_csv(report, timestamp)
            generated_files.append(path)
        if "html" in formats:
            path = self._write_html(report, timestamp)
            generated_files.append(path)

        return generated_files

    def _write_json(self, report: FinalReport, ts: str) -> str:
        path = os.path.join(self.output_dir, f"report_{ts}.json")
        data = {
            "project_path": report.project_path,
            "generated_at": report.generated_at,
            "summary": {
                "total_raw_findings": report.total_raw_findings,
                "total_analyzed": report.total_analyzed,
                "analyzer_failure_count": len(report.analyzer_failures),
                "true_positives": report.true_positives,
                "false_positives": report.false_positives,
                "uncertain": report.uncertain,
                "false_positive_rate": round(report.false_positive_rate, 4),
                "tool_stats": report.tool_stats,
                "analyzer_failure_stats": report.analyzer_failure_stats,
            },
            "findings": [self._report_to_dict(r) for r in report.reports],
            "analysis_failures": [self._failure_to_dict(f) for f in report.analyzer_failures],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return path

    def _write_csv(self, report: FinalReport, ts: str) -> str:
        path = os.path.join(self.output_dir, f"report_{ts}.csv")
        fieldnames = [
            "verdict", "confidence", "tool", "file_path", "line",
            "defect_id", "cwe", "message", "function_name",
            "fixed_code", "fix_explanation", "reasoning",
        ]
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
            writer.writeheader()
            for r in report.reports:
                raw = r.finding.raw
                writer.writerow({
                    "verdict": r.verdict,
                    "confidence": r.confidence,
                    "tool": raw.tool,
                    "file_path": raw.file_path,
                    "line": raw.line,
                    "defect_id": raw.defect_id,
                    "cwe": raw.cwe or "",
                    "message": raw.message,
                    "function_name": r.finding.function_name,
                    "fixed_code": r.fixed_code,
                    "fix_explanation": r.fix_explanation,
                    "reasoning": " | ".join(r.reasoning_chain),
                })
        return path

    def _write_html(self, report: FinalReport, ts: str) -> str:
        path = os.path.join(self.output_dir, f"report_{ts}.html")

        rows = ""
        meta_items = []
        for idx, r in enumerate(report.reports):
            raw = r.finding.raw
            verdict_class = {
                "TRUE_POSITIVE": "verdict-tp",
                "FALSE_POSITIVE": "verdict-fp",
                "UNCERTAIN": "verdict-uc"
            }.get(r.verdict, "verdict-uc")
            verdict_label = {
                "TRUE_POSITIVE": "真阳性",
                "FALSE_POSITIVE": "假阳性",
                "UNCERTAIN": "不确定"
            }.get(r.verdict, r.verdict)
            confidence_pct = int(r.confidence * 100)
            confidence_color = "#e74c3c" if r.confidence >= 0.8 else ("#e67e22" if r.confidence >= 0.6 else "#27ae60")

            reasoning_steps = ""
            if r.reasoning_chain:
                for step in r.reasoning_chain:
                    reasoning_steps += f"<li>{step}</li>"
            else:
                reasoning_steps = "<li>-</li>"

            fix_content = f"<pre class='code-block'>{r.fixed_code}</pre>" if r.fixed_code else "<span class='empty-hint'>无修复建议</span>"

            rows += f"""
            <div class="finding-card {verdict_class}" id="card-{idx}" data-id="{idx}">
                <div class="card-header">
                    <div class="header-left">
                        <span class="index-badge">#{idx + 1}</span>
                        <span class="verdict-badge {verdict_class}">{verdict_label}</span>
                        <span class="tool-badge">{raw.tool}</span>
                        <span class="location-text">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                            {os.path.basename(raw.file_path)}:<strong>{raw.line}</strong>
                        </span>
                        <span class="defect-type">{raw.defect_id}</span>
                    </div>
                    <div class="header-right">
                        <div class="confidence-bar-wrap" title="置信度 {r.confidence:.0%}">
                            <span class="confidence-label">置信度</span>
                            <div class="confidence-bar">
                                <div class="confidence-fill" style="width:{confidence_pct}%;background:{confidence_color}"></div>
                            </div>
                            <span class="confidence-value" style="color:{confidence_color}">{r.confidence:.0%}</span>
                        </div>
                        <button class="toggle-btn" onclick="toggleCard({idx})">
                            <svg class="chevron" id="chevron-{idx}" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
                        </button>
                    </div>
                </div>
                <div class="card-summary">
                    <span class="summary-message">{raw.message}</span>
                    {f'<span class="func-tag">⨍ {r.finding.function_name}</span>' if r.finding.function_name else ''}
                </div>
                <div class="card-body" id="body-{idx}">
                    <div class="content-grid">
                        <div class="content-section">
                            <div class="section-title">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                                推理链
                            </div>
                            <ol class="reasoning-list">{reasoning_steps}</ol>
                        </div>
                        <div class="content-section">
                            <div class="section-title">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                                修复建议
                            </div>
                            {fix_content}
                        </div>
                    </div>
                    <div class="annotation-panel">
                        <div class="annotation-title">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                            人工标注
                        </div>
                        <div class="annotation-buttons">
                            <button class="ann-btn ann-tp" onclick="setAnnotation({idx}, 'TRUE_POSITIVE')" id="ann-tp-{idx}">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                                真缺陷
                            </button>
                            <button class="ann-btn ann-fp" onclick="setAnnotation({idx}, 'FALSE_POSITIVE')" id="ann-fp-{idx}">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                                误报
                            </button>
                            <button class="ann-btn ann-uc" onclick="setAnnotation({idx}, 'UNCERTAIN')" id="ann-uc-{idx}">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                                待定
                            </button>
                            <button class="ann-btn ann-clear" onclick="clearAnnotation({idx})">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>
                                清除
                            </button>
                        </div>
                        <div class="annotation-note-wrap">
                            <textarea
                                class="annotation-note"
                                id="note-{idx}"
                                placeholder="在此填写标注备注说明..."
                                oninput="saveAnnotation({idx})"
                                rows="2"
                            ></textarea>
                        </div>
                        <div class="ann-status" id="ann-status-{idx}"></div>
                    </div>
                </div>
            </div>"""

            meta_items.append({
                "tool": raw.tool,
                "file": os.path.basename(raw.file_path),
                "line": raw.line,
                "defect_id": raw.defect_id,
                "ai_verdict": r.verdict,
                "ai_confidence": r.confidence,
            })

        findings_meta_js = json.dumps(meta_items, ensure_ascii=False)
        failure_section = self._build_failure_section(report)

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DefectAware 缺陷报告 - {ts}</title>
<style>
  :root {{
    --bg: #f0f2f5;
    --surface: #ffffff;
    --surface2: #f5f6fa;
    --border: #dde1ea;
    --border-light: #c4c9d8;
    --text: #1a1d2e;
    --text-muted: #5a6278;
    --text-dim: #9399a8;
    --accent: #4f52c8;
    --accent-hover: #3d40b5;
    --tp-bg: rgba(220,38,38,0.06);
    --tp-border: rgba(220,38,38,0.30);
    --tp-color: #dc2626;
    --fp-bg: rgba(22,163,74,0.06);
    --fp-border: rgba(22,163,74,0.30);
    --fp-color: #16a34a;
    --uc-bg: rgba(202,138,4,0.08);
    --uc-border: rgba(202,138,4,0.35);
    --uc-color: #ca8a04;
    --radius: 10px;
    --radius-sm: 6px;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    padding: 24px;
  }}
  /* Header */
  .report-header {{
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    margin-bottom: 24px;
    gap: 16px;
  }}
  .report-title {{
    font-size: 22px;
    font-weight: 700;
    color: var(--text);
    letter-spacing: -0.3px;
    display: flex;
    align-items: center;
    gap: 10px;
  }}
  .report-title svg {{ color: var(--accent); }}
  .report-subtitle {{ font-size: 13px; color: var(--text-muted); margin-top: 4px; }}
  /* Summary Panel */
  .summary-panel {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px 24px;
    margin-bottom: 20px;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
  }}
  .summary-meta {{ display: flex; flex-direction: column; gap: 6px; }}
  .meta-item {{ font-size: 13px; color: var(--text-muted); }}
  .meta-item strong {{ color: var(--text); font-weight: 500; }}
  .summary-stats {{ display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }}
  .stat-card {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 10px 16px;
    text-align: center;
    min-width: 80px;
  }}
  .stat-value {{ font-size: 22px; font-weight: 700; line-height: 1; }}
  .stat-label {{ font-size: 11px; color: var(--text-muted); margin-top: 4px; }}
  .stat-tp .stat-value {{ color: var(--tp-color); }}
  .stat-fp .stat-value {{ color: var(--fp-color); }}
  .stat-uc .stat-value {{ color: var(--uc-color); }}
  .stat-total .stat-value {{ color: var(--accent); }}
  /* Toolbar */
  .toolbar {{
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 16px;
    flex-wrap: wrap;
  }}
  .toolbar-label {{ font-size: 13px; color: var(--text-muted); }}
  .filter-btn {{
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text-muted);
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 12px;
    cursor: pointer;
    transition: all 0.2s;
  }}
  .filter-btn:hover, .filter-btn.active {{
    border-color: var(--accent);
    color: var(--accent);
    background: rgba(99,102,241,0.1);
  }}
  .toolbar-right {{ margin-left: auto; display: flex; gap: 8px; }}
  .export-btn {{
    background: var(--accent);
    border: none;
    color: white;
    padding: 7px 16px;
    border-radius: var(--radius-sm);
    font-size: 12px;
    cursor: pointer;
    font-weight: 500;
    transition: background 0.2s;
    display: flex; align-items: center; gap: 6px;
  }}
  .export-btn:hover {{ background: var(--accent-hover); }}
  .save-html-btn {{ background: #1e7e34; }}
  .save-html-btn:hover {{ background: #28a745; }}
  .ann-progress {{ font-size: 12px; color: var(--text-muted); padding: 7px 14px; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-sm); }}
  /* Finding Cards */
  .findings-list {{ display: flex; flex-direction: column; gap: 10px; }}
  .finding-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
    transition: border-color 0.2s, box-shadow 0.2s;
  }}
  .finding-card:hover {{ border-color: var(--border-light); box-shadow: 0 2px 16px rgba(0,0,0,0.3); }}
  .finding-card.verdict-tp {{ border-left: 3px solid var(--tp-color); }}
  .finding-card.verdict-fp {{ border-left: 3px solid var(--fp-color); }}
  .finding-card.verdict-uc {{ border-left: 3px solid var(--uc-color); }}
  .card-header {{
    display: flex;
    align-items: center;
    padding: 12px 16px;
    gap: 10px;
    cursor: default;
    user-select: none;
  }}
  .header-left {{ display: flex; align-items: center; gap: 8px; flex: 1; flex-wrap: wrap; }}
  .header-right {{ display: flex; align-items: center; gap: 12px; flex-shrink: 0; }}
  .index-badge {{
    font-size: 11px;
    color: var(--text-dim);
    font-weight: 600;
    min-width: 28px;
  }}
  .verdict-badge {{
    font-size: 11px;
    font-weight: 600;
    padding: 3px 9px;
    border-radius: 12px;
    letter-spacing: 0.3px;
  }}
  .verdict-badge.verdict-tp {{ background: var(--tp-bg); color: var(--tp-color); border: 1px solid var(--tp-border); }}
  .verdict-badge.verdict-fp {{ background: var(--fp-bg); color: var(--fp-color); border: 1px solid var(--fp-border); }}
  .verdict-badge.verdict-uc {{ background: var(--uc-bg); color: var(--uc-color); border: 1px solid var(--uc-border); }}
  .tool-badge {{
    font-size: 11px;
    background: rgba(99,102,241,0.12);
    color: var(--accent);
    padding: 3px 9px;
    border-radius: 12px;
    border: 1px solid rgba(99,102,241,0.25);
    font-weight: 500;
  }}
  .location-text {{
    font-size: 12px;
    color: var(--text-muted);
    display: flex; align-items: center; gap: 4px;
    font-family: 'Consolas', 'Fira Code', monospace;
  }}
  .location-text strong {{ color: var(--text); }}
  .defect-type {{
    font-size: 11px;
    color: var(--text-dim);
    font-family: 'Consolas', monospace;
  }}
  /* Confidence */
  .confidence-bar-wrap {{ display: flex; align-items: center; gap: 6px; }}
  .confidence-label {{ font-size: 11px; color: var(--text-dim); }}
  .confidence-bar {{
    width: 60px; height: 4px;
    background: var(--border);
    border-radius: 2px;
    overflow: hidden;
  }}
  .confidence-fill {{ height: 100%; border-radius: 2px; transition: width 0.3s; }}
  .confidence-value {{ font-size: 12px; font-weight: 600; min-width: 36px; text-align: right; }}
  /* Toggle */
  .toggle-btn {{
    background: none;
    border: 1px solid var(--border);
    color: var(--text-muted);
    width: 28px; height: 28px;
    border-radius: var(--radius-sm);
    cursor: pointer;
    display: flex; align-items: center; justify-content: center;
    transition: all 0.2s;
  }}
  .toggle-btn:hover {{ background: var(--surface2); border-color: var(--border-light); }}
  .chevron {{ transition: transform 0.25s; }}
  .chevron.rotated {{ transform: rotate(180deg); }}
  /* Card Summary Preview */
  .card-summary {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 0 16px 12px;
    flex-wrap: wrap;
  }}
  .summary-message {{ font-size: 13px; color: var(--text-muted); flex: 1; min-width: 0; }}
  .func-tag {{
    font-size: 11px;
    color: var(--text-dim);
    background: var(--surface2);
    border: 1px solid var(--border);
    padding: 2px 8px;
    border-radius: 4px;
    font-family: 'Consolas', monospace;
    white-space: nowrap;
  }}
  /* Card Body */
  .card-body {{
    display: none;
    border-top: 1px solid var(--border);
    padding: 16px;
    flex-direction: column;
    gap: 16px;
  }}
  .card-body.open {{ display: flex; }}
  .content-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
  }}
  @media (max-width: 900px) {{ .content-grid {{ grid-template-columns: 1fr; }} }}
  .content-section {{ display: flex; flex-direction: column; gap: 8px; }}
  .section-title {{
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    display: flex; align-items: center; gap: 6px;
  }}
  .reasoning-list {{
    list-style: none;
    display: flex; flex-direction: column; gap: 5px;
    padding-left: 0;
  }}
  .reasoning-list li {{
    font-size: 12px;
    color: var(--text);
    padding: 6px 10px;
    background: var(--surface2);
    border-radius: var(--radius-sm);
    border-left: 2px solid var(--accent);
    line-height: 1.5;
    counter-increment: step;
    position: relative;
  }}
  .code-block {{
    font-family: 'Consolas', 'Fira Code', monospace;
    font-size: 11.5px;
    line-height: 1.6;
    background: #11131e;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 12px;
    white-space: pre-wrap;
    word-break: break-word;
    color: #c9d1d9;
    max-height: 320px;
    overflow-y: auto;
  }}
  .empty-hint {{ font-size: 12px; color: var(--text-dim); font-style: italic; }}
  /* Annotation Panel */
  .annotation-panel {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 14px 16px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }}
  .annotation-title {{
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    display: flex; align-items: center; gap: 6px;
  }}
  .annotation-buttons {{ display: flex; gap: 8px; flex-wrap: wrap; }}
  .ann-btn {{
    display: inline-flex; align-items: center; gap: 5px;
    padding: 6px 14px;
    border-radius: var(--radius-sm);
    font-size: 12px;
    font-weight: 500;
    cursor: pointer;
    border: 1px solid transparent;
    transition: all 0.18s;
    background: var(--surface);
  }}
  .ann-tp {{
    color: var(--tp-color);
    border-color: var(--tp-border);
  }}
  .ann-tp:hover, .ann-tp.selected {{
    background: var(--tp-bg);
    box-shadow: 0 0 0 2px var(--tp-border);
  }}
  .ann-tp.selected {{ font-weight: 700; }}
  .ann-fp {{
    color: var(--fp-color);
    border-color: var(--fp-border);
  }}
  .ann-fp:hover, .ann-fp.selected {{
    background: var(--fp-bg);
    box-shadow: 0 0 0 2px var(--fp-border);
  }}
  .ann-fp.selected {{ font-weight: 700; }}
  .ann-uc {{
    color: var(--uc-color);
    border-color: var(--uc-border);
  }}
  .ann-uc:hover, .ann-uc.selected {{
    background: var(--uc-bg);
    box-shadow: 0 0 0 2px var(--uc-border);
  }}
  .ann-uc.selected {{ font-weight: 700; }}
  .ann-clear {{
    color: var(--text-dim);
    border-color: var(--border);
  }}
  .ann-clear:hover {{ color: var(--text-muted); border-color: var(--border-light); background: var(--surface2); }}
  .annotation-note-wrap {{ width: 100%; }}
  .annotation-note {{
    width: 100%;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--text);
    font-size: 12.5px;
    padding: 8px 12px;
    resize: vertical;
    font-family: inherit;
    line-height: 1.5;
    transition: border-color 0.2s;
    min-height: 60px;
  }}
  .annotation-note:focus {{
    outline: none;
    border-color: var(--accent);
  }}
  .annotation-note::placeholder {{ color: var(--text-dim); }}
  .ann-status {{
    font-size: 11px;
    color: var(--fp-color);
    min-height: 16px;
    opacity: 0;
    transition: opacity 0.3s;
  }}
  .ann-status.visible {{ opacity: 1; }}
  .failure-panel {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 18px 20px;
    margin-bottom: 20px;
  }}
  .failure-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 12px;
  }}
  .failure-title {{
    font-size: 14px;
    font-weight: 700;
    color: var(--text);
  }}
  .failure-count {{
    font-size: 12px;
    color: var(--text-muted);
  }}
  .failure-details {{
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--surface2);
    margin-top: 10px;
    overflow: hidden;
  }}
  .failure-details summary {{
    cursor: pointer;
    list-style: none;
    padding: 12px 14px;
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }}
  .failure-details summary::-webkit-details-marker {{ display: none; }}
  .failure-file {{
    font-family: 'Consolas', 'Fira Code', monospace;
    font-size: 12px;
    color: var(--text);
    font-weight: 600;
  }}
  .failure-kind {{
    font-size: 11px;
    color: var(--uc-color);
    border: 1px solid var(--uc-border);
    background: var(--uc-bg);
    border-radius: 999px;
    padding: 2px 8px;
  }}
  .failure-summary {{
    font-size: 12px;
    color: var(--text-muted);
  }}
  .failure-body {{
    border-top: 1px solid var(--border);
    padding: 12px 14px 14px;
    display: grid;
    gap: 12px;
  }}
  .failure-meta {{
    font-size: 12px;
    color: var(--text-muted);
  }}
  .failure-trace {{
    font-size: 12px;
    color: var(--text);
    display: grid;
    gap: 4px;
  }}
  .failure-trace-item {{
    font-family: 'Consolas', 'Fira Code', monospace;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 6px 8px;
  }}
  /* Hidden filter helper */
  .finding-card.hidden {{ display: none; }}
</style>
</head>
<body>
<div class="report-header">
  <div>
    <div class="report-title">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      DefectAware 缺陷检测报告
    </div>
    <div class="report-subtitle">生成时间: {report.generated_at} &nbsp;|&nbsp; 项目: {report.project_path}</div>
  </div>
</div>
<div class="summary-panel">
  <div class="summary-meta">
    <div class="meta-item"><strong>原始 Finding 数</strong>：{report.total_raw_findings}</div>
    <div class="meta-item"><strong>分析数</strong>：{report.total_analyzed}</div>
    <div class="meta-item"><strong>假阳性率</strong>：{report.false_positive_rate:.1%}</div>
  </div>
  <div class="summary-stats">
    <div class="stat-card stat-total">
      <div class="stat-value">{report.total_analyzed}</div>
      <div class="stat-label">总计</div>
    </div>
    <div class="stat-card stat-tp">
      <div class="stat-value">{report.true_positives}</div>
      <div class="stat-label">真阳性</div>
    </div>
    <div class="stat-card stat-fp">
      <div class="stat-value">{report.false_positives}</div>
      <div class="stat-label">假阳性</div>
    </div>
    <div class="stat-card stat-uc">
      <div class="stat-value">{report.uncertain}</div>
      <div class="stat-label">不确定</div>
    </div>
  </div>
</div>
{failure_section}
<div class="toolbar">
  <span class="toolbar-label">筛选：</span>
  <button class="filter-btn active" onclick="filterCards('all', this)">全部</button>
  <button class="filter-btn" onclick="filterCards('TRUE_POSITIVE', this)">真阳性</button>
  <button class="filter-btn" onclick="filterCards('FALSE_POSITIVE', this)">假阳性</button>
  <button class="filter-btn" onclick="filterCards('UNCERTAIN', this)">不确定</button>
  <div class="toolbar-right">
    <span class="ann-progress" id="ann-progress">已标注: 0 / {report.total_analyzed}</span>
    <button class="export-btn" onclick="exportAnnotations()">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
      导出 JSON
    </button>
    <button class="export-btn save-html-btn" onclick="saveHtml()">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
      保存 HTML
    </button>
  </div>
</div>
<div class="findings-list" id="findings-list">
{rows}
</div>
<script>
  // ---- Data ----
  const total = {report.total_analyzed};
  const findingMeta = {findings_meta_js};
  const annotations = {{}};  // {{idx: {{verdict, note}}}}

  // ---- Toggle card expand ----
  function toggleCard(idx) {{
    const body = document.getElementById('body-' + idx);
    const chevron = document.getElementById('chevron-' + idx);
    body.classList.toggle('open');
    chevron.classList.toggle('rotated');
  }}

  // ---- Filter cards ----
  function filterCards(verdict, btn) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.finding-card').forEach(card => {{
      if (verdict === 'all' || card.dataset.verdict === verdict) {{
        card.classList.remove('hidden');
      }} else {{
        card.classList.add('hidden');
      }}
    }});
  }}

  // ---- Annotation ----
  function setAnnotation(idx, verdict) {{
    if (!annotations[idx]) annotations[idx] = {{verdict: null, note: ''}};
    // toggle off if same
    if (annotations[idx].verdict === verdict) {{
      clearAnnotation(idx);
      return;
    }}
    annotations[idx].verdict = verdict;
    // update button styles
    ['tp','fp','uc'].forEach(t => {{
      const btn = document.getElementById('ann-' + t + '-' + idx);
      if (btn) btn.classList.remove('selected');
    }});
    const map = {{TRUE_POSITIVE: 'tp', FALSE_POSITIVE: 'fp', UNCERTAIN: 'uc'}};
    const btnId = 'ann-' + map[verdict] + '-' + idx;
    const selBtn = document.getElementById(btnId);
    if (selBtn) selBtn.classList.add('selected');
    showStatus(idx, '已标注为: ' + {{TRUE_POSITIVE:'真缺陷', FALSE_POSITIVE:'误报', UNCERTAIN:'待定'}}[verdict]);
    updateProgress();
    persistToStorage();
  }}

  function clearAnnotation(idx) {{
    if (annotations[idx]) annotations[idx].verdict = null;
    ['tp','fp','uc'].forEach(t => {{
      const btn = document.getElementById('ann-' + t + '-' + idx);
      if (btn) btn.classList.remove('selected');
    }});
    showStatus(idx, '已清除标注');
    updateProgress();
    persistToStorage();
  }}

  function saveAnnotation(idx) {{
    if (!annotations[idx]) annotations[idx] = {{verdict: null, note: ''}};
    const ta = document.getElementById('note-' + idx);
    annotations[idx].note = ta ? ta.value : '';
    persistToStorage();
  }}

  function showStatus(idx, msg) {{
    const el = document.getElementById('ann-status-' + idx);
    if (!el) return;
    el.textContent = msg;
    el.classList.add('visible');
    setTimeout(() => el.classList.remove('visible'), 2000);
  }}

  function updateProgress() {{
    const done = Object.values(annotations).filter(a => a && a.verdict).length;
    const el = document.getElementById('ann-progress');
    if (el) el.textContent = '已标注: ' + done + ' / ' + total;
  }}

  // ---- LocalStorage persistence ----
  const STORAGE_KEY = 'defectaware_annotations_{ts}';

  function persistToStorage() {{
    try {{ localStorage.setItem(STORAGE_KEY, JSON.stringify(annotations)); }} catch(e) {{}}
  }}

  function loadFromStorage() {{
    try {{
      const saved = localStorage.getItem(STORAGE_KEY);
      if (!saved) return;
      const data = JSON.parse(saved);
      Object.entries(data).forEach(([idx, ann]) => {{
        const i = parseInt(idx);
        annotations[i] = ann;
        if (ann.verdict) setAnnotation(i, ann.verdict);
        const ta = document.getElementById('note-' + i);
        if (ta && ann.note) ta.value = ann.note;
      }});
      updateProgress();
    }} catch(e) {{}}
  }}

  // ---- Export JSON ----
  function exportAnnotations() {{
    const result = findingMeta.map((meta, idx) => ({{
      index: idx + 1,
      tool: meta.tool,
      file: meta.file,
      line: meta.line,
      defect_id: meta.defect_id,
      ai_verdict: meta.ai_verdict,
      ai_confidence: meta.ai_confidence,
      human_verdict: annotations[idx] ? annotations[idx].verdict : null,
      note: annotations[idx] ? annotations[idx].note : ''
    }}));
    const blob = new Blob([JSON.stringify(result, null, 2)], {{type: 'application/json'}});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'annotations_{ts}.json';
    a.click();
    URL.revokeObjectURL(url);
  }}

  // ---- Save HTML with annotations embedded ----
  // [saveHtml injected below via Python string concatenation]


  // ---- Init ----
  window.addEventListener('DOMContentLoaded', () => {{
    // set data-verdict on cards for filter
    document.querySelectorAll('.finding-card').forEach((card, i) => {{
      if (findingMeta[i]) card.dataset.verdict = findingMeta[i].ai_verdict;
    }});
    loadFromStorage();
    // auto-open first card
    if (total > 0) toggleCard(0);
  }});
</script>
</body>
</html>"""
        save_html_fn = (
            "  function saveHtml() {\n"
            "    for (let i = 0; i < total; i++) {\n"
            "      const ta = document.getElementById('note-' + i);\n"
            "      if (ta && ta.value) {\n"
            "        if (!annotations[i]) annotations[i] = {verdict: null, note: ''};\n"
            "        annotations[i].note = ta.value;\n"
            "      }\n"
            "    }\n"
            "    const annJson = JSON.stringify(annotations);\n"
            "    const doctype = '<!DOCTYPE html>';\n"
            "    let htmlStr = doctype + '\\n' + document.documentElement.outerHTML;\n"
            "    const MARKED = 'const annotations = {}; /* __SAVED__ */';\n"
            "    const INIT   = 'const annotations = {};  //';\n"
            "    let found = false;\n"
            "    [INIT, MARKED].forEach(m => {\n"
            "      const idx = htmlStr.indexOf(m);\n"
            "      if (!found && idx >= 0) {\n"
            "        const eol = htmlStr.indexOf('\\n', idx);\n"
            "        htmlStr = htmlStr.slice(0, idx) + 'const annotations = ' + annJson\n"
            "                  + '; /* __SAVED__ */' + htmlStr.slice(eol >= 0 ? eol : idx + m.length);\n"
            "        found = true;\n"
            "      }\n"
            "    });\n"
            f"    const blob = new Blob([htmlStr], {{type: 'text/html;charset=utf-8'}});\n"
            "    const url = URL.createObjectURL(blob);\n"
            "    const a = document.createElement('a');\n"
            "    a.href = url;\n"
            f"    a.download = 'report_{ts}_annotated.html';\n"
            "    a.click();\n"
            "    URL.revokeObjectURL(url);\n"
            "  }\n"
        )
        html = html.replace(
            "  // [saveHtml injected below via Python string concatenation]\n",
            save_html_fn
        )
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    def _report_to_dict(self, r: DefectReport) -> dict:
        raw = r.finding.raw
        return {
            "verdict": r.verdict,
            "confidence": r.confidence,
            "tool": raw.tool,
            "file_path": raw.file_path,
            "line": raw.line,
            "column": raw.column,
            "severity": raw.severity,
            "defect_id": raw.defect_id,
            "cwe": raw.cwe,
            "message": raw.message,
            "function_name": r.finding.function_name,
            "reasoning_chain": r.reasoning_chain,
            "tool_calls_count": len(r.tool_calls_log),
            "fixed_code": r.fixed_code,
            "fix_explanation": r.fix_explanation,
            "processing_time": round(r.processing_time, 2),
            "llm_tokens_used": r.llm_tokens_used,
            "error": r.error,
        }

    def _failure_to_dict(self, failure) -> dict:
        return {
            "analyzer": failure.analyzer,
            "file_path": failure.file_path,
            "error_category": failure.error_category,
            "error_summary": failure.error_summary,
            "stderr_excerpt": failure.stderr_excerpt,
            "include_trace": failure.include_trace,
            "return_code": failure.return_code,
        }

    def _build_failure_section(self, report: FinalReport) -> str:
        if not report.analyzer_failures:
            return ""

        details = []
        for failure in report.analyzer_failures:
            trace_html = "".join(
                f"<div class='failure-trace-item'>{html_lib.escape(item)}</div>"
                for item in failure.include_trace
            ) or "<div class='failure-trace-item'>-</div>"
            stderr_html = html_lib.escape(failure.stderr_excerpt or failure.error_summary)
            details.append(
                f"""
<details class="failure-details">
  <summary>
    <span class="failure-file">{html_lib.escape(os.path.basename(failure.file_path) or failure.file_path)}</span>
    <span class="failure-kind">{html_lib.escape(failure.error_category)}</span>
    <span class="failure-summary">{html_lib.escape(failure.error_summary)}</span>
  </summary>
  <div class="failure-body">
    <div class="failure-meta">
      Analyzer: {html_lib.escape(failure.analyzer)} |
      Return code: {failure.return_code if failure.return_code is not None else "-"} |
      File: {html_lib.escape(failure.file_path)}
    </div>
    <div class="failure-trace">{trace_html}</div>
    <pre class="code-block">{stderr_html}</pre>
  </div>
</details>"""
            )

        return (
            f"""
<div class="failure-panel">
  <div class="failure-header">
    <div class="failure-title">分析失败文件</div>
    <div class="failure-count">{len(report.analyzer_failures)} 个翻译单元未能进入分析阶段</div>
  </div>
  {''.join(details)}
</div>"""
        )
