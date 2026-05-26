# -*- coding: utf-8 -*-
"""
vibe-csa HTML Report Generator
vibe-csa v3 JSON → HTML 安全审计报告

Usage:
    python vibe_csa_report.py -i <input.json> -o <output.html>
    python vibe_csa_report.py --input dynamic-verified.json --output report.html
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from html import escape


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="vibe-csa v3 JSON → HTML 安全审计报告生成器"
    )
    parser.add_argument("-i", "--input",  required=True, metavar="INPUT_JSON",  help="vibe-csa v3 JSON 输入文件路径")
    parser.add_argument("-o", "--output", required=True, metavar="OUTPUT_HTML", help="HTML 报告输出路径")
    return parser.parse_args()


# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────

def sev_class(sev):
    return {"critical":"sev-critical","high":"sev-high","medium":"sev-medium","low":"sev-low"}.get(sev.lower(),"sev-low")

def sev_label(sev):
    return {"critical":"严重","high":"高危","medium":"中危","low":"低危"}.get(sev.lower(), sev)

def sev_color(sev):
    return {"critical":"#e53e3e","high":"#dd6b20","medium":"#d69e2e","low":"#38a169"}.get(sev.lower(),"#38a169")

def status_class(s):
    return {"CONFIRMED":"status-confirmed","HYPOTHESIS":"status-hypothesis","FAILED":"status-failed"}.get(s.upper(),"status-hypothesis")

def status_label(s):
    return {"CONFIRMED":"已确认","HYPOTHESIS":"待验证","FAILED":"验证未成功"}.get(s.upper(), s)

def dv_state_class(s):
    return {"verified":"dv-verified","failed":"dv-failed","blocked":"dv-blocked",
            "skipped":"dv-skipped","in_progress":"dv-progress","not_started":"dv-notstarted"}.get(s.lower(),"dv-notstarted")

def dv_state_label(s):
    return {"verified":"已验证","failed":"失败","blocked":"受阻",
            "skipped":"已跳过","in_progress":"进行中","not_started":"未开始"}.get(s.lower(), s)

def ev_level_label(l):
    return {"L0":"L0 源码推断","L1":"L1 HTTP信号","L2":"L2 业务状态","L3":"L3 强证据"}.get(l.upper(), l)

def strength_class(s):
    return {"L3":"ev-l3","L2":"ev-l2","L1":"ev-l1","L0":"ev-l0"}.get(s.upper(),"ev-l0")

def poc_result_class(r):
    return {"success":"poc-success","failure":"poc-failure","pending":"poc-pending",
            "timeout":"poc-timeout","skipped":"poc-skipped","auth_failed":"poc-authfailed"}.get(r.lower(),"poc-pending")

def poc_result_label(r):
    return {"success":"成功","failure":"失败","pending":"待验证",
            "timeout":"超时","skipped":"已跳过","auth_failed":"认证失败"}.get(r.lower(), r)

def e(text):
    return escape(str(text)) if text is not None else ""

def score_ring(score):
    pct = min(max(float(score) / 10.0, 0), 1)
    r = 26
    import math
    circ = 2 * math.pi * r
    dash = circ * pct
    gap  = circ - dash
    color = sev_color("critical" if score>=9 else "high" if score>=7 else "medium" if score>=4 else "low")
    return f"""<svg class="score-ring" viewBox="0 0 68 68" width="68" height="68">
      <circle cx="34" cy="34" r="{r}" fill="none" stroke="#e8edf2" stroke-width="6"/>
      <circle cx="34" cy="34" r="{r}" fill="none" stroke="{color}" stroke-width="6"
        stroke-dasharray="{dash:.2f} {gap:.2f}" stroke-linecap="round"
        transform="rotate(-90 34 34)"/>
      <text x="34" y="39" text-anchor="middle" class="score-text" style="fill:{color}">{score}</text>
    </svg>"""

def render_headers(headers):
    if not headers: return ""
    lines = []
    for k, v in headers.items():
        lines.append(f'<span class="hdr-key">{e(k)}</span><span class="hdr-col">: </span><span class="hdr-val">{e(v)}</span>')
    return "\n".join(lines)

def render_params(params):
    if not params: return ""
    parts = [f"{e(k)}={e(v)}" for k, v in params.items()]
    return "?" + "&amp;".join(parts)

def resp_status_class(status):
    try:
        c = int(status) // 100
        return f"s{c}xx"
    except:
        return "sxxx"


# ──────────────────────────────────────────────
# COVER  (全新布局，无品牌字样)
# ──────────────────────────────────────────────

def build_cover(audit, findings):
    stage_map = {"static_audit":"静态代码审计","dynamic_verification":"动态漏洞验证","report":"最终安全报告"}
    mode_map  = {"quick":"快速扫描","standard":"标准扫描","deep":"深度扫描"}
    scope_map = {"full":"全量审计","partial":"部分审计","incremental":"增量审计"}
    env_map   = {"unknown":"未知","local":"本地","dev":"开发","test":"测试","staging":"预发布","production":"生产"}

    stage  = stage_map.get(audit.get("stage",""), audit.get("stage",""))
    mode   = mode_map.get(audit.get("mode",""), audit.get("mode",""))
    scope  = scope_map.get(audit.get("scope",""), audit.get("scope",""))
    langs  = "、".join(audit.get("language",[]))
    env    = env_map.get(audit.get("target",{}).get("environment","unknown"), "未知")
    roles  = "、".join(audit.get("target",{}).get("auth_context",{}).get("roles",[]) or ["无"])

    tools  = audit.get("tool_versions",{})
    tool_tags = "".join(f'<span class="tool-tag">{e(k)} <strong>{e(v)}</strong></span>' for k,v in tools.items())

    start = audit.get("audit_date",{}).get("start","—")
    end   = audit.get("audit_date",{}).get("end","—")
    now   = datetime.now().strftime("%Y-%m-%d")

    # 从实际findings动态计算统计数据
    s = audit.get("summary",{})
    total = len(findings) if findings else s.get("total", 0)
    
    # 按严重性统计
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
    
    crit = sev_counts["critical"]
    high = sev_counts["high"]
    med = sev_counts["medium"]
    low = sev_counts["low"]
    
    # 按状态统计
    confirmed = sum(1 for f in findings if f.get("status") == "CONFIRMED")
    hypothesis = sum(1 for f in findings if f.get("status") == "HYPOTHESIS")
    
    # 动态验证统计
    runtime_verified = 0  # 验证成功
    verification_failed = 0  # 验证失败
    pending_only = 0  # 仅静态审计(pending)
    for f in findings:
        dyn = f.get("dynamic_verification", {})
        state = dyn.get("state", "")
        poc_result = f.get("poc", {}).get("result", "pending")
        if state == "verified":
            runtime_verified += 1
        elif state == "failed" or poc_result == "failure":
            verification_failed += 1
        else:
            pending_only += 1
    
    # 动态验证总数 = 验证成功 + 验证失败
    dynamic_verification_total = runtime_verified + verification_failed

    # donut chart data
    donut_segments = []
    colors = [("#e53e3e", crit, "严重"), ("#dd6b20", high, "高危"), ("#d69e2e", med, "中危"), ("#38a169", low, "低危")]
    offset = 0
    import math
    r, cx, cy = 52, 70, 70
    circ = 2 * math.pi * r
    for color, cnt, label in colors:
        if total > 0:
            pct = cnt / total
            dash = circ * pct
            gap  = circ - dash
            donut_segments.append(
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" stroke-width="18" '
                f'stroke-dasharray="{dash:.2f} {gap:.2f}" stroke-linecap="butt" '
                f'transform="rotate({offset * 360 - 90} {cx} {cy})"/>'
            )
            offset += pct

    donut_svg = f"""<svg viewBox="0 0 140 140" width="140" height="140" class="donut-svg">
      <circle cx="70" cy="70" r="52" fill="none" stroke="#e8edf2" stroke-width="18"/>
      {"".join(donut_segments)}
      <text x="70" y="66" text-anchor="middle" class="donut-total">{total}</text>
      <text x="70" y="84" text-anchor="middle" class="donut-lbl">漏洞总计</text>
    </svg>"""

    sev_items = "".join([
        f'<div class="cover-sev-item"><span class="csev-dot" style="background:{c}"></span>'
        f'<span class="csev-label">{lb}</span><span class="csev-cnt">{cnt}</span></div>'
        for c, cnt, lb in colors
    ])

    base_url = audit.get("target",{}).get("base_url","") or "—"
    src_path = audit.get("target",{}).get("source_path","") or "—"

    return f"""
<div class="cover-wrap">
  <div class="cover-left">
    <div class="cover-eyebrow">安全审计报告</div>
    <h1 class="cover-title">{e(audit.get("title","代码安全审计"))}</h1>
    <div class="cover-repo">{e(audit.get("repository","—"))}</div>

    <div class="cover-badges">
      <span class="cbadge cbadge-stage">{e(stage)}</span>
      <span class="cbadge cbadge-mode">{e(mode)}</span>
      <span class="cbadge cbadge-scope">{e(scope)}</span>
      <span class="cbadge cbadge-lang">{e(langs)}</span>
    </div>

    <div class="cover-info-grid">
      <div class="ci-item"><span class="ci-k">审计编号</span><span class="ci-v mono">{e(audit.get("audit_id","—"))}</span></div>
      <div class="ci-item"><span class="ci-k">目标环境</span><span class="ci-v">{e(env)}</span></div>
      <div class="ci-item"><span class="ci-k">目标地址</span><span class="ci-v mono small">{e(base_url)}</span></div>
      <div class="ci-item"><span class="ci-k">源码路径</span><span class="ci-v mono small">{e(src_path)}</span></div>
      <div class="ci-item"><span class="ci-k">审计周期</span><span class="ci-v">{e(start)} — {e(end)}</span></div>
      <div class="ci-item"><span class="ci-k">可用角色</span><span class="ci-v">{e(roles)}</span></div>
      <div class="ci-item"><span class="ci-k">报告生成</span><span class="ci-v">{now}</span></div>
      <div class="ci-item"><span class="ci-k">认证要求</span><span class="ci-v">{"需要认证" if audit.get("target",{}).get("auth_context",{}).get("required") else "无需认证"}</span></div>
    </div>

    <div class="cover-tools">{tool_tags}</div>
  </div>

  <div class="cover-right">
    <div class="cover-donut-wrap">
      {donut_svg}
      <div class="cover-sev-legend">{sev_items}</div>
    </div>
    <div class="cover-stat-row">
      <div class="cstat"><span class="cstat-v">{runtime_verified}</span><span class="cstat-l">已确认</span></div>
      <div class="cstat"><span class="cstat-v">{pending_only}</span><span class="cstat-l">待验证</span></div>
      <div class="cstat"><span class="cstat-v">{dynamic_verification_total}</span><span class="cstat-l">动态验证</span></div>
      <div class="cstat"><span class="cstat-v">{verification_failed}</span><span class="cstat-l">验证未成功</span></div>
    </div>
  </div>
</div>"""


# ──────────────────────────────────────────────
# EXECUTIVE SUMMARY
# ──────────────────────────────────────────────

def build_summary(audit, findings):
    # 从实际findings动态计算统计数据
    s = audit.get("summary", {})
    cov = audit.get("coverage_summary", {})
    total = len(findings) if findings else s.get("total", 0)
    
    # 按严重性统计
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
    
    # 按状态统计
    confirmed = sum(1 for f in findings if f.get("status") == "CONFIRMED")
    hypothesis = sum(1 for f in findings if f.get("status") == "HYPOTHESIS")
    
    # 动态验证统计
    runtime_verified = 0  # 验证成功
    verification_failed = 0  # 验证失败
    pending_only = 0  # 仅静态审计(pending)
    for f in findings:
        dyn = f.get("dynamic_verification", {})
        state = dyn.get("state", "")
        poc_result = f.get("poc", {}).get("result", "pending")
        if state == "verified":
            runtime_verified += 1
        elif state == "failed" or poc_result == "failure":
            verification_failed += 1
        else:
            pending_only += 1
    
    # 动态验证总数 = 验证成功 + 验证失败
    dynamic_verification_total = runtime_verified + verification_failed

    # severity bars
    sev_bars = ""
    for sev, cls, lb in [("critical","sev-critical","严重"),("high","sev-high","高危"),
                          ("medium","sev-medium","中危"),("low","sev-low","低危")]:
        cnt = sev_counts[sev]
        pct = int(cnt / total * 100) if total else 0
        sev_bars += f"""<div class="sb-row">
          <span class="sb-label {cls}-text">{lb}</span>
          <div class="sb-track"><div class="sb-fill {cls}" style="width:{pct}%"></div></div>
          <span class="sb-cnt">{cnt}</span>
        </div>"""

    # type distribution
    by_type = s.get("by_type",{})
    type_rows = "".join([
        f'<div class="tr-row"><span class="tr-name">{e(k)}</span>'
        f'<div class="tr-bar-wrap"><div class="tr-bar" style="width:{int(v/max(by_type.values())*100) if by_type else 0}%"></div></div>'
        f'<span class="tr-cnt">{v}</span></div>'
        for k, v in by_type.items()
    ])

    # coverage meters
    cov_items = [
        ("综合覆盖", cov.get("total_pct",0), "cov-total"),
        ("入口点文件覆盖率",  cov.get("tier1_pct",0),  "cov-t1"),
        ("业务逻辑层覆盖率",  cov.get("tier2_pct",0),  "cov-t2"),
        ("数据结构层覆盖率",  cov.get("tier3_pct",0),  "cov-t3"),
    ]
    cov_meters = "".join([
        f'<div class="cov-row"><span class="cov-k">{lb}</span>'
        f'<div class="cov-track"><div class="cov-fill {cls}" style="width:{pct}%"></div></div>'
        f'<span class="cov-pct">{pct}%</span></div>'
        for lb, pct, cls in cov_items
    ])

    return f"""
<section class="sec" id="summary">
  <div class="sec-hdr"><span class="sec-num">01</span><h2>执行摘要</h2></div>
  <div class="summary-layout">

    <div class="sumcol">
      <div class="sumcard">
        <div class="sumcard-title">严重性分布</div>
        <div class="sev-bars">{sev_bars}</div>
      </div>
      <div class="sumcard">
        <div class="sumcard-title">漏洞类型分布</div>
        {type_rows if type_rows else '<p class="muted">暂无数据</p>'}
      </div>
    </div>

    <div class="sumcol">
      <div class="sumcard">
        <div class="sumcard-title">代码覆盖率</div>
        {cov_meters}
        <div class="cov-detail">
          <span>已审文件 <strong>{cov.get("reviewed_files","—")}</strong></span>
          <span>有效代码行 (EALOC) <strong>{cov.get("ealoc","—")}</strong></span>
        </div>
      </div>
      <div class="sumcard">
        <div class="sumcard-title">发现状态概览</div>
        <div class="status-overview">
          <div class="so-item so-confirmed"><span class="so-val">{runtime_verified}</span><span class="so-lbl">已确认</span></div>
          <div class="so-item so-pending"><span class="so-val">{pending_only}</span><span class="so-lbl">待验证</span></div>
          <div class="so-item so-rv"><span class="so-val">{dynamic_verification_total}</span><span class="so-lbl">动态验证</span></div>
          <div class="so-item so-failed"><span class="so-val">{verification_failed}</span><span class="so-lbl">验证未成功</span></div>
        </div>
      </div>
    </div>

  </div>
</section>"""


# ──────────────────────────────────────────────
# TOC
# ──────────────────────────────────────────────

def build_toc(findings):
    rows = ""
    for f in findings:
        vid   = f.get("vuln_id","")
        sev   = f.get("severity","low")
        
        # 根据动态验证结果确定状态
        dyn = f.get("dynamic_verification", {})
        poc = f.get("poc", {})
        dyn_state = dyn.get("state", "")
        poc_result = poc.get("result", "pending")
        
        if dyn_state == "verified":
            status = "CONFIRMED"
        elif dyn_state == "failed" or poc_result == "failure":
            status = "FAILED"
        else:
            status = f.get("status", "HYPOTHESIS")
        
        slug  = f"finding-{e(vid)}"
        rows += f"""<tr class="toc-row" onclick="jumpTo('{slug}')">
          <td><span class="toc-id">{e(vid)}</span></td>
          <td class="toc-title">{e(f.get("title",""))}</td>
          <td><span class="badge {sev_class(sev)}">{sev_label(sev)}</span></td>
          <td><span class="badge {status_class(status)}">{status_label(status)}</span></td>
          <td class="toc-type">{e(f.get("vuln_type",""))}</td>
          <td class="toc-score">{f.get("dktss_score","—")}</td>
        </tr>"""
    return f"""
<section class="sec" id="toc">
  <div class="sec-hdr"><span class="sec-num">02</span><h2>漏洞列表</h2></div>
  <table class="toc-table">
    <thead><tr><th>编号</th><th>漏洞标题</th><th>严重性</th><th>状态</th><th>类型</th><th>DKTSS</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>"""


# ──────────────────────────────────────────────
# FINDING DETAIL
# ──────────────────────────────────────────────

def build_finding(f, idx, audit_stage="static_audit"):
    vid      = f.get("vuln_id", f"FINDING-{idx:03d}")
    sev      = f.get("severity","low")
    status   = f.get("status","HYPOTHESIS")
    loc      = f.get("location",{})
    analysis = f.get("analysis",{})
    static_ev= f.get("static_evidence",{})
    dyn      = f.get("dynamic_verification",{})
    poc      = f.get("poc",{})
    remediation = f.get("remediation",{})
    fix      = f.get("fix",{})
    slug     = f"finding-{e(vid)}"
    
    # 根据动态验证结果确定状态
    dyn_state = dyn.get("state", "")
    poc_result = poc.get("result", "pending")
    if dyn_state == "verified":
        status = "CONFIRMED"
    elif dyn_state == "failed" or poc_result == "failure":
        status = "FAILED"
    else:
        status = f.get("status", "HYPOTHESIS")
    
    is_static_stage = (audit_stage == "static_audit")

    # ── Data flow
    flow_html = ""
    for step in analysis.get("data_flow",[]):
        stype = step.get("type","")
        tmap  = {"source":"flow-src","sink":"flow-sink","propagation":"flow-prop"}
        tlbl  = {"source":"SOURCE","sink":"SINK","propagation":"PROPAGATION"}
        flow_html += f"""<div class="flow-step {tmap.get(stype,'flow-prop')}">
          <div class="flow-hdr">
            <span class="flow-badge">{tlbl.get(stype,stype.upper())}</span>
            <span class="flow-loc">{e(step.get("location",""))}</span>
          </div>
          <div class="flow-desc">{e(step.get("desc",""))}</div>
          {f'<code class="flow-code">{e(step.get("code",""))}</code>' if step.get("code") else ""}
        </div>"""

    # ── Controls
    ctrl_html = ""
    for ctrl in analysis.get("security_controls",[]):
        bypas = "bypassable" in ctrl.get("assessment","")
        ctrl_html += f"""<div class="ctrl {'ctrl-bypass' if bypas else 'ctrl-ok'}">
          <div class="ctrl-row">
            <span class="ctrl-name">{e(ctrl.get("control",""))}</span>
            <span class="ctrl-badge">{"可绕过" if bypas else "有效"}</span>
            <span class="ctrl-loc">{e(ctrl.get("location",""))}</span>
          </div>
          {f'<div class="ctrl-note">{e(ctrl.get("bypass_notes",""))}</div>' if ctrl.get("bypass_notes") else ""}
        </div>"""

    # ── Bypass
    bypass_html = ""
    bp = analysis.get("bypass_strategy",{})
    if bp.get("ideas"):
        diff_map = {"low":"低","medium":"中","high":"高"}
        ideas = "".join([f"""<div class="bp-idea">
          <span class="bp-tech">{e(i.get("technique",""))}</span>
          <code class="bp-payload">{e(i.get("payload_hint",""))}</code>
          <p class="bp-reason">{e(i.get("reason",""))}</p>
        </div>""" for i in bp.get("ideas",[])])
        bypass_html = f"""<div class="bypass-box">
          <div class="bypass-hdr">绕过可行性：<span class="{'bp-yes' if bp.get('feasible') else 'bp-no'}">{'可行' if bp.get('feasible') else '不可行'}</span>
          &ensp;难度：<strong>{diff_map.get(bp.get("difficulty",""),"—")}</strong></div>
          {ideas}
        </div>"""

    # ── Evidence refs
    evid_refs = static_ev.get("evidence_refs",{})
    evid_html = ""
    if evid_refs:
        rows = "".join([f'<tr><td class="evk">{e(k)}</td><td class="evv">{e(v)}</td></tr>' for k,v in evid_refs.items()])
        evid_html = f'<table class="evid-tbl"><thead><tr><th>证据标识</th><th>位置</th></tr></thead><tbody>{rows}</tbody></table>'

    # ── PoC steps
    poc_result = poc.get("result", "pending")
    poc_steps_html = ""
    for step in poc.get("steps",[]):
        req  = step.get("request",{})
        resp = step.get("response",{})
        params_str = render_params(req.get("params",{}))
        ev_matches = "".join([f"""<div class="ev-match {strength_class(em.get('strength','L0'))}">
          <span class="em-type">{e(em.get('type',''))}</span>
          <span class="em-str">{e(em.get('strength',''))}</span>
          <code class="em-snip">{e(em.get('snippet',''))}</code>
        </div>""" for em in resp.get("_evidence_match",[])])

        elapsed = resp.get("_meta",{}).get("elapsed_ms","")
        status_c = resp_status_class(resp.get("status",""))
        
        # pending: 不显示REQUEST/RESPONSE内容
        if poc_result == "pending":
            poc_steps_html += f"""<div class="poc-step">
              <div class="poc-step-hdr">
                <span class="poc-snum">Step {step.get("step","")}</span>
                <span class="poc-sname">{e(step.get("name",""))}</span>
              </div>
              <p class="muted">静态审计阶段，暂无动态验证的REQUEST/RESPONSE内容</p>
            </div>"""
            continue
        
        # failure及其他结果：显示REQUEST/RESPONSE内容
        req_display = req.get("raw", "")
        resp_display = resp.get("raw", "")
        has_req_raw = bool(req_display)
        has_resp_raw = bool(resp_display)
        
        if not has_req_raw:
            req_display = req.get("body", "")
        if not has_resp_raw:
            resp_display = resp.get("body", "")
        
        # Normalize line endings: \r\n → \n for consistent display
        if req_display:
            req_display = req_display.replace("\\r\\n", "\n").replace("\r\n", "\n")
        if resp_display:
            resp_display = resp_display.replace("\\r\\n", "\n").replace("\r\n", "\n")

        poc_steps_html += f"""<div class="poc-step">
          <div class="poc-step-hdr">
            <span class="poc-snum">Step {step.get("step","")}</span>
            <span class="poc-sname">{e(step.get("name",""))}</span>
          </div>
          <div class="http-grid">
            <div class="http-pane req-pane">
              <div class="http-pane-lbl">REQUEST</div>
              {'' if has_req_raw else f'''<div class="http-rline">
                <span class="http-method meth-{e(req.get('method','GET')).lower()}">{e(req.get('method','GET'))}</span>
                <span class="http-url">{e(req.get('url',''))}{params_str}</span>
              </div>'''}<pre class="http-body">{e(req_display)}</pre>
            </div>
            <div class="http-pane resp-pane">
              <div class="http-pane-lbl">RESPONSE{f' <span class="elapsed">{elapsed}ms</span>' if elapsed else ''}</div>
              {'' if has_resp_raw else f'''<div class="resp-sline">
                <span class="resp-code {status_c}">{resp.get('status','—')}</span>
                <span class="resp-ct">{e(resp.get('headers',{}).get('Content-Type',''))}</span>
              </div>'''}<pre class="http-body resp-body">{e(resp_display)}</pre>
              {f'<div class="ev-matches">{ev_matches}</div>' if ev_matches else ""}
            </div>
          </div>
        </div>"""

    # ── Dynamic verification
    dv_state = dyn.get("state","not_started")
    final_ev = dyn.get("final_evidence",{})
    _snippets = final_ev.get("snippets",[])
    # Handle both structured (dict) and flat (string) snippet formats
    if _snippets and isinstance(_snippets[0], str):
        dv_snips = "".join([f"""<div class="dv-snip ev-l0">
          <code>{e(sn)}</code>
        </div>""" for sn in _snippets])
    else:
        dv_snips = "".join([f"""<div class="dv-snip {strength_class(sn.get('strength','L0'))}">
          <span class="dvsn-step">Step {sn.get('step','')}</span>
          <span class="dvsn-type">{e(sn.get('signature_type',''))}</span>
          <code>{e(sn.get('snippet',''))}</code>
        </div>""" for sn in _snippets])

    attempts_html = "".join([f"""<div class="att-row">
      <span class="att-num">#{att.get('attempt','')}</span>
      <span class="att-res {'att-ok' if att.get('result')=='success' else 'att-fail'}">{att.get('result','')}</span>
      <span class="att-strategy">{e(att.get('payload_strategy',''))}</span>
      {f'<code class="att-snip">{e(att.get("evidence_snippet",""))}</code>' if att.get("evidence_snippet") else ""}
    </div>""" for att in dyn.get("attempts",[])])

    # ── Fix diff
    fix_html = ""
    if fix.get("before") or fix.get("after"):
        fix_html = f"""<div class="fix-block">
          <div class="fix-lang">{e(fix.get("language",""))}</div>
          <div class="fix-grid">
            <div class="fix-before"><span class="fix-lbl">当前代码片段</span><code>{e(fix.get("before",""))}</code></div>
            <div class="fix-after"><span class="fix-lbl">代码整改参考建议</span><code>{e(fix.get("after",""))}</code></div>
          </div>
        </div>"""

    # 清理snippet中的行号前缀（如"L18: "）
    raw_snippet = loc.get("snippet", "")
    if raw_snippet:
        import re
        cleaned_snippet = re.sub(r'^L\d+:\s*', '', raw_snippet, flags=re.MULTILINE)
    else:
        cleaned_snippet = ""

    as_items = "".join([
        f'<div class="as-item"><span class="as-k">{e(k)}</span><span class="as-v">{e(v)}</span></div>'
        for k, v in analysis.get("attack_surface",{}).items()
    ])

    return f"""
<div class="finding-card" id="{slug}">
  <div class="fc-toggle" onclick="toggleFinding('{slug}')">
    <div class="fc-toggle-left">
      <span class="fc-chevron" id="chev-{slug}">▼</span>
      <span class="badge {sev_class(sev)} badge-sm">{sev_label(sev)}</span>
      <span class="badge {status_class(status)} badge-sm">{status_label(status)}</span>
      <span class="fc-id">{e(vid)}</span>
      <span class="fc-title-txt">{e(f.get("title",""))}</span>
    </div>
    <div class="fc-toggle-right">
      <span class="ev-lvl-badge">{ev_level_label(f.get("evidence_level","L0"))}</span>
      {score_ring(f.get("dktss_score",0))}
    </div>
  </div>

  <div class="fc-body" id="body-{slug}">
    <div class="fc-meta-row">
      <span class="meta-chip"><span class="mc-k">类型</span>{e(f.get("vuln_type",""))}</span>
      <span class="meta-chip"><span class="mc-k">CWE</span>{e(f.get("cwe","—"))}</span>
      <span class="meta-chip"><span class="mc-k">分类</span>{e(f.get("category",""))}</span>
      <span class="meta-chip"><span class="mc-k">Agent</span>{e(static_ev.get("agent","—"))}</span>
      <span class="meta-chip"><span class="mc-k">置信度</span><span class="conf-{f.get('confidence','low')}">{f.get('confidence','—')}</span></span>
    </div>

    <div class="tabs-wrap" data-fid="{e(vid)}">
      <div class="tabs-nav">
        <button class="tbtn active" data-tab="overview">概述</button>
        <button class="tbtn" data-tab="dataflow">数据流</button>
        {'' if is_static_stage else '<button class="tbtn" data-tab="poc">PoC 步骤</button>'}
        {'' if is_static_stage else '<button class="tbtn" data-tab="dynverify">动态验证</button>'}
        <button class="tbtn" data-tab="remediation">修复建议</button>
      </div>

      <div class="tab-panel active" data-panel="overview">
        <div class="p2col">
          <div>
            <h4 class="ph">漏洞描述</h4>
            <p class="pdesc">{e(f.get("description",""))}</p>
            <h4 class="ph">影响说明</h4>
            <p class="pdesc">{e(f.get("impact","—"))}</p>
            <h4 class="ph">触发前置条件</h4>
            <ul class="pre-cond">{"".join(f'<li>{e(p)}</li>' for p in analysis.get("preconditions",[]))}</ul>
          </div>
          <div>
            <h4 class="ph">漏洞位置</h4>
            <div class="loc-card">
              <div class="loc-row"><span class="lk">文件</span><code>{e(loc.get("file",""))}</code></div>
              <div class="loc-row"><span class="lk">行号</span><code>{loc.get("line_start","—")} – {loc.get("line_end","—")}</code></div>
              <div class="loc-row"><span class="lk">函数</span><code>{e(loc.get("function","—"))}</code></div>
              <div class="loc-row"><span class="lk">路由</span><code>{e(loc.get("route","—"))}</code></div>
              <div class="loc-row"><span class="lk">方法</span><code>{e(loc.get("http_method","—"))}</code></div>
            </div>
            <h4 class="ph">关键代码片段</h4>
            <pre class="snippet">{e(cleaned_snippet)}</pre>
            <h4 class="ph">安全控制措施</h4>
            {ctrl_html if ctrl_html else '<p class="muted">无</p>'}
          </div>
        </div>
      </div>

      <div class="tab-panel" data-panel="dataflow">
        <div class="as-card">
          <h4 class="ph">攻击面</h4>
          <div class="as-grid">{as_items}</div>
        </div>
        <h4 class="ph">数据流追踪</h4>
        <div class="flow-chain">{flow_html if flow_html else '<p class="muted">暂无数据流</p>'}</div>
        {bypass_html}
        <h4 class="ph">静态证据引用</h4>
        {evid_html if evid_html else '<p class="muted">暂无</p>'}
        <div class="conf-row">
          <span class="cr-k">置信度说明</span>
          <span class="cr-v">{e(static_ev.get("confidence_reason",""))}</span>
        </div>
      </div>

      {'' if is_static_stage else f'''
      <div class="tab-panel" data-panel="poc">
        <div class="poc-banner {poc_result_class(poc.get('result','pending'))}">
          PoC 结果：{poc_result_label(poc.get("result","pending"))}
        </div>
        {f'<div class="poc-evbox">{e(poc.get("evidence",""))}</div>' if poc.get("evidence") else ""}
        {poc_steps_html if poc_steps_html else '<p class="muted">静态阶段暂无 PoC 步骤</p>'}
      </div>

      <div class="tab-panel" data-panel="dynverify">
        <div class="dv-banner {dv_state_class(dv_state)}">
          <span class="dv-icon">{'✔' if dv_state=='verified' else '✘' if dv_state=='failed' else '⏸'}</span>
          <span class="dv-text">动态验证状态：{dv_state_label(dv_state)}</span>
          <span class="dv-proof">证据类型：{e(final_ev.get("proof_type","—"))}</span>
        </div>
        <p class="dv-summary">{e(final_ev.get("summary",""))}</p>
        {f'<div class="dv-snips">{dv_snips}</div>' if dv_snips else ""}
        <h4 class="ph">尝试记录</h4>
        {attempts_html}
        {f'<div class="rt-notes">{e(dyn.get("runtime_notes",""))}</div>' if dyn.get("runtime_notes") else ""}
      </div>
      '''}

      <div class="tab-panel" data-panel="remediation">
        <div class="rem-grid">
          <div class="rem-short"><div class="rem-badge">短期修复</div><p>{e(remediation.get("short_term","—"))}</p></div>
          <div class="rem-long"><div class="rem-badge">长期修复</div><p>{e(remediation.get("long_term","—"))}</p></div>
        </div>
        {fix_html}
      </div>
    </div>
  </div>
</div>"""


# ──────────────────────────────────────────────
# STYLES
# ──────────────────────────────────────────────

CSS = """
:root {
  --bg-start:   #f0f4f8;
  --bg-end:     #e8f0fb;
  --navy:       #1e3a5f;
  --navy2:      #2a4e7f;
  --teal:       #3b9eba;
  --teal2:      #2a8fa8;
  --teal-light: #c8eaf4;
  --teal-faint: #eef8fb;
  --white:      #ffffff;
  --text:       #1c2e40;
  --text2:      #4a6178;
  --text3:      #8fa8c0;
  --border:     #d0dce8;
  --surf1:      #ffffff;
  --surf2:      #f3f7fb;
  --surf3:      #ebf2f8;

  --sc: #e53e3e;
  --sh: #dd6b20;
  --sm: #d69e2e;
  --sl: #38a169;

  --r: 10px;
  --shadow: 0 2px 12px rgba(30,58,95,.08);
  --shadow2: 0 4px 24px rgba(30,58,95,.11);
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  font-family: 'Segoe UI','PingFang SC','Hiragino Sans GB','Microsoft YaHei',sans-serif;
  background: linear-gradient(145deg, var(--bg-start) 0%, var(--bg-end) 100%);
  background-attachment: fixed;
  color: var(--text); font-size: 14px; line-height: 1.65; min-height: 100vh;
}
.page { max-width: 1100px; margin: 0 auto; padding: 0 20px 24px; min-height: 100vh; display: flex; flex-direction: column; }

/* ── TOP BAR ── */
.topbar {
  position: sticky; top: 0; z-index: 200;
  background: rgba(246,255,255,.82);
  backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 28px;
}
.tb-title { font-size: 15px; font-weight: 700; color: var(--navy); }
.tb-sub   { font-size: 12px; color: var(--text3); }
.tb-stage { font-size: 12px; font-weight: 600; color: var(--teal); letter-spacing: .06em; }

/* ── COVER ── */
.cover-wrap {
  display: grid; grid-template-columns: 1fr 340px; gap: 32px;
  background: linear-gradient(135deg, #ffffff 0%, #eef5fb 50%, #e4f0f8 100%);
  border-radius: 0 0 20px 20px;
  border: 1px solid var(--border); border-top: none;
  padding: 48px 48px 40px;
  margin-bottom: 36px;
  box-shadow: var(--shadow2);
  position: relative; overflow: hidden;
}
.cover-wrap::before {
  content:''; position:absolute; top:-80px; right:-80px;
  width:360px; height:360px; border-radius:50%;
  background: radial-gradient(circle, rgba(59,158,186,.08) 0%, transparent 70%);
  pointer-events: none;
}
.cover-eyebrow { font-size:12px; font-weight:700; color:var(--teal); letter-spacing:.14em; text-transform:uppercase; margin-bottom:10px; }
.cover-title   { font-size:28px; font-weight:800; color:var(--navy); line-height:1.25; margin-bottom:8px; }
.cover-repo    { font-size:13px; color:var(--text2); font-family:monospace; margin-bottom:20px; }
.cover-badges  { display:flex; flex-wrap:wrap; gap:7px; margin-bottom:24px; }
.cbadge        { padding:4px 13px; border-radius:20px; font-size:12px; font-weight:600; }
.cbadge-stage  { background:linear-gradient(90deg,var(--navy),var(--navy2)); color:#fff; }
.cbadge-mode   { background:var(--teal-faint); color:var(--teal2); border:1px solid var(--teal-light); }
.cbadge-scope  { background:var(--surf2); color:var(--text2); border:1px solid var(--border); }
.cbadge-lang   { background:#f0f7ff; color:#2563c7; border:1px solid #bfd6f5; }
.cover-info-grid { display:grid; grid-template-columns:1fr 1fr; gap:10px 24px; margin-bottom:20px; }
.ci-item       { display:flex; flex-direction:column; }
.ci-k          { font-size:11px; color:var(--text3); letter-spacing:.08em; text-transform:uppercase; margin-bottom:2px; }
.ci-v          { font-size:13px; color:var(--text); font-weight:500; }
.ci-v.mono     { font-family:monospace; font-size:12px; }
.ci-v.small    { font-size:11.5px; }
.cover-tools   { display:flex; flex-wrap:wrap; gap:6px; margin-top:4px; }
.tool-tag      { font-size:11px; background:var(--surf2); border:1px solid var(--border); border-radius:6px; padding:2px 9px; color:var(--text2); }
.tool-tag strong { color:var(--navy); }

/* donut */
.cover-right   { display:flex; flex-direction:column; align-items:center; justify-content:center; gap:20px; }
.cover-donut-wrap { display:flex; flex-direction:column; align-items:center; gap:12px; }
.donut-svg     { display:block; filter: drop-shadow(0 2px 8px rgba(30,58,95,.12)); }
.donut-total   { font-size:22px; font-weight:800; fill:var(--navy); font-family:inherit; }
.donut-lbl     { font-size:11px; fill:var(--text3); font-family:inherit; }
.cover-sev-legend { display:flex; flex-wrap:wrap; justify-content:center; gap:8px 16px; }
.cover-sev-item { display:flex; align-items:center; gap:5px; font-size:12px; }
.csev-dot      { width:8px; height:8px; border-radius:50%; flex-shrink:0; }
.csev-label    { color:var(--text2); }
.csev-cnt      { font-weight:700; color:var(--navy); }
.cover-stat-row { display:grid; grid-template-columns:repeat(2,1fr); gap:10px; width:100%; }
.cstat         { background:var(--surf1); border:1px solid var(--border); border-radius:8px; padding:10px; text-align:center; box-shadow:var(--shadow); }
.cstat-v       { display:block; font-size:22px; font-weight:800; color:var(--navy); }
.cstat-l       { font-size:11px; color:var(--text3); }

/* ── SECTIONS ── */
.sec { margin-bottom: 44px; }
.sec-hdr { display:flex; align-items:baseline; gap:12px; padding-bottom:10px; border-bottom:2px solid var(--border); margin-bottom:22px; }
.sec-hdr h2 { font-size:20px; font-weight:700; color:var(--navy); }
.sec-num    { font-size:12px; font-weight:800; color:var(--teal); letter-spacing:.1em; min-width:24px; }

/* ── SUMMARY ── */
.summary-layout { display:grid; grid-template-columns:1fr 1fr; gap:20px; }
.sumcol  { display:flex; flex-direction:column; gap:16px; }
.sumcard { background:var(--surf1); border:1px solid var(--border); border-radius:var(--r); padding:18px 20px; box-shadow:var(--shadow); }
.sumcard-title { font-size:13px; font-weight:700; color:var(--navy); margin-bottom:14px; }
.sb-row  { display:flex; align-items:center; gap:10px; margin-bottom:8px; }
.sb-label{ width:28px; font-size:12px; font-weight:700; }
.sb-track{ flex:1; height:8px; background:var(--surf3); border-radius:4px; overflow:hidden; }
.sb-fill { height:100%; border-radius:4px; transition:width .4s; }
.sb-cnt  { width:22px; font-size:12px; text-align:right; font-weight:600; color:var(--text2); }
.sev-critical { background:var(--sc); } .sev-high { background:var(--sh); }
.sev-medium   { background:var(--sm); } .sev-low  { background:var(--sl); }
.sev-critical-text { color:var(--sc); } .sev-high-text { color:var(--sh); }
.sev-medium-text   { color:var(--sm); } .sev-low-text  { color:var(--sl); }

.tr-row  { display:flex; align-items:center; gap:10px; padding:5px 0; border-bottom:1px solid var(--surf3); }
.tr-name { font-size:13px; min-width:100px; }
.tr-bar-wrap { flex:1; height:7px; background:var(--surf3); border-radius:4px; overflow:hidden; }
.tr-bar  { height:100%; background:linear-gradient(90deg,var(--teal),var(--navy2)); border-radius:4px; }
.tr-cnt  { font-weight:700; color:var(--navy); font-size:13px; min-width:20px; text-align:right; }

.cov-row { display:flex; align-items:center; gap:10px; margin-bottom:8px; }
.cov-k   { font-size:12px; color:var(--text2); min-width:100px; }
.cov-track { flex:1; height:7px; background:var(--surf3); border-radius:4px; overflow:hidden; }
.cov-fill { height:100%; border-radius:4px; }
.cov-total { background:var(--teal); } .cov-t1 { background:var(--navy); }
.cov-t2    { background:#5a9fd4; }    .cov-t3 { background:#8ec6e8; }
.cov-pct { font-size:12px; font-weight:600; color:var(--navy); min-width:36px; text-align:right; }
.cov-detail { display:flex; gap:16px; margin-top:10px; font-size:12px; color:var(--text3); }
.cov-detail strong { color:var(--navy); }

.status-overview { display:grid; grid-template-columns:repeat(2,1fr); gap:10px; margin-top:4px; }
.so-item { border-radius:8px; padding:12px 14px; text-align:center; border:1px solid; }
.so-item .so-val { display:block; font-size:24px; font-weight:800; line-height:1; margin-bottom:4px; }
.so-item .so-lbl { font-size:11px; }
.so-open      { background:#fff8ec; border-color:#f6c26e; } .so-open .so-val      { color:var(--sh); }
.so-unverified{ background:#f9f0ff; border-color:#c4a8f0; } .so-unverified .so-val{ color:#7c3aed; }
.so-confirmed { background:#fff0f0; border-color:var(--sc); } .so-confirmed .so-val { color:var(--sc); }
.so-rv        { background:#f0fff4; border-color:#9ae6b4; } .so-rv .so-val        { color:var(--sl); }
.so-pending   { background:#fffbec; border-color:#f6c26e; } .so-pending .so-val   { color:var(--sm); }
.so-failed    { background:#f3f7fb; border-color:var(--border); } .so-failed .so-val  { color:var(--text3); }

/* ── TOC TABLE ── */
.toc-table { width:100%; border-collapse:collapse; background:var(--surf1); box-shadow:var(--shadow); border-radius:var(--r); overflow:hidden; }
.toc-table thead th { background:var(--navy); color:#c8dde8; padding:10px 14px; font-size:12px; font-weight:600; letter-spacing:.05em; text-align:left; }
.toc-row  { border-bottom:1px solid var(--border); cursor:pointer; transition:background .15s; }
.toc-row:hover { background:var(--teal-faint); }
.toc-row td   { padding:10px 14px; font-size:13px; }
.toc-id       { font-family:monospace; font-size:11px; color:var(--text3); }
.toc-title    { font-weight:600; color:var(--navy); }
.toc-type     { color:var(--text2); font-size:12px; }
.toc-score    { font-weight:700; color:var(--navy); text-align:center; }

/* badges */
.badge      { display:inline-block; padding:3px 10px; border-radius:12px; font-size:11px; font-weight:700; }
.badge-sm   { font-size:10.5px; padding:2px 8px; }
.sev-critical { background:#fff0f0; color:var(--sc); border:1px solid var(--sc); }
.sev-high     { background:#fff4ed; color:var(--sh); border:1px solid var(--sh); }
.sev-medium   { background:#fffbec; color:var(--sm); border:1px solid var(--sm); }
.sev-low      { background:#f0fff4; color:var(--sl); border:1px solid var(--sl); }
.status-confirmed  { background:#fff0f0; color:var(--sc); border:1px solid var(--sc); }
.status-hypothesis { background:#fffbec; color:#92600a; border:1px solid #f6c26e; }
.status-failed     { background:#f3f7fb; color:var(--text3); border:1px solid var(--border); }
.conf-high   { color:var(--sl); font-weight:700; } .conf-medium { color:var(--sm); font-weight:700; } .conf-low { color:var(--sc); font-weight:700; }

/* ── FINDING CARD ── */
.finding-card { background:var(--surf1); border:1px solid var(--border); border-radius:var(--r); margin-bottom:14px; box-shadow:var(--shadow); overflow:hidden; transition:box-shadow .2s; }
.finding-card:hover { box-shadow:var(--shadow2); }

.fc-toggle { display:flex; align-items:center; justify-content:space-between; padding:14px 20px; cursor:pointer; user-select:none; background:linear-gradient(90deg,var(--surf1) 0%,var(--surf2) 100%); border-bottom:1px solid transparent; transition:background .15s; }
.fc-toggle:hover { background:linear-gradient(90deg,var(--teal-faint) 0%,#e4f4f9 100%); }
.fc-toggle-left { display:flex; align-items:center; gap:9px; flex:1; min-width:0; flex-wrap:wrap; }
.fc-chevron  { color:var(--text3); font-size:12px; transition:transform .25s; min-width:14px; }
.fc-chevron.collapsed { transform:rotate(-90deg); }
.fc-id       { font-family:monospace; font-size:11px; color:var(--text3); }
.fc-title-txt{ font-size:14px; font-weight:700; color:var(--navy); }
.fc-toggle-right { display:flex; align-items:center; gap:10px; flex-shrink:0; }
.ev-lvl-badge{ background:var(--navy); color:#c8dde8; padding:2px 9px; border-radius:10px; font-size:10px; font-weight:700; letter-spacing:.05em; }
.score-ring  { display:block; }
.score-text  { font-size:13px; font-weight:800; font-family:inherit; }

.fc-body     { overflow:hidden; transition:max-height .35s ease, opacity .3s ease; }
.fc-body.collapsed { max-height:0 !important; opacity:0; }

.fc-meta-row { display:flex; flex-wrap:wrap; gap:7px; padding:12px 20px 0; border-top:1px solid var(--border); }
.meta-chip   { display:flex; align-items:center; gap:5px; background:var(--surf2); border:1px solid var(--border); border-radius:6px; padding:3px 9px; font-size:12px; }
.mc-k        { color:var(--text3); margin-right:2px; }

/* ── TABS ── */
.tabs-wrap   { padding:16px 20px 20px; }
.tabs-nav    { display:flex; gap:2px; border-bottom:2px solid var(--border); margin-bottom:18px; flex-wrap:wrap; }
.tbtn        { background:none; border:none; padding:8px 16px; font-size:13px; font-weight:600; color:var(--text2); cursor:pointer; border-bottom:3px solid transparent; margin-bottom:-2px; border-radius:6px 6px 0 0; transition:all .15s; }
.tbtn:hover  { color:var(--navy); background:var(--surf2); }
.tbtn.active { color:var(--navy); border-bottom-color:var(--teal); background:var(--teal-faint); }
.tab-panel   { display:none; }
.tab-panel.active { display:block; }

/* ── PANEL CONTENT ── */
.p2col  { display:grid; grid-template-columns:1fr 1fr; gap:24px; }
.p2col > div { min-width:0; }
.ph     { font-size:12px; font-weight:700; color:var(--navy); letter-spacing:.06em; text-transform:uppercase; margin:14px 0 7px; }
.ph:first-child { margin-top:0; }
.pdesc  { font-size:13.5px; color:var(--text); line-height:1.75; }
.pre-cond { padding-left:16px; font-size:13px; color:var(--text); line-height:1.85; }
.muted  { color:var(--text3); font-style:italic; font-size:13px; }

.loc-card { background:var(--surf2); border:1px solid var(--border); border-radius:8px; padding:12px 14px; display:flex; flex-direction:column; gap:6px; width:100%; }
.loc-row  { display:flex; align-items:baseline; gap:8px; font-size:12.5px; }
.lk       { color:var(--text3); font-weight:600; width:34px; flex-shrink:0; font-size:11px; text-transform:uppercase; letter-spacing:.05em; }
.loc-row code { font-family:monospace; color:var(--navy); font-size:12px; word-break:break-all; flex:1; min-width:0; }
.snippet  { background:#1e3a5f; color:#a8d8e4; font-family:monospace; font-size:12px; padding:10px 14px; border-radius:7px; overflow-x:auto; border-left:3px solid var(--teal); line-height:1.6; width:100%; }

/* flow */
.flow-chain { display:flex; flex-direction:column; gap:3px; margin:8px 0; }
.flow-step  { background:var(--surf2); border:1px solid var(--border); border-radius:7px; padding:10px 13px; border-left-width:4px; }
.flow-src  { border-left-color:var(--sl); } .flow-sink { border-left-color:var(--sc); } .flow-prop { border-left-color:var(--sm); }
.flow-hdr  { display:flex; align-items:center; gap:8px; margin-bottom:4px; }
.flow-badge{ font-size:10px; font-weight:800; padding:2px 7px; border-radius:4px; letter-spacing:.06em; }
.flow-src  .flow-badge { background:#f0fff4; color:var(--sl); }
.flow-sink .flow-badge { background:#fff0f0; color:var(--sc); }
.flow-prop .flow-badge { background:#fffbec; color:var(--sm); }
.flow-loc  { font-family:monospace; font-size:11px; color:var(--text3); }
.flow-desc { font-size:13px; color:var(--text); }
.flow-code { display:block; font-family:monospace; font-size:12px; color:var(--navy); background:rgba(30,58,95,.06); padding:4px 8px; border-radius:4px; margin-top:4px; }

/* attack surface */
.as-card   { background:var(--surf2); border:1px solid var(--border); border-radius:8px; padding:14px; margin-bottom:14px; }
.as-grid   { display:flex; flex-wrap:wrap; gap:8px 22px; margin-top:8px; }
.as-item   { display:flex; flex-direction:column; }
.as-k      { font-size:11px; color:var(--text3); text-transform:uppercase; letter-spacing:.06em; }
.as-v      { font-size:13px; color:var(--navy); font-weight:500; }

/* bypass */
.bypass-box{ background:#fffbec; border:1px solid #f6c26e; border-radius:8px; padding:14px; margin:12px 0; }
.bypass-hdr{ font-size:13px; font-weight:700; margin-bottom:10px; }
.bp-yes { color:var(--sh); } .bp-no { color:var(--sl); }
.bp-idea   { margin-bottom:10px; padding-bottom:10px; border-bottom:1px solid rgba(246,194,110,.3); }
.bp-idea:last-child { margin:0; padding:0; border:none; }
.bp-tech   { display:inline-block; font-size:12px; font-weight:700; color:var(--sh); margin-bottom:3px; }
.bp-payload{ display:block; font-family:monospace; font-size:12px; background:rgba(0,0,0,.05); padding:3px 8px; border-radius:4px; margin:3px 0; }
.bp-reason { font-size:12.5px; color:var(--text2); }

/* evid table */
.evid-tbl  { width:100%; border-collapse:collapse; font-size:12px; margin:8px 0; }
.evid-tbl th { background:var(--surf2); padding:6px 10px; text-align:left; font-weight:700; color:var(--text2); border-bottom:1px solid var(--border); }
.evk { font-family:monospace; color:var(--navy); font-weight:700; padding:5px 10px; border-bottom:1px solid var(--border); }
.evv { font-family:monospace; color:var(--text2); padding:5px 10px; border-bottom:1px solid var(--border); }
.conf-row  { margin-top:12px; display:flex; align-items:flex-start; gap:10px; font-size:12.5px; }
.cr-k      { color:var(--text3); font-weight:700; white-space:nowrap; }
.cr-v      { color:var(--text2); }

/* ctrl */
.ctrl      { border-radius:7px; padding:9px 13px; margin-bottom:7px; border:1px solid; }
.ctrl-bypass { background:#fff8ec; border-color:#f6c26e; }
.ctrl-ok     { background:#f0fff4; border-color:#9ae6b4; }
.ctrl-row  { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.ctrl-name { font-weight:600; font-size:13px; }
.ctrl-badge{ padding:2px 8px; border-radius:10px; font-size:10px; font-weight:700; }
.ctrl-bypass .ctrl-badge { background:var(--sh); color:#fff; }
.ctrl-ok     .ctrl-badge { background:var(--sl); color:#fff; }
.ctrl-loc  { font-family:monospace; font-size:11px; color:var(--text3); }
.ctrl-note { font-size:12px; color:var(--text2); margin-top:4px; padding-left:2px; }

/* dyn verify */
.dv-banner { display:flex; align-items:center; gap:12px; padding:11px 16px; border-radius:8px; margin-bottom:12px; font-size:14px; font-weight:600; border:1px solid; }
.dv-icon   { font-size:16px; }
.dv-text   { flex:1; }
.dv-proof  { font-size:12px; font-weight:400; opacity:.75; }
.dv-verified   { background:#e6f4ff; color:#1a6bc4; border-color:#90c8f0; }
.dv-failed     { background:#fff0f0; color:var(--sc); border-color:var(--sc); }
.dv-blocked    { background:#fff4ed; color:var(--sh); border-color:var(--sh); }
.dv-skipped    { background:var(--surf2); color:var(--text2); border-color:var(--border); }
.dv-progress   { background:#fffbec; color:var(--sm); border-color:var(--sm); }
.dv-notstarted { background:var(--surf2); color:var(--text3); border-color:var(--border); }
.dv-summary    { font-size:13.5px; color:var(--text); line-height:1.75; margin-bottom:12px; }
.dv-snips      { display:flex; flex-direction:column; gap:5px; margin-bottom:14px; }
.dv-snip       { display:flex; align-items:center; gap:10px; padding:7px 12px; border-radius:7px; font-size:12px; border:1px solid; }
.dvsn-step     { font-weight:700; color:var(--navy); }
.dvsn-type     { color:var(--text3); min-width:88px; }
.dv-snip code  { font-family:monospace; font-size:11.5px; }
.ev-l3 { background:#e6f4ff; border-color:#90c8f0; } .ev-l2 { background:#f0fff4; border-color:#9ae6b4; }
.ev-l1 { background:#fffbec; border-color:#f6c26e; } .ev-l0 { background:var(--surf2); border-color:var(--border); }
.att-row { display:flex; align-items:flex-start; gap:9px; padding:7px 0; border-bottom:1px solid var(--border); flex-wrap:wrap; font-size:13px; }
.att-num { font-weight:800; color:var(--navy); min-width:22px; }
.att-res  { padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; }
.att-ok   { background:#f0fff4; color:var(--sl); } .att-fail { background:#fff0f0; color:var(--sc); }
.att-strategy { color:var(--text2); flex:1; }
.att-snip { font-family:monospace; font-size:11px; background:var(--surf2); padding:2px 7px; border-radius:4px; color:var(--navy); }
.rt-notes { margin-top:10px; background:var(--surf2); border-radius:6px; padding:9px 13px; font-size:12.5px; color:var(--text2); }

/* PoC */
.poc-banner { padding:10px 16px; border-radius:8px; font-size:13px; font-weight:700; margin-bottom:12px; border:1px solid; }
.poc-success  { background:#f0fff4; color:var(--sl); border-color:var(--sl); }
.poc-failure  { background:#fff0f0; color:var(--sc); border-color:var(--sc); }
.poc-pending  { background:var(--surf2); color:var(--text2); border-color:var(--border); }
.poc-timeout  { background:#fffbec; color:var(--sm); border-color:var(--sm); }
.poc-skipped  { background:var(--surf2); color:var(--text3); border-color:var(--border); }
.poc-authfailed{ background:#fff0f0; color:var(--sh); border-color:var(--sh); }
.poc-evbox    { background:var(--teal-faint); border:1px solid var(--teal-light); border-radius:7px; padding:10px 14px; font-size:13px; margin-bottom:14px; color:var(--navy); }
.poc-step     { margin-bottom:18px; }
.poc-step-hdr { display:flex; align-items:center; gap:9px; margin-bottom:9px; }
.poc-snum     { background:var(--navy); color:#c8dde8; padding:2px 10px; border-radius:12px; font-size:11px; font-weight:800; letter-spacing:.06em; }
.poc-sname    { font-size:13px; font-weight:600; color:var(--navy); }
.http-grid    { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
.http-pane    { background:#1a2e45; border-radius:8px; padding:12px 14px; overflow:hidden; }
.resp-pane    { background:#12243a; }
.http-pane-lbl{ font-size:10px; font-weight:800; letter-spacing:.12em; color:#7fb8cc; margin-bottom:8px; display:flex; align-items:center; gap:8px; }
.elapsed      { font-size:10px; color:var(--teal); font-weight:600; }
.http-rline   { display:flex; align-items:center; gap:8px; margin-bottom:8px; flex-wrap:wrap; }
.http-method  { padding:2px 9px; border-radius:5px; font-size:11px; font-weight:800; letter-spacing:.06em; }
.meth-get    { background:#e6f4ff; color:#1a6bc4; } .meth-post   { background:#f0fff4; color:var(--sl); }
.meth-put    { background:#fffbec; color:var(--sm); } .meth-delete { background:#fff0f0; color:var(--sc); }
.http-url     { font-family:monospace; font-size:12px; color:#a8d8e4; word-break:break-all; }
.http-hdrs    { font-family:monospace; font-size:11px; white-space:pre-wrap; word-break:break-all; margin-bottom:6px; line-height:1.7; }
.hdr-key { color:#4ab9c4; } .hdr-col { color:#5a7a8a; } .hdr-val { color:#a0cad8; }
.http-body    { font-family:monospace; font-size:11px; white-space:pre-wrap; word-break:break-word; word-wrap:break-word; color:#b8d4e0; background:rgba(255,255,255,.04); padding:6px 8px; border-radius:4px; line-height:1.5; overflow-x:auto; }
.resp-body    { border-left:3px solid var(--teal); }
.resp-sline   { display:flex; align-items:center; gap:9px; margin-bottom:8px; }
.resp-code    { font-size:16px; font-weight:800; font-family:monospace; }
.s2xx { color:#4cae7a; } .s3xx { color:var(--teal); } .s4xx { color:var(--sm); } .s5xx { color:var(--sc); } .sxxx { color:var(--text3); }
.resp-ct      { font-size:11px; color:#5a7a8a; }
.ev-matches   { display:flex; flex-direction:column; gap:4px; margin-top:8px; }
.ev-match     { display:flex; align-items:center; gap:7px; padding:5px 8px; border-radius:5px; font-size:11px; border:1px solid; }
.em-type      { font-weight:700; color:var(--navy); }
.em-str       { padding:1px 6px; border-radius:7px; font-size:10px; font-weight:800; background:var(--navy); color:#c8dde8; }
.em-snip      { font-family:monospace; font-size:11px; }

/* remediation */
.rem-grid  { display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-bottom:14px; }
.rem-short { background:#fff8ec; border:1px solid var(--sh); border-radius:8px; padding:14px 16px; }
.rem-long  { background:#e8f5fe; border:1px solid #90c8f0; border-radius:8px; padding:14px 16px; }
.rem-badge { font-size:11px; font-weight:800; letter-spacing:.07em; margin-bottom:8px; }
.rem-short .rem-badge { color:var(--sh); } .rem-long .rem-badge { color:#1a6bc4; }
.rem-short p, .rem-long p { font-size:13.5px; color:var(--text); line-height:1.7; }
.fix-block { background:#1a2e45; border-radius:8px; padding:14px; }
.fix-lang  { font-size:11px; font-weight:700; color:var(--teal); letter-spacing:.1em; text-transform:uppercase; margin-bottom:10px; }
.fix-grid  { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
.fix-before{ background:rgba(229,62,62,.12); border:1px solid rgba(229,62,62,.3); border-radius:6px; padding:10px 12px; }
.fix-after { background:rgba(56,161,105,.12); border:1px solid rgba(56,161,105,.3); border-radius:6px; padding:10px 12px; }
.fix-lbl   { display:block; font-size:10px; font-weight:800; letter-spacing:.1em; margin-bottom:5px; }
.fix-before .fix-lbl { color:#fc8282; } .fix-after .fix-lbl { color:#68d391; }
.fix-before code, .fix-after code { font-family:monospace; font-size:12px; color:#c8dde8; display:block; white-space:pre-wrap; word-break:break-all; }

/* footer */
.footer { border-top:1px solid var(--border); padding:16px 0; margin-top:auto; display:flex; align-items:center; justify-content:space-between; color:var(--text3); font-size:12px; flex-wrap:wrap; gap:10px; }
.footer strong { color:var(--navy); }

/* responsive */
@media (max-width:900px) {
  .cover-wrap, .p2col, .http-grid, .fix-grid, .rem-grid, .summary-layout { grid-template-columns:1fr; }
  .cover-wrap { padding:28px 20px; }
  .cover-title { font-size:22px; }
  .cover-right { flex-direction:row; flex-wrap:wrap; justify-content:flex-start; }
  .cover-stat-row { grid-template-columns:repeat(4,1fr); }
}
@media print {
  .topbar { display:none; }
  .fc-body { max-height:none !important; opacity:1 !important; }
  .tab-panel { display:block !important; }
  .tabs-nav { display:none; }
}
"""

# ──────────────────────────────────────────────
# JS
# ──────────────────────────────────────────────

JS = """
function toggleFinding(slug) {
  var body = document.getElementById('body-' + slug);
  var chev = document.getElementById('chev-' + slug);
  if (!body) return;
  if (body.classList.contains('collapsed')) {
    body.classList.remove('collapsed');
    chev.classList.remove('collapsed');
  } else {
    body.classList.add('collapsed');
    chev.classList.add('collapsed');
  }
}

function jumpTo(slug) {
  var el = document.getElementById(slug);
  if (!el) return;
  var body = document.getElementById('body-' + slug);
  var chev = document.getElementById('chev-' + slug);
  if (body && body.classList.contains('collapsed')) {
    body.classList.remove('collapsed');
    if (chev) chev.classList.remove('collapsed');
  }
  setTimeout(function(){ el.scrollIntoView({behavior:'smooth', block:'start'}); }, 80);
}

document.querySelectorAll('.tabs-wrap').forEach(function(wrap) {
  wrap.querySelectorAll('.tbtn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var tab = btn.getAttribute('data-tab');
      wrap.querySelectorAll('.tbtn').forEach(function(b){ b.classList.remove('active'); });
      wrap.querySelectorAll('.tab-panel').forEach(function(p){ p.classList.remove('active'); });
      btn.classList.add('active');
      var panel = wrap.querySelector('[data-panel="' + tab + '"]');
      if (panel) panel.classList.add('active');
    });
  });
});
"""


# ──────────────────────────────────────────────
# HTML BUILDER
# ──────────────────────────────────────────────

def build_html(data):
    audit    = data.get("audit",{})
    findings = data.get("findings",[])
    stage_map = {"static_audit":"静态代码审计","dynamic_verification":"动态漏洞验证","report":"最终安全报告"}
    stage = stage_map.get(audit.get("stage",""), audit.get("stage",""))
    audit_stage = audit.get("stage", "static_audit")
    title = audit.get("title","代码安全审计报告")

    findings_html = "\n".join(build_finding(f, i+1, audit_stage) for i, f in enumerate(findings))

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>{e(title)}</title>
<style>{CSS}</style>
</head>
<body>

<nav class="topbar">
  <div>
    <div class="tb-title">{e(title)}</div>
    <div class="tb-sub">代码安全审计报告 · Schema v{e(data.get("schema_version","3.0"))}</div>
  </div>
  <div class="tb-stage">{e(stage)}</div>
</nav>

<div class="page">
  {build_cover(audit, findings)}
  {build_summary(audit, findings)}
  {build_toc(findings)}

  <section class="sec" id="findings">
    <div class="sec-hdr"><span class="sec-num">03</span><h2>漏洞详情</h2></div>
    {findings_html}
  </section>

  <footer class="footer">
    <span>本报告由 <strong>vibe-csa</strong> 自动审计系统生成</span>
    <span>Schema v{e(data.get("schema_version","3.0"))} · 审计编号 {e(audit.get("audit_id","—"))}</span>
    <span>生成于 {datetime.now().strftime("%Y-%m-%d %H:%M")}</span>
  </footer>
</div>

<script>{JS}</script>
</body>
</html>"""


# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────

def main():
    args = parse_args()
    inp  = Path(args.input)
    out  = Path(args.output)

    if not inp.exists():
        print(f"[ERROR] 输入文件不存在: {inp}", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] 读取: {inp}")
    with open(inp, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as ex:
            print(f"[ERROR] JSON 解析失败: {ex}", file=sys.stderr)
            sys.exit(1)

    schema = data.get("schema_version","?")
    if schema != "3.0":
        print(f"[WARN] schema_version={schema}，本脚本针对 3.0 优化")

    n = len(data.get("findings",[]))
    print(f"[INFO] 漏洞数量: {n}  阶段: {data.get('audit',{}).get('stage','—')}")

    html = build_html(data)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)

    size = out.stat().st_size / 1024
    print(f"[OK]  报告已生成: {out}  ({size:.1f} KB)")

if __name__ == "__main__":
    main()