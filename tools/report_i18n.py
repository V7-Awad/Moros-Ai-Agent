#!/usr/bin/env python3
"""
report_i18n.py — Bilingual Arabic/English Penetration Testing Report Formatter.

Supports Arabic-first deliverables (Modern Standard Arabic and Egyptian Arabic)
as well as English deliverables, with bilingual Arabic + English section headers,
table headers, severity labels, executive summaries, and remediation sections.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SUPPORTED_LANGS = ("en", "ar")
SUPPORTED_DIALECTS = ("msa", "egyptian")

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNASSESSED")

_SEVERITY_LABELS: Dict[str, Dict[str, Dict[str, str]]] = {
    "en": {
        "msa": {
            "CRITICAL": "Critical",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "INFO": "Informational",
            "UNASSESSED": "Unassessed",
        },
        "egyptian": {
            "CRITICAL": "Critical",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "INFO": "Informational",
            "UNASSESSED": "Unassessed",
        },
    },
    "ar": {
        "msa": {
            "CRITICAL": "حرج",
            "HIGH": "عالي",
            "MEDIUM": "متوسط",
            "LOW": "منخفض",
            "INFO": "معلوماتي",
            "UNASSESSED": "غير مُقيَّم",
        },
        "egyptian": {
            "CRITICAL": "حرج جداً",
            "HIGH": "عالي",
            "MEDIUM": "متوسط",
            "LOW": "بسيط",
            "INFO": "معلومة",
            "UNASSESSED": "لسه متقيّمش",
        },
    },
}

_COPY: Dict[str, Dict[str, Dict[str, str]]] = {
    "en": {
        "msa": {
            "title": "Penetration Test Report",
            "subtitle": "Automated Security Assessment Deliverable",
            "generated_at": "Generated At",
            "target_label": "Target",
            "language_label": "Language",
            "exec_summary_heading": "Executive Summary",
            "exec_summary_body": (
                "This report summarizes {total} triage item(s) identified during the security assessment "
                "of `{target}` ({validated} validated, {candidates} unverified candidate(s)). "
                "All AI-proposed severity ratings remain provisional and require human verification before final sign-off."
            ),
            "severity_table_heading": "Severity Breakdown",
            "col_severity": "Severity",
            "col_count": "Count",
            "col_review": "Review Status",
            "review_provisional": "AI-proposed — pending human review",
            "findings_table_heading": "Findings Overview",
            "col_index": "#",
            "col_title": "Finding",
            "col_endpoint": "Endpoint",
            "col_validation": "Validation",
            "no_findings": "No candidate or validated findings were recorded for this target.",
            "details_heading": "Detailed Findings & Remediation",
            "label_severity": "Severity",
            "label_endpoint": "Endpoint",
            "label_parameter": "Parameter",
            "label_cwe": "CWE",
            "label_validation": "Validation Status",
            "label_payload": "Payload / Trigger",
            "label_evidence": "Evidence IDs",
            "label_details": "Technical Details",
            "label_poc": "Reproduction cURL",
            "remediation_item_heading": "Remediation",
            "default_remediation": "Validate and sanitize untrusted input, enforce strict server-side authorization checks, and verify the fix with a targeted regression test.",
            "remediation_section_heading": "Remediation Recommendations",
            "remediation_recs": (
                "1. Prioritize Critical and High items with confirmed reproduction evidence.\n"
                "2. Enforce server-side input validation, output encoding, and authorization boundaries.\n"
                "3. Re-run targeted verification checks after patching to confirm remediation."
            ),
            "limitations_heading": "Limitations & Human Review",
            "limitations_body": (
                "- AI-proposed severities are provisional until confirmed by a security engineer.\n"
                "- Automated checks may not cover multi-step business logic flows without manual review."
            ),
            "status_validated": "Validated",
            "status_unverified": "Unverified Candidate",
        },
        "egyptian": {
            "title": "Penetration Test Report",
            "subtitle": "Automated Security Assessment Deliverable",
            "generated_at": "Generated At",
            "target_label": "Target",
            "language_label": "Language",
            "exec_summary_heading": "Executive Summary",
            "exec_summary_body": (
                "This report summarizes {total} triage item(s) identified during the security assessment "
                "of `{target}` ({validated} validated, {candidates} unverified candidate(s)). "
                "All AI-proposed severity ratings remain provisional and require human verification before final sign-off."
            ),
            "severity_table_heading": "Severity Breakdown",
            "col_severity": "Severity",
            "col_count": "Count",
            "col_review": "Review Status",
            "review_provisional": "AI-proposed — pending human review",
            "findings_table_heading": "Findings Overview",
            "col_index": "#",
            "col_title": "Finding",
            "col_endpoint": "Endpoint",
            "col_validation": "Validation",
            "no_findings": "No candidate or validated findings were recorded for this target.",
            "details_heading": "Detailed Findings & Remediation",
            "label_severity": "Severity",
            "label_endpoint": "Endpoint",
            "label_parameter": "Parameter",
            "label_cwe": "CWE",
            "label_validation": "Validation Status",
            "label_payload": "Payload / Trigger",
            "label_evidence": "Evidence IDs",
            "label_details": "Technical Details",
            "label_poc": "Reproduction cURL",
            "remediation_item_heading": "Remediation",
            "default_remediation": "Validate and sanitize untrusted input, enforce strict server-side authorization checks, and verify the fix with a targeted regression test.",
            "remediation_section_heading": "Remediation Recommendations",
            "remediation_recs": (
                "1. Prioritize Critical and High items with confirmed reproduction evidence.\n"
                "2. Enforce server-side input validation, output encoding, and authorization boundaries.\n"
                "3. Re-run targeted verification checks after patching to confirm remediation."
            ),
            "limitations_heading": "Limitations & Human Review",
            "limitations_body": (
                "- AI-proposed severities are provisional until confirmed by a security engineer.\n"
                "- Automated checks may not cover multi-step business logic flows without manual review."
            ),
            "status_validated": "Validated",
            "status_unverified": "Unverified Candidate",
        },
    },
    "ar": {
        "msa": {
            "title": "تقرير اختبار الاختراق الأمني (Penetration Test Report)",
            "subtitle": "مخرج تقييم أمني ثنائي اللغة — العربية والإنجليزية",
            "generated_at": "تاريخ الإنشاء (Generated At)",
            "target_label": "النطاق المستهدف (Target)",
            "language_label": "اللغة / اللهجة (Language)",
            "exec_summary_heading": "الملخص التنفيذي (Executive Summary)",
            "exec_summary_body": (
                "يستعرض هذا التقرير نتائج التقييم الأمني للنطاق `{target}`، حيث تم رصد إجمالي **{total}** عنصر فرز "
                "(**{validated}** نتيجة مُتحقق منها، و**{candidates}** مرشح بانتظار المراجعة). "
                "تبقى جميع تقييمات الخطورة المقترحة آلياً مبدئية وتخضع للمراجعة والاعتماد البشري."
            ),
            "severity_table_heading": "توزيع مستويات الخطورة (Severity Breakdown)",
            "col_severity": "مستوى الخطورة (Severity)",
            "col_count": "العدد (Count)",
            "col_review": "حالة المراجعة (Review Status)",
            "review_provisional": "مُقترح آلياً — بانتظار المراجعة البشرية (Pending Human Review)",
            "findings_table_heading": "جدول النتائج المكتشفة (Findings Overview)",
            "col_index": "#",
            "col_title": "العنوان (Finding)",
            "col_endpoint": "النقطة الطرفية (Endpoint)",
            "col_validation": "حالة التحقق (Validation)",
            "no_findings": "لم يتم تسجيل أي نتائج أو مرشحات أمنية لهذا النطاق حتى الآن.",
            "details_heading": "التفاصيل التقنية وخطط المعالجة (Detailed Findings & Remediation)",
            "label_severity": "مستوى الخطورة (Severity)",
            "label_endpoint": "المسار / النقطة الطرفية (Endpoint)",
            "label_parameter": "المُعامل (Parameter)",
            "label_cwe": "تصنيف CWE",
            "label_validation": "حالة التحقق (Validation Status)",
            "label_payload": "الحمولة / المؤشر (Payload)",
            "label_evidence": "معرّفات الأدلة (Evidence IDs)",
            "label_details": "التفاصيل التقنية (Technical Details)",
            "label_poc": "أمر إعادة الإنتاج (Reproduction cURL)",
            "remediation_item_heading": "التوصيات العلاجية (Remediation)",
            "default_remediation": "تحقق من جميع المدخلات ونقِّها على الخادم، وفعِّل ضوابط الصلاحيات الصارمة، ثم أعد الاختبار للتحقق من المعالجة.",
            "remediation_section_heading": "خطة المعالجة والتوصيات العامة (Remediation Recommendations)",
            "remediation_recs": (
                "1. معالجة الثغرات الحرجة والعالية ذات الأدلة المُؤكدة كأولوية قصوى.\n"
                "2. تطبيق التحقق الصارم من المدخلات وضوابط التفويض من جهة الخادم (Server-Side).\n"
                "3. إعادة تشغيل الفحوصات المستهدفة بعد الإصلاح للتأكد من إغلاق الثغرات بالكامل."
            ),
            "limitations_heading": "القيود والمراجعة البشرية (Limitations & Human Review)",
            "limitations_body": (
                "- جميع مستويات الخطورة المقترحة من الذكاء الاصطناعي مبدئية لحين تأكيدها من مهندس الأمن.\n"
                "- قد لا تغطي الفحوصات الآلية بعض تدفقات منطق الأعمال المعقدة دون مراجعة يدوية."
            ),
            "status_validated": "مُتحقق منه (Validated)",
            "status_unverified": "مرشح غير مؤكد (Unverified)",
        },
        "egyptian": {
            "title": "تقرير فحص الأمان واختبار الاختراق (Penetration Test Report)",
            "subtitle": "تقرير مزدوج اللغة — مصري / إنجليزي",
            "generated_at": "وقت التقرير (Generated At)",
            "target_label": "الموقع / النطاق (Target)",
            "language_label": "اللغة / اللهجة (Language)",
            "exec_summary_heading": "الملخص التنفيذي (Executive Summary)",
            "exec_summary_body": (
                "التقرير ده بيوضح نتائج الفحص الأمني على `{target}` — اترصد إجمالي **{total}** ملاحظة "
                "(منهم **{validated}** متأكدين بالأدلة، و**{candidates}** لسه محتاجين مراجعة). "
                "كل تقييمات الخطورة اللي الذكاء الاصطناعي اقترحها مبدئية ولازم تتراجع من مهندس أمان قبل الاعتماد النهائي."
            ),
            "severity_table_heading": "ملخص مستويات الخطورة (Severity Breakdown)",
            "col_severity": "مستوى الخطورة (Severity)",
            "col_count": "العدد (Count)",
            "col_review": "حالة المراجعة (Review Status)",
            "review_provisional": "تقييم مبدئي — محتاج مراجعة بشرية (Pending Human Review)",
            "findings_table_heading": "جدول الملاحظات المكتشفة (Findings Overview)",
            "col_index": "#",
            "col_title": "الملاحظة (Finding)",
            "col_endpoint": "الرابط / المسار (Endpoint)",
            "col_validation": "حالة التأكيد (Validation)",
            "no_findings": "مفيش أي ثغرات أو ملاحظات متسجلة للنطاق ده لحد دلوقتي.",
            "details_heading": "التفاصيل التقنية وطرق الإصلاح (Detailed Findings & Remediation)",
            "label_severity": "مستوى الخطورة (Severity)",
            "label_endpoint": "الرابط / المسار (Endpoint)",
            "label_parameter": "المُدخل / البراميتر (Parameter)",
            "label_cwe": "تصنيف CWE",
            "label_validation": "حالة التأكيد (Validation Status)",
            "label_payload": "البايلود / الدليل (Payload)",
            "label_evidence": "أرقام الأدلة (Evidence IDs)",
            "label_details": "الشرح التقني (Technical Details)",
            "label_poc": "أمر التجربة (Reproduction cURL)",
            "remediation_item_heading": "طريقة الإصلاح والحل (Remediation)",
            "default_remediation": "افحص ونضّف أي مدخلات جاية من المستخدم على السيرفر، وتأكد من صلاحيات الوصول، وبعدين جرّب تاني عشان تتأكد إن المشكلة اتقفلت.",
            "remediation_section_heading": "توصيات الإصلاح العامة (Remediation Recommendations)",
            "remediation_recs": (
                "1. ابدأ بإصلاح المشاكل الحرجة والعالية اللي ليها إثبات واضح الأول.\n"
                "2. طبّق فحص المدخلات وقواعد الصلاحيات على السيرفر مش في الواجهة بس.\n"
                "3. اعمل إعادة فحص بعد التعديل عشان تطمن إن كل ثغرة اتقفلت تماماً."
            ),
            "limitations_heading": "ملاحظات والمراجعة البشرية (Limitations & Human Review)",
            "limitations_body": (
                "- درجات الخطورة المقترحة من الأداة مبدئية لحد ما المهندس يراجعها ويأكدها.\n"
                "- الفحص الآلي ممكن ميغطيش كل سيناريوهات منطق الشغل من غير مراجعة يدوية."
            ),
            "status_validated": "مُؤكد (Validated)",
            "status_unverified": "محتاج مراجعة (Unverified)",
        },
    },
}


def _normalize_lang(lang: str) -> str:
    value = str(lang or "en").strip().lower()
    if value in ("ar", "arabic", "ar-eg", "ar-sa"):
        return "ar"
    return "en"


def _normalize_dialect(dialect: str) -> str:
    value = str(dialect or "msa").strip().lower()
    if value in ("egyptian", "egypt", "eg", "arz", "masri"):
        return "egyptian"
    return "msa"


def _normalize_severity_key(severity: Any) -> str:
    upper = str(severity or "UNASSESSED").upper()
    for level in _SEVERITY_ORDER:
        if level in upper:
            return level
    if "INFORMATIONAL" in upper:
        return "INFO"
    return "UNASSESSED"


def localize_severity_label(
    severity: Any,
    lang: str = "en",
    dialect: str = "msa",
    bilingual: bool = False,
) -> str:
    """
    Return a localized severity label for ``en`` or ``ar`` (``msa`` / ``egyptian``).

    When ``bilingual=True`` and ``lang='ar'``, appends the English label in
    parentheses, e.g. ``"حرج (Critical)"``.
    """
    norm_lang = _normalize_lang(lang)
    norm_dialect = _normalize_dialect(dialect)
    sev_key = _normalize_severity_key(severity)

    localized = _SEVERITY_LABELS[norm_lang][norm_dialect][sev_key]
    if bilingual and norm_lang == "ar":
        en_label = _SEVERITY_LABELS["en"]["msa"][sev_key]
        return f"{localized} ({en_label})"
    return localized


def _is_validated(finding: Dict[str, Any]) -> bool:
    status = str(finding.get("validation_status", "")).strip().lower()
    if status == "validated":
        return True
    record = finding.get("validation_record")
    return (
        isinstance(record, dict)
        and str(record.get("verified_by", "")).startswith("human:")
        and record.get("outcome") == "reproduced"
    )


def format_report_markdown(
    target: str,
    findings: Optional[List[Dict[str, Any]]] = None,
    lang: str = "en",
    dialect: str = "msa",
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Format penetration test findings into a clean Markdown deliverable.

    Supports English (``lang='en'``) and Arabic-first bilingual Arabic/English
    (``lang='ar'``) in Modern Standard Arabic (``dialect='msa'``) or Egyptian
    Arabic (``dialect='egyptian'``).
    """
    norm_lang = _normalize_lang(lang)
    norm_dialect = _normalize_dialect(dialect)
    copy = _COPY[norm_lang][norm_dialect]
    items = [f for f in (findings or []) if isinstance(f, dict)]
    meta = metadata or {}

    timestamp = str(meta.get("generated_at") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    lang_desc = f"{norm_lang.upper()} ({norm_dialect})"

    counts: Dict[str, int] = {lvl: 0 for lvl in _SEVERITY_ORDER}
    validated_count = 0
    for f in items:
        sev_key = _normalize_severity_key(f.get("severity_level") or f.get("severity"))
        counts[sev_key] += 1
        if _is_validated(f):
            validated_count += 1
    candidates_count = len(items) - validated_count

    lines: List[str] = []
    if norm_lang == "ar":
        lines.append('<div dir="rtl">')
        lines.append("")

    lines.append(f"# {copy['title']} — {target}")
    lines.append(f"_{copy['subtitle']}_")
    lines.append("")
    lines.append(f"- **{copy['target_label']}:** `{target}`")
    lines.append(f"- **{copy['generated_at']}:** {timestamp}")
    lines.append(f"- **{copy['language_label']}:** `{lang_desc}`")
    lines.append("")

    # Executive Summary
    lines.append(f"## {copy['exec_summary_heading']}")
    lines.append("")
    lines.append(
        copy["exec_summary_body"].format(
            target=target,
            total=len(items),
            validated=validated_count,
            candidates=candidates_count,
        )
    )
    lines.append("")

    # Severity Breakdown Table
    lines.append(f"### {copy['severity_table_heading']}")
    lines.append("")
    lines.append(f"| {copy['col_severity']} | {copy['col_count']} | {copy['col_review']} |")
    lines.append("|:---|---:|:---|")
    for sev_key in _SEVERITY_ORDER:
        sev_label = localize_severity_label(
            sev_key,
            lang=norm_lang,
            dialect=norm_dialect,
            bilingual=(norm_lang == "ar"),
        )
        lines.append(f"| {sev_label} | {counts[sev_key]} | {copy['review_provisional']} |")
    lines.append("")

    # Findings Overview Table
    lines.append(f"## {copy['findings_table_heading']}")
    lines.append("")
    if not items:
        lines.append(f"> {copy['no_findings']}")
        lines.append("")
    else:
        lines.append(
            f"| {copy['col_index']} | {copy['col_title']} | {copy['col_severity']} | "
            f"{copy['col_endpoint']} | {copy['col_validation']} |"
        )
        lines.append("|---:|:---|:---|:---|:---|")
        for idx, f in enumerate(items, 1):
            title = str(f.get("title") or f.get("type") or f"Finding {idx}").replace("|", "\\|")
            sev_label = localize_severity_label(
                f.get("severity_level") or f.get("severity"),
                lang=norm_lang,
                dialect=norm_dialect,
                bilingual=(norm_lang == "ar"),
            )
            endpoint = str(f.get("endpoint") or f.get("url") or f.get("source_file") or "-").replace("|", "\\|")
            val_label = copy["status_validated"] if _is_validated(f) else copy["status_unverified"]
            lines.append(f"| {idx} | {title} | {sev_label} | `{endpoint}` | {val_label} |")
        lines.append("")

        # Detailed Findings & Remediation
        lines.append(f"## {copy['details_heading']}")
        lines.append("")
        for idx, f in enumerate(items, 1):
            title = str(f.get("title") or f.get("type") or f"Finding {idx}")
            sev_label = localize_severity_label(
                f.get("severity_level") or f.get("severity"),
                lang=norm_lang,
                dialect=norm_dialect,
                bilingual=(norm_lang == "ar"),
            )
            endpoint = str(f.get("endpoint") or f.get("url") or f.get("source_file") or "-")
            param = str(f.get("parameter") or f.get("param") or "").strip()
            cwe = str(f.get("cwe") or f.get("cwe_id") or "").strip()
            payload = str(f.get("payload") or "").strip()
            details = str(f.get("details") or f.get("notes") or f.get("description") or "").strip()
            curl_cmd = str(f.get("curl_command") or f.get("curl") or "").strip()
            evidence_ids = f.get("evidence_ids") or []
            remediation = str(f.get("remediation") or copy["default_remediation"]).strip()
            val_label = copy["status_validated"] if _is_validated(f) else copy["status_unverified"]

            lines.append(f"### {idx}. {title}")
            lines.append("")
            lines.append(f"- **{copy['label_severity']}:** {sev_label} ({copy['review_provisional']})")
            lines.append(f"- **{copy['label_endpoint']}:** `{endpoint}`")
            lines.append(f"- **{copy['label_validation']}:** {val_label}")
            if param:
                lines.append(f"- **{copy['label_parameter']}:** `{param}`")
            if cwe:
                lines.append(f"- **{copy['label_cwe']}:** `{cwe}`")
            if payload:
                lines.append(f"- **{copy['label_payload']}:** `{payload}`")
            if evidence_ids:
                lines.append(f"- **{copy['label_evidence']}:** {', '.join(f'`{e}`' for e in evidence_ids)}")
            lines.append("")
            if details:
                lines.append(f"**{copy['label_details']}:** {details}")
                lines.append("")
            if curl_cmd:
                lines.append(f"**{copy['label_poc']}:**")
                lines.append("```bash")
                lines.append(curl_cmd)
                lines.append("```")
                lines.append("")

            lines.append(f"#### {copy['remediation_item_heading']}")
            lines.append("")
            lines.append(remediation)
            lines.append("")

    # General Remediation & Limitations
    lines.append(f"## {copy['remediation_section_heading']}")
    lines.append("")
    lines.append(copy["remediation_recs"])
    lines.append("")
    lines.append(f"## {copy['limitations_heading']}")
    lines.append("")
    lines.append(copy["limitations_body"])
    lines.append("")

    if norm_lang == "ar":
        lines.append("</div>")
        lines.append("")

    return "\n".join(lines)
