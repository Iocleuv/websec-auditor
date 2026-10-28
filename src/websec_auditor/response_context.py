"""Conservative response classification for context-aware auditing.

Classify only from status and Content-Type; never inspect or store response
bodies. An absent or ambiguous Content-Type is *not* proof of HTML.
"""

HTML_MEDIA_TYPES = frozenset({"text/html", "application/xhtml+xml"})


def classify_response(status_code: int, content_type: str | None) -> str:
    """Return an allowlisted category; never echo raw server-provided values."""
    if 300 <= status_code < 400:
        return "redirect"
    if status_code in (204, 205) or 100 <= status_code < 200:
        return "no_body"
    if not 200 <= status_code < 300:
        return "non_success"

    if not content_type or not content_type.strip():
        return "unknown_content_type"
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type in HTML_MEDIA_TYPES:
        return "html_document"
    return "non_html"
