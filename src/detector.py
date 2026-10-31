import re


def analyze_event(event):
    """
    Analyse one Windows process-creation event.
    Returns an explainable detection result.
    """

    process_name = event.get("process_name") or ""
    command_line = event.get("command_line") or ""

    reasons = []
    matched_rules = []

    # Rule TL001: PowerShell encoded-command indicator
    is_powershell = (
        "powershell.exe" in process_name.lower()
        or "pwsh.exe" in process_name.lower()
    )

    encoded_command_pattern = r"(?i)(?:^|\s)-(?:encodedcommand|enc)(?=\s|$)"

    if is_powershell and re.search(
        encoded_command_pattern, command_line
    ):
        matched_rules.append("TL001")
        reasons.append(
            "PowerShell command contains -EncodedCommand or -enc."
        )

    if matched_rules:
        status = "FLAGGED"
        severity = "MEDIUM"
    else:
        status = "NORMAL"
        severity = "INFO"

    return {
        "status": status,
        "severity": severity,
        "matched_rules": matched_rules,
        "reasons": reasons,
        "process_name": process_name,
        "process_id": event.get("process_id"),
        "command_line": command_line,
        "parent_process": event.get("parent_process"),
        "timestamp": event.get("timestamp"),
    }
