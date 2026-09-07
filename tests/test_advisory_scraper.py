from datetime import datetime, timezone

from vm_analysis.advisory_scraper import parse_advisory


def test_structured_advisory_extracts_versions_ids_and_command():
    body = b"""
    <html><head><title>Security update</title>
    <script type="application/ld+json">{"@type":"TechArticle","name":"Kernel update","version":"6.5.0-41"}</script>
    </head><body><h2>Remediation</h2>
    <p>Affected versions: Ubuntu 22.04 kernels before 6.5.0-41</p>
    <p>Fixed versions: 6.5.0-41</p>
    <p>Update identifier: USN-7000-1</p>
    <pre>sudo apt-get update
sudo apt-get install --only-upgrade linux-image-generic</pre>
    <p>Reboot required. This issue is actively exploited.</p></body></html>
    """
    guidance = parse_advisory("https://ubuntu.com/security/CVE-2024-1086", body, "text/html",
                              datetime.now(timezone.utc))
    assert guidance.advisory_status == "extracted"
    assert guidance.fixed_version == "6.5.0-41"
    assert "USN-7000-1" in guidance.update_identifiers
    assert guidance.commands[0].command.startswith("sudo apt-get")
    assert guidance.reboot_required is True
    assert guidance.exploitation_status == "actively exploited"


def test_unstructured_page_is_partial_or_error_with_warning():
    guidance = parse_advisory("https://msrc.microsoft.com/update-guide/vulnerability/CVE-1",
                              b"<html><body><p>Welcome to the advisory.</p></body></html>",
                              "text/html", datetime.now(timezone.utc))
    assert guidance.advisory_status in {"partial", "error"}
    assert guidance.extraction_warnings
