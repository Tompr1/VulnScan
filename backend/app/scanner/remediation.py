"""
Finding enrichment — adds generic remediation and description context to
plugin findings that did not provide their own.
"""
from __future__ import annotations

import re

from app.scanner.plugins.base import Finding

_DETAILED_REMEDIATION_MIN_LENGTH = 50
_VERSION_PATTERN = re.compile(r"(?:version|installed|ver)[=: ]*([0-9][0-9.]+[0-9a-zA-Z.-]*)", re.IGNORECASE)

_REMEDIATION_DB = {
    "nginx": {
        "remediation": "Upgrade nginx to the latest stable version. Visit https://nginx.org/en/download.html for the latest release. Apply security patches and harden configuration by removing unnecessary modules, setting 'server_tokens off', and configuring proper TLS settings.",
        "category": "web_server",
    },
    "apache": {
        "remediation": "Upgrade Apache HTTP Server to the latest version from https://httpd.apache.org/download.cgi. Disable unnecessary modules (a2dismod), set 'ServerTokens Prod' and 'ServerSignature Off', enforce TLS 1.2+, and configure security headers.",
        "category": "web_server",
    },
    "http_server": {
        "remediation": "Upgrade Apache HTTP Server to the latest version. Disable server version disclosure in headers, enforce HTTPS, and apply all available security patches.",
        "category": "web_server",
    },
    "openssh": {
        "remediation": "Upgrade OpenSSH to the latest version via your package manager (apt upgrade openssh-server / yum update openssh-server). Disable root login (PermitRootLogin no), use key-based authentication only, disable SSHv1, and restrict allowed ciphers/MACs to modern algorithms.",
        "category": "remote_access",
    },
    "redis": {
        "remediation": "Upgrade Redis to the latest stable version from https://redis.io/download. Bind to localhost only (bind 127.0.0.1), enable AUTH with a strong password, disable dangerous commands (rename-command FLUSHALL ''), and run Redis as non-root.",
        "category": "database",
    },
    "elasticsearch": {
        "remediation": "Upgrade Elasticsearch to the latest version. Enable X-Pack security, configure TLS for transport and HTTP layers, set up authentication, and restrict network access to trusted hosts only.",
        "category": "database",
    },
    "postgresql": {
        "remediation": "Upgrade PostgreSQL to the latest minor version. Review pg_hba.conf to restrict access, enforce SSL connections, use strong passwords, and disable trust authentication.",
        "category": "database",
    },
    "mysql": {
        "remediation": "Upgrade MySQL to the latest version. Run mysql_secure_installation, disable remote root login, enforce SSL, and remove anonymous users.",
        "category": "database",
    },
    "wordpress": {
        "remediation": "Update WordPress core, all themes, and all plugins to the latest versions. Remove unused themes/plugins, enforce strong admin passwords, enable two-factor authentication, and use a Web Application Firewall (WAF).",
        "category": "cms",
    },
    "drupal": {
        "remediation": "Update Drupal core and all contributed modules to the latest versions. Review security advisories at https://www.drupal.org/security. Restrict admin access and configure proper file permissions.",
        "category": "cms",
    },
    "joomla": {
        "remediation": "Update Joomla to the latest version and patch all extensions. Review Joomla security advisories, enforce strong admin passwords, and restrict backend access by IP.",
        "category": "cms",
    },
    "magento": {
        "remediation": "Apply all Adobe Commerce / Magento security patches. Update to the latest version, enable two-factor admin authentication, review third-party extensions for vulnerabilities.",
        "category": "cms",
    },
    "openssl": {
        "remediation": "Upgrade OpenSSL to the latest version via your package manager. Disable TLS 1.0/1.1, prefer TLS 1.3, use strong cipher suites, and rotate certificates if a key compromise vulnerability was involved.",
        "category": "crypto",
    },
    "laravel": {
        "remediation": "Update Laravel to the latest LTS or stable version. Run 'composer update' to update dependencies, ensure APP_DEBUG=false in production, and rotate APP_KEY if compromised.",
        "category": "framework",
    },
    "nextjs": {
        "remediation": "Update Next.js to the latest version with 'npm update next'. Review and update all npm dependencies, and ensure no sensitive data is exposed in client-side bundles.",
        "category": "framework",
    },
    "php": {
        "remediation": "Upgrade PHP to the latest supported version (check https://www.php.net/supported-versions.php). Disable dangerous functions (exec, system, passthru) in php.ini, set expose_php=Off, and enable security extensions.",
        "category": "runtime",
    },
    "python": {
        "remediation": "Upgrade Python to the latest patch release of your major version. Review dependencies with 'pip audit' or 'safety check' and update vulnerable packages.",
        "category": "runtime",
    },
    "nodejs": {
        "remediation": "Upgrade Node.js to the latest LTS version from https://nodejs.org/. Run 'npm audit fix' to patch known dependency vulnerabilities.",
        "category": "runtime",
    },
    "sudo": {
        "remediation": "Upgrade sudo to the latest version. Review /etc/sudoers for overly permissive rules, enforce password prompts, and limit sudo access to required users only.",
        "category": "system",
    },
    "bash": {
        "remediation": "Upgrade bash to the latest version via your package manager. Ensure Shellshock (CVE-2014-6271) and related patches are applied.",
        "category": "system",
    },
    "glibc": {
        "remediation": "Upgrade glibc (libc6) to the latest version. This requires a system restart. Schedule maintenance and apply with 'apt upgrade libc6' or equivalent.",
        "category": "system",
    },
    "linux_kernel": {
        "remediation": "Update the Linux kernel to the latest patched version for your distribution. Reboot to activate the new kernel. Consider enabling automatic security updates.",
        "category": "system",
    },
    "curl": {
        "remediation": "Upgrade curl and libcurl to the latest version. Verify with 'curl --version'. If using curl in scripts, ensure TLS verification is not disabled.",
        "category": "networking",
    },
    "git": {
        "remediation": "Upgrade git to the latest version. Review repository permissions and ensure .git directories are not exposed on web servers.",
        "category": "development",
    },
    "docker": {
        "remediation": "Update Docker Engine to the latest version. Run containers as non-root, enable content trust, scan images for vulnerabilities, and keep base images updated.",
        "category": "container",
    },
    "containerd": {
        "remediation": "Upgrade containerd to the latest version. Review runtime security settings and ensure proper namespace isolation.",
        "category": "container",
    },
    "iis": {
        "remediation": "Apply the latest Windows security updates for IIS. Disable directory browsing, remove unnecessary ISAPI extensions, configure request filtering, and enforce TLS 1.2+.",
        "category": "web_server",
    },
    "asp.net": {
        "remediation": "Update the .NET runtime to the latest version. Disable detailed error messages in production (customErrors mode='On'), enforce HTTPS, and review web.config security settings.",
        "category": "framework",
    },
    "tomcat": {
        "remediation": "Upgrade Apache Tomcat to the latest version. Remove default applications (manager, examples), disable AJP if unused, configure HTTPS, and set secure cookie flags.",
        "category": "web_server",
    },
    "react": {
        "remediation": "Update React and related dependencies to the latest versions. Run 'npm audit' to identify and fix known vulnerabilities in the dependency tree.",
        "category": "framework",
    },
    "vue": {
        "remediation": "Update Vue.js and related packages to the latest versions. Review for XSS risks in v-html usage and ensure proper input sanitization.",
        "category": "framework",
    },
    "jquery": {
        "remediation": "Update jQuery to the latest version (3.x+). Older versions have known XSS vulnerabilities. Review usage of .html() and similar methods for XSS risks.",
        "category": "library",
    },
}


def enrich_remediation(finding: Finding) -> Finding:
    """Enrich a finding with remediation steps and version/target details.
    Info-severity findings (compliance passes) are skipped, as are findings
    whose plugin already wrote a detailed remediation. The SLA policy is added
    later, once the final severity is known (see app.risk.sla_engine).
    """
    if finding.severity and finding.severity.lower() == "info":
        return finding

    if finding.remediation and len(finding.remediation) > _DETAILED_REMEDIATION_MIN_LENGTH:
        return finding

    remediation_parts: list[str] = []
    evidence_lower = (finding.evidence or "").lower()
    title_lower = (finding.title or "").lower()
    plugin_lower = (finding.plugin_id or "").lower()
    combined = f"{evidence_lower} {title_lower} {plugin_lower}"

    for product_key, info in _REMEDIATION_DB.items():
        if product_key in combined:
            remediation_parts.append(f"[REMEDIATION] {info['remediation']}")
            break

    # Extract version info from evidence
    version_match = _VERSION_PATTERN.search(finding.evidence or "")
    if version_match:
        ver = version_match.group(1)
        remediation_parts.append(
            f"[AFFECTED VERSION] Detected version: {ver}. "
            f"Check the vendor's security advisory for this specific version "
            f"and upgrade to the latest patched release."
        )

    # Extract CPE info for component details
    cpe_match = re.search(r'cpe[=: ]*(cpe:2\.3:[^ ]+)', finding.evidence or "", re.I)
    if cpe_match:
        cpe = cpe_match.group(1)
        cpe_parts = cpe.split(":")
        if len(cpe_parts) >= 6:
            vendor = cpe_parts[3].replace("_", " ").title()
            product = cpe_parts[4].replace("_", " ").title()
            version = cpe_parts[5] if len(cpe_parts) > 5 and cpe_parts[5] != "*" else "unknown"
            remediation_parts.append(
                f"[AFFECTED COMPONENT] {vendor} {product} version {version}. "
                f"Search for security advisories at the vendor's website."
            )

    # CVE-specific remediation
    if finding.cve and finding.cve.startswith("CVE-"):
        remediation_parts.append(
            f"[CVE REFERENCE] {finding.cve} — "
            f"Review full details at https://nvd.nist.gov/vuln/detail/{finding.cve} "
            f"and https://www.cve.org/CVERecord?id={finding.cve}. "
            f"Check if your vendor has released a specific patch for this CVE."
        )

    if finding.is_kev:
        remediation_parts.append(
            "[CISA KEV] This vulnerability is actively exploited in the wild. "
            "Immediate remediation is required per CISA BOD 22-01. "
            "Apply patches within the KEV due date or implement "
            "compensating controls immediately."
        )

    if not remediation_parts:
        remediation_parts.append(
            "[GENERAL] Review the finding evidence and apply vendor-recommended "
            "patches or configuration changes. Consult the relevant security "
            "advisory for specific remediation steps."
        )

    finding.remediation = "\n\n".join(remediation_parts)
    return finding


def enrich_description(finding: Finding, target: str, scan_type: str) -> Finding:
    """Enrich finding description with target/version context if sparse."""
    desc_parts: list[str] = []

    if finding.description:
        desc_parts.append(finding.description)

    if target and target not in (finding.description or ""):
        desc_parts.append(f"Target: {target} (scan type: {scan_type})")

    evidence = finding.evidence or ""
    versions = _VERSION_PATTERN.findall(evidence)
    if versions and not any(v in (finding.description or "") for v in versions):
        desc_parts.append(f"Detected version(s): {', '.join(set(versions))}")

    ports = re.findall(r'open_ports=\[([^\]]+)\]', evidence)
    if ports and "port" not in (finding.description or "").lower():
        desc_parts.append(f"Open ports: {ports[0]}")

    pkg_match = re.search(r'package=(\S+)\s+installed=(\S+)', evidence)
    if pkg_match:
        pkg, ver = pkg_match.group(1), pkg_match.group(2)
        if pkg not in (finding.description or ""):
            desc_parts.append(f"Affected package: {pkg} (installed version: {ver})")

    finding.description = "\n".join(desc_parts) if desc_parts else finding.description
    return finding
