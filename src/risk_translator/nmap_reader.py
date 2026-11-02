"""Read an Nmap XML scan produced with `nmap -sV --script vulners -oX scan.xml`.

Structure we rely on:

    <nmaprun>
      <host>
        <address addr="10.0.0.5" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22">
            <service name="ssh" product="OpenSSH" version="8.9p1"/>
            <script id="vulners" output="...">
              <table key="cpe:/a:openbsd:openssh:8.9p1">
                <table>
                  <elem key="id">CVE-2023-38408</elem>
                  <elem key="type">cve</elem>
                  ...

Some vulners entries are exploits or advisories rather than CVEs (their id is
not a CVE ID); we skip those. Older versions of the script only fill in the
`output` text, so we fall back to finding CVE IDs in that text.

We parse with defusedxml, which refuses XML tricks such as entity expansion
("billion laughs") that the standard library parser would process.
"""

import re
from collections import Counter
from pathlib import Path
from xml.etree.ElementTree import Element, ParseError

import defusedxml.ElementTree as SafeET
from defusedxml import DefusedXmlException

from risk_translator.errors import InputError
from risk_translator.models import Finding
from risk_translator.readers import AssetRegistry, InputResult, normalise_cve_id

CVE_IN_TEXT = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def _host_ip(host: Element) -> str | None:
    """Return the host's IPv4 address, or its IPv6 address if it has no IPv4 one."""
    addresses = {a.get("addrtype"): a.get("addr") for a in host.findall("address")}
    return addresses.get("ipv4") or addresses.get("ipv6")


def _cves_from_script(script: Element) -> list[str]:
    """Return the unique CVE IDs listed by one vulners script element, in order."""
    found: list[str] = []
    tables = list(script.iter("table"))
    for table in tables:
        for elem in table.findall("elem"):
            if elem.get("key") == "id":
                cve_id = normalise_cve_id(elem.text or "")
                if cve_id:
                    found.append(cve_id)
    if not tables:
        found = [match.upper() for match in CVE_IN_TEXT.findall(script.get("output", ""))]
    return list(dict.fromkeys(found))


def _service_label(port: Element) -> str:
    """Describe a port and its service, e.g. "tcp/22 ssh OpenSSH 8.9p1"."""
    label = f"{port.get('protocol', '?')}/{port.get('portid', '?')}"
    service = port.find("service")
    if service is not None:
        parts = [service.get("name"), service.get("product"), service.get("version")]
        label = " ".join([label, *[part for part in parts if part]])
    return label


def _host_cves(host: Element) -> list[tuple[str, str]]:
    """Return (service label, CVE ID) pairs for every vulners result on a host."""
    pairs: list[tuple[str, str]] = []
    for port in host.findall("./ports/port"):
        for script in port.findall("script"):
            if script.get("id") == "vulners":
                label = _service_label(port)
                pairs.extend((label, cve_id) for cve_id in _cves_from_script(script))
    for script in host.findall("./hostscript/script"):
        if script.get("id") == "vulners":
            pairs.extend(("host", cve_id) for cve_id in _cves_from_script(script))
    return list(dict.fromkeys(pairs))


def read_nmap_xml(path: Path, assets: AssetRegistry) -> InputResult:
    """Turn each host and service in an Nmap XML scan into Findings.

    Hosts are matched to assets.yaml by IP address. Hosts that are not in the
    assets file are not scored, but each one is reported as a warning so it is
    never dropped silently.
    """
    try:
        root = SafeET.parse(path).getroot()
    except FileNotFoundError:
        raise InputError(f"Scan file not found: {path}") from None
    except DefusedXmlException:
        raise InputError(f"Scan file {path} contains unsafe XML and was not read") from None
    except (ParseError, OSError) as exc:
        raise InputError(f"Scan file {path} is not valid XML: {exc}") from None

    if root.tag != "nmaprun":
        raise InputError(f"{path} does not look like Nmap XML output (no <nmaprun> element)")

    findings: list[Finding] = []
    warnings: list[str] = []
    unknown_hosts: Counter[str] = Counter()
    hosts_seen = 0
    for host in root.findall("host"):
        ip = _host_ip(host)
        if ip is None:
            continue
        hosts_seen += 1
        pairs = _host_cves(host)
        asset = assets.find_by_ip(ip)
        if asset is None:
            unknown_hosts[ip] += len(pairs)
            continue
        for service, cve_id in pairs:
            findings.append(
                Finding(asset=asset, cve_id=cve_id, source=f"{path.name} {ip}", service=service)
            )

    for ip, cve_count in unknown_hosts.items():
        warnings.append(
            f"Host {ip} is in the scan ({cve_count} CVE(s)) but not in the assets file, "
            "so it was not assessed. Add it to assets.yaml to include it."
        )
    if hosts_seen == 0:
        warnings.append(f"The scan {path.name} contains no hosts.")
    return InputResult(findings=findings, warnings=warnings)
