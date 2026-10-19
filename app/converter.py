"""Multi-backend query generator for Operator Console.

Translates Sigma rule YAML definitions into multiple target SIEM/query dialects:
1. Splunk SPL
2. Microsoft Sentinel KQL
3. Elasticsearch Lucene & EQL
4. Wazuh XML
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from xml.dom import minidom
from typing import Any

import yaml

try:
    from sigma.rule import SigmaRule
    from sigma.backends.splunk import SplunkBackend
    from sigma.backends.kusto import KustoBackend
    from sigma.backends.elasticsearch import LuceneBackend
    _HAVE_PYSIGMA = True
except ImportError:
    _HAVE_PYSIGMA = False


# Field mapping for Wazuh Sysmon / Windows EventChannel
_FIELD_MAP = {
    "Image": "win.eventdata.image",
    "CommandLine": "win.eventdata.commandLine",
    "ParentImage": "win.eventdata.parentImage",
    "TargetImage": "win.eventdata.targetImage",
    "SourceImage": "win.eventdata.sourceImage",
    "GrantedAccess": "win.eventdata.grantedAccess",
    "TargetFilename": "win.eventdata.targetFilename",
    "ImagePath": "win.eventdata.imagePath",
    "ServiceName": "win.eventdata.serviceName",
    "ServiceFileName": "win.eventdata.serviceFileName",
    "TargetObject": "win.eventdata.targetObject",
    "Details": "win.eventdata.details",
    "NewProcessName": "win.eventdata.newProcessName",
    "ParentProcessName": "win.eventdata.parentProcessName",
    "ProcessCommandLine": "win.eventdata.commandLine",
    "EventID": "win.system.eventID",
}

_SYSMON_PARENTS = {
    1: {"sid": "61603", "group": "sysmon_process_creation"},
    10: {"sid": "61612", "group": "sysmon_process_access"},
    11: {"sid": "61613", "group": "sysmon_file_create"},
    12: {"sid": "61614", "group": "sysmon_registry_event"},
    13: {"sid": "61615", "group": "sysmon_registry_event"},
    14: {"sid": "61616", "group": "sysmon_registry_event"},
}

_SYSMON_CATEGORIES = {
    "process_creation": 1,
    "process_access": 10,
    "file_event": 11,
    "registry_add": 12,
    "registry_delete": 12,
    "registry_set": 13,
    "registry_rename": 14,
}


def _pcre2_alt(values: list[str]) -> str:
    escaped = [re.escape(str(v)).replace("/", "\\/") for v in values]
    return "(" + "|".join(escaped) + ")" if len(escaped) > 1 else (escaped[0] if escaped else "")


def convert_to_wazuh_xml(doc: dict[str, Any], rule_id: int = 100099, level: int = 8) -> str:
    """Translate parsed Sigma doc into a standalone Wazuh custom rule XML block."""
    logsource = doc.get("logsource") or {}
    detection = doc.get("detection") or {}
    category = str(logsource.get("category", "")).lower()
    service = str(logsource.get("service", "")).lower()

    lvl_map = {"low": 3, "medium": 6, "high": 10, "critical": 13}
    rule_level = lvl_map.get(str(doc.get("level", "")).lower(), level)

    root = ET.Element("group", name="custom_rules,")
    rule_el = ET.SubElement(root, "rule", id=str(rule_id), level=str(rule_level))

    # Parent anchor
    if category in _SYSMON_CATEGORIES:
        eid = _SYSMON_CATEGORIES[category]
        parent = _SYSMON_PARENTS.get(eid, {"sid": "61603", "group": "sysmon_process_creation"})
        anchor_el = ET.SubElement(rule_el, "if_group")
        anchor_el.text = parent["group"]
    elif service in ("security", "system"):
        channel = "Security" if service == "security" else "System"
        f = ET.SubElement(rule_el, "field", name="win.system.channel")
        f.text = f"^{channel}$"
        f.set("type", "pcre2")
        grp = ET.SubElement(rule_el, "group")
        grp.text = "windows_security," if service == "security" else "windows_system,"
    elif service in ("sshd", "auth"):
        anchor_el = ET.SubElement(rule_el, "if_group")
        anchor_el.text = "sshd"

    # Field selections
    for name, sel in detection.items():
        if name == "condition" or not isinstance(sel, dict):
            continue
        is_filter = name.lower().startswith("filter")
        for key, val in sel.items():
            field_name = key.split("|")[0]
            op = key.split("|")[1] if "|" in key else "exact"
            wazuh_field = _FIELD_MAP.get(field_name, f"win.eventdata.{field_name.lower()}")
            
            f_el = ET.SubElement(rule_el, "field", name=wazuh_field)
            f_el.set("type", "pcre2")
            if is_filter:
                f_el.set("negate", "yes")

            val_list = val if isinstance(val, list) else [val]
            if op == "contains":
                f_el.text = "(?i).*" + _pcre2_alt(val_list) + ".*"
            elif op == "endswith":
                f_el.text = "(?i).*" + _pcre2_alt(val_list) + "$"
            elif op == "startswith":
                f_el.text = "(?i)^" + _pcre2_alt(val_list) + ".*"
            else:
                f_el.text = "^" + _pcre2_alt(val_list) + "$"

    # MITRE ATT&CK block
    tags = doc.get("tags") or []
    mitre_techniques = []
    for t in tags:
        s = str(t).strip().lower()
        if s.startswith("attack.t"):
            mitre_techniques.append(s[len("attack."):].upper())
    
    if mitre_techniques:
        mitre_el = ET.SubElement(rule_el, "mitre")
        for tech in mitre_techniques:
            id_el = ET.SubElement(mitre_el, "id")
            id_el.text = tech

    desc = ET.SubElement(rule_el, "description")
    desc.text = str(doc.get("title", "Custom Sigma Detection Rule"))

    xml_raw = ET.tostring(root, encoding="utf-8")
    dom = minidom.parseString(xml_raw)
    pretty = dom.toprettyxml(indent="  ")
    # Clean up empty lines and XML header
    lines = [line for line in pretty.splitlines() if line.strip() and not line.startswith("<?xml")]
    return "\n".join(lines)


def translate_sigma_rule(raw_yaml: str) -> dict[str, Any]:
    """Translate raw Sigma YAML into Splunk SPL, Sentinel KQL, Lucene, and Wazuh XML."""
    if not (raw_yaml or "").strip():
        return {
            "valid": False,
            "error": "Sigma YAML content is empty",
            "queries": {},
        }

    try:
        docs = list(yaml.safe_load_all(raw_yaml))
        if not docs or not isinstance(docs[0], dict):
            return {"valid": False, "error": "No valid YAML document found", "queries": {}}
        parsed = docs[0]
    except Exception as exc:
        return {"valid": False, "error": f"YAML parsing failed: {exc}", "queries": {}}

    queries: dict[str, str] = {}
    backends_available: list[str] = []

    # 1. Wazuh XML
    try:
        queries["wazuh"] = convert_to_wazuh_xml(parsed)
        backends_available.append("wazuh")
    except Exception as exc:
        queries["wazuh"] = f"<!-- Wazuh translation error: {exc} -->"

    # 2. pySigma Backends (Splunk, KQL, Lucene)
    if _HAVE_PYSIGMA:
        try:
            rule = SigmaRule.from_yaml(raw_yaml)

            # Splunk SPL
            try:
                splunk_res = SplunkBackend().convert_rule(rule)
                queries["splunk"] = "\n".join(splunk_res) if splunk_res else ""
                backends_available.append("splunk")
            except Exception as e:
                queries["splunk"] = f"# Splunk translation error: {e}"

            # Microsoft Sentinel KQL
            try:
                kusto_res = KustoBackend().convert_rule(rule)
                queries["kql"] = "\n".join(kusto_res) if kusto_res else ""
                backends_available.append("kql")
            except Exception as e:
                queries["kql"] = f"// Microsoft Sentinel KQL error: {e}"

            # Elasticsearch Lucene
            try:
                lucene_res = LuceneBackend().convert_rule(rule)
                queries["lucene"] = "\n".join(lucene_res) if lucene_res else ""
                backends_available.append("lucene")
            except Exception as e:
                queries["lucene"] = f"# Elasticsearch Lucene error: {e}"

            # CrowdStrike LogScale CQL
            try:
                cql_parts = []
                detection_dict = parsed.get("detection") or {}
                for sel_name, sel in detection_dict.items():
                    if sel_name.startswith("selection") and isinstance(sel, dict):
                        for k, v in sel.items():
                            f = k.split("|")[0]
                            vals = v if isinstance(v, list) else [v]
                            patt = "|".join([re.escape(str(x)) for x in vals])
                            cql_parts.append(f"{f}=/{patt}/i")
                filt = " and ".join(cql_parts) if cql_parts else "true"
                queries["cql"] = (
                    "// CrowdStrike LogScale CQL\n"
                    "#event_simpleName=/ProcessRollup2/ or #event_simpleName=/RegistryEvent/\n"
                    f"| {filt}\n"
                    "| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine])"
                )
                backends_available.append("cql")
            except Exception as e:
                queries["cql"] = f"// CrowdStrike LogScale CQL error: {e}"

        except Exception as exc:
            for b in ("splunk", "kql", "lucene", "cql"):
                if b not in queries:
                    queries[b] = f"Translation error: {exc}"

    # Extract clean MITRE ATT&CK technique code (e.g., T1059.001)
    tags = parsed.get("tags") or []
    extracted_tech = "T1000"
    if isinstance(tags, list):
        for t in tags:
            s = str(t).strip().lower()
            if s.startswith("attack.t"):
                code = s[len("attack."):].upper()
                if re.fullmatch(r"^T\d{4}(?:\.\d{3})?$", code):
                    extracted_tech = code
                    break
            elif s.startswith("t") and re.fullmatch(r"^T\d{4}(?:\.\d{3})?$", s.upper()):
                extracted_tech = s.upper()
                break

    return {
        "valid": True,
        "title": parsed.get("title", ""),
        "technique": extracted_tech,
        "logsource": parsed.get("logsource", {}),
        "queries": queries,
        "backends": backends_available,
    }


PRESET_RULES: dict[str, dict[str, str]] = {
    "t1547-001": {
        "id": "t1547-001",
        "title": "Registry Run Key Persistence via SetValue",
        "technique": "T1547.001",
        "slug": "registry_run_key_persistence",
        "yaml": """title: Registry Run Key Persistence via SetValue
id: b34a2e8c-8f20-4e3a-96bf-9c7b89d41234
status: test
description: Detects persistence mechanisms using Run or RunOnce keys
author: Sithum (Ctum0)
logsource:
  product: windows
  category: registry_set
detection:
  selection:
    TargetObject|contains:
      - '\\Microsoft\\Windows\\CurrentVersion\\Run'
      - '\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
      - '\\Microsoft\\Windows\\CurrentVersion\\RunServices'
  filter:
    Image|endswith:
      - '\\Windows\\System32\\msiexec.exe'
      - '\\Windows\\SysWOW64\\msiexec.exe'
  condition: selection and not filter
tags:
  - attack.persistence
  - attack.t1547.001
level: high
"""
    },
    "t1003-001": {
        "id": "t1003-001",
        "title": "Windows Credential Dumping via LSASS Access",
        "technique": "T1003.001",
        "slug": "lsass_credential_dumping",
        "yaml": """title: Windows Credential Dumping via LSASS Access
id: a12b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: test
description: Detects process access to LSASS for credential dumping
author: Sithum (Ctum0)
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\\lsass.exe'
    GrantedAccess:
      - '0x1010'
      - '0x1038'
      - '0x1fffff'
  condition: selection
tags:
  - attack.credential_access
  - attack.t1003.001
level: high
"""
    },
    "t1053-005": {
        "id": "t1053-005",
        "title": "Scheduled Task Creation via Security Log",
        "technique": "T1053.005",
        "slug": "scheduled_task_creation",
        "yaml": """title: Scheduled Task Creation
id: c5d6e7f8-9a0b-1c2d-3e4f-5a6b7c8d9e0f
status: test
description: Detects scheduled task creation via EventID 4698
author: Sithum (Ctum0)
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4698
  condition: selection
tags:
  - attack.execution
  - attack.persistence
  - attack.t1053.005
level: medium
"""
    },
    "t1059-001": {
        "id": "t1059-001",
        "title": "Suspicious PowerShell Download Cradle",
        "technique": "T1059.001",
        "slug": "powershell_download_cradle",
        "yaml": """title: Suspicious PowerShell Download Cradle
id: d7e8f9a0-1b2c-3d4e-5f6a-7b8c9d0e1f2a
status: test
description: Detects PowerShell executing inline download cradles (Net.WebClient, DownloadString)
author: Sithum (Ctum0)
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
    CommandLine|contains:
      - 'Net.WebClient'
      - 'DownloadString'
      - 'DownloadFile'
  condition: selection
tags:
  - attack.execution
  - attack.t1059.001
level: high
"""
    },
    "t1053-002": {
        "id": "t1053-002",
        "title": "At Command Used for Scheduled Job Creation",
        "technique": "T1053.002",
        "slug": "at_command_job_creation",
        "yaml": """title: At Command Used for Scheduled Job Creation
id: e8a123bc-5d4e-4f3a-8b1c-9e2d3f4a5b6c
status: experimental
description: Detects the execution of the legacy Windows at.exe utility to schedule tasks
author: Sithum (Ctum0)
date: 2026-10-18
references:
  - https://attack.mitre.org/techniques/T1053/002/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\at.exe'
    CommandLine|contains:
      - ' /create '
      - ' -create '
  condition: selection
falsepositives:
  - Legacy administrative scripts scheduling maintenance jobs
tags:
  - attack.persistence
  - attack.t1053.002
level: high
"""
    },
    "t1685-005": {
        "id": "t1685-005",
        "title": "Clear Windows Event Logs via Wevtutil",
        "technique": "T1685.005",
        "slug": "clear_windows_event_logs",
        "yaml": """title: Clear Windows Event Logs via Wevtutil
id: f9b234cd-6e5f-5a4b-9c2d-0e3f4a5b6c7d
status: stable
description: Detects attempts to clear Windows event logs using wevtutil command-line utility
author: Sithum (Ctum0)
date: 2026-10-18
references:
  - https://attack.mitre.org/techniques/T1685/005/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\wevtutil.exe'
    CommandLine|contains:
      - ' cl '
      - ' clear-log '
  condition: selection
falsepositives:
  - Routine system maintenance scripts by authorized administrators
tags:
  - attack.defense_evasion
  - attack.t1685.005
level: high
"""
    },
    "t1543-003": {
        "id": "t1543-003",
        "title": "Suspicious Windows Service Creation via SC.exe",
        "technique": "T1543.003",
        "slug": "suspicious_service_creation",
        "yaml": """title: Suspicious Windows Service Creation via SC.exe
id: a0c345de-7f6a-6b5c-0d3e-1f4a5b6c7d8e
status: test
description: Detects new Windows service creation executing binaries from suspicious temporary or writable paths
author: Sithum (Ctum0)
date: 2026-10-18
references:
  - https://attack.mitre.org/techniques/T1543/003/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\sc.exe'
    CommandLine|contains:
      - ' create '
  selection_path:
    CommandLine|contains:
      - '\\AppData\\'
      - '\\Temp\\'
      - '\\Users\\Public\\'
      - 'C:\\Temp\\'
  condition: selection and selection_path
falsepositives:
  - Software installers executing from user Temp directories
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1543.003
level: high
"""
    },
    "t1555-003": {
        "id": "t1555-003",
        "title": "Web Browser Credential Store Database Access",
        "technique": "T1555.003",
        "slug": "browser_credential_store_access",
        "yaml": """title: Web Browser Credential Store Database Access
id: b1d456ef-8a7b-7c6d-1e4f-2a5b6c7d8e9f
status: experimental
description: Detects suspicious process access referencing web browser stored credential files (Login Data, logins.json, key4.db)
author: Sithum (Ctum0)
date: 2026-10-18
references:
  - https://attack.mitre.org/techniques/T1555/003/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'Login Data'
      - 'logins.json'
      - 'key4.db'
      - 'vaultcmd'
  filter:
    Image|endswith:
      - '\\chrome.exe'
      - '\\msedge.exe'
      - '\\firefox.exe'
  condition: selection and not filter
falsepositives:
  - Enterprise browser profile backup scripts
tags:
  - attack.credential_access
  - attack.t1555.003
level: high
"""
    },
    "t1021-001": {
        "id": "t1021-001",
        "title": "Remote Desktop Protocol (RDP) Lateral Execution",
        "technique": "T1021.001",
        "slug": "rdp_lateral_execution",
        "yaml": """title: Remote Desktop Protocol (RDP) Lateral Execution
id: c2e567fa-9b8c-8d7e-2f5a-3b6c7d8e9f0a
status: experimental
description: Detects command-line invocation of mstsc.exe with specific remote admin targeting
author: Sithum (Ctum0)
date: 2026-10-18
references:
  - https://attack.mitre.org/techniques/T1021/001/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\mstsc.exe'
    CommandLine|contains:
      - ' /v:'
      - ' /admin'
      - ' /shadow:'
  condition: selection
falsepositives:
  - System administrators managing remote endpoints via RDP
tags:
  - attack.lateral_movement
  - attack.t1021.001
level: medium
"""
    }
}
