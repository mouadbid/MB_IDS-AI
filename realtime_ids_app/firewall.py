import subprocess
import re


def _run(cmd: str) -> tuple[int, str]:
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode, result.stdout + result.stderr


def block_ip(ip: str) -> bool:
    rule_name = f"IDS_BLOCK_{ip.replace('.', '_')}"
    code, _ = _run(
        f'netsh advfirewall firewall add rule name="{rule_name}" '
        f'dir=in action=block remoteip={ip} enable=yes'
    )
    return code == 0


def unblock_ip(ip: str) -> bool:
    rule_name = f"IDS_BLOCK_{ip.replace('.', '_')}"
    code, _ = _run(
        f'netsh advfirewall firewall delete rule name="{rule_name}"'
    )
    return code == 0


def list_blocked() -> list[str]:
    _, output = _run('netsh advfirewall firewall show rule name=all')
    blocked = []
    current_name = None
    for line in output.splitlines():
        name_match = re.match(r'Rule Name:\s+(.+)', line.strip())
        if name_match:
            current_name = name_match.group(1).strip()
        if current_name and current_name.startswith('IDS_BLOCK_'):
            ip_match = re.match(r'RemoteIP:\s+(.+)', line.strip())
            if ip_match:
                ip = ip_match.group(1).strip()
                if ip not in blocked:
                    blocked.append(ip)
    return blocked


def is_blocked(ip: str) -> bool:
    return ip in list_blocked()
