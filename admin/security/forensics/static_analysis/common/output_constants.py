"""
Shared constants for static analysis tools in the Forensic Analysis Toolkit.

This module centralizes constants used across the static analysis tools,
including output formats, regex patterns for detection, thresholds, and
file type definitions. It ensures consistency between different tools
and facilitates easier maintenance.
"""

import re
from typing import Dict, Final, FrozenSet, List

# --- Output Format Constants ---
DEFAULT_OUTPUT_FORMAT: str = "json"
SUPPORTED_OUTPUT_FORMATS: List[str] = ["json", "text", "yaml"]
DEFAULT_OUTPUT_DIR: str = "analysis_output"
DEFAULT_REPORT_PERMS: int = 0o644  # Default permissions for output reports

# --- File Analysis Constants ---
DEFAULT_READ_CHUNK_SIZE: int = 65536  # 64KB chunks for efficient reading
MAX_FILE_SIZE_BYTES: int = 100 * 1024 * 1024  # 100MB default max size
MAX_EMBEDDED_DEPTH: int = 5  # Maximum recursion for embedded file extraction
MAX_EMBEDDED_FILES: int = 100  # Maximum number of embedded files to extract
DANGEROUS_FILE_EXTENSIONS: FrozenSet[str] = frozenset([
    ".exe", ".dll", ".sys", ".ocx", ".scr", ".com",  # Windows executables
    ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",   # Windows scripts
    ".sh", ".pl", ".py", ".rb",                      # Unix scripts
    ".jar", ".war", ".ear",                          # Java archives
    ".msi", ".msp", ".msc",                          # Windows installers
    ".apk", ".app"                                   # Mobile apps
])

# --- String Analysis Constants ---
DEFAULT_MIN_STRING_LENGTH: int = 6  # Default for memory analysis
DEFAULT_MAX_STRING_LENGTH: int = 20000  # Prevent excessive memory usage

# --- Regex Patterns for IOC (Indicator of Compromise) Detection ---
# Network IOCs
REGEX_IPV4 = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
REGEX_IPV6 = re.compile(r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b|\b(?:[A-F0-9]{1,4}:){6}:[A-F0-9]{1,4}\b|\b(?:[A-F0-9]{1,4}:){5}(?::[A-F0-9]{1,4}){1,2}\b', re.IGNORECASE)
REGEX_DOMAIN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
REGEX_URL = re.compile(r'\b(?:https?|ftp|file)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]*[-A-Za-z0-9+&@#/%=~_|]\b', re.IGNORECASE)
REGEX_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
REGEX_MAC_ADDR = re.compile(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b')

# File Path Patterns
REGEX_FILEPATH_WINDOWS = re.compile(r'\b[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*\b')
REGEX_FILEPATH_LINUX = re.compile(r'\b/(?:[^/\0<>|\r\n]+/)*[^/\0<>|\r\n]+\b')
REGEX_REGISTRY_PATH = re.compile(r'\b(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_USERS|HKU|HKEY_CLASSES_ROOT|HKCR|HKEY_CURRENT_CONFIG|HKCC)\\[^\\]+(?:\\[^\\]+)*\b', re.IGNORECASE)

# Potential Credentials / Sensitive Info
REGEX_PASSWORD_KW = re.compile(r'\b(?:password|passwd|pwd|secret|key|token|auth|cred(?:ential)?s?)\s*[:=]\s*[\'"]?\S+[\'"]?\b', re.IGNORECASE)
REGEX_API_KEY = re.compile(r'\b(?:api_?key|access_?key|secret_?key|app_?key|auth_?token)\s*[:=]\s*[\'"]?([a-zA-Z0-9/+._-]{16,})[\'"]?\b', re.IGNORECASE)
REGEX_AWS_KEY = re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')
REGEX_SSH_PRIVATE_KEY = re.compile(r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----')
REGEX_CERTIFICATE = re.compile(r'-----BEGIN CERTIFICATE-----')
REGEX_JWT = re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}')
REGEX_CREDIT_CARD = re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b')
REGEX_SSN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')

# Crypto & Encoding Patterns
REGEX_CRYPTO_KW = re.compile(r'\b(aes|des|rsa|sha[0-9]{1,3}|md[0-9]|encrypt|decrypt|cipher|hash|salt|pbkdf[0-9]|hmac)\b', re.IGNORECASE)
REGEX_BASE64 = re.compile(r'\b(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b')  # More strict Base64
REGEX_HEX = re.compile(r'\b[0-9a-fA-F]{16,}\b')  # Hex strings (potentially encoded data)

# Command & Code Execution Patterns
REGEX_CMD_EXEC = re.compile(r'\b(?:cmd\.exe|powershell|pwsh|bash|sh|/bin/(?:ba)?sh|system\(|exec\(|popen\(|subprocess\.|shell_exec|eval\(|child_process\.|Process\.Start|Runtime\.exec)\b', re.IGNORECASE)
REGEX_POWERSHELL_ENCODED = re.compile(r'powershell.*-[eE][nN][cC][oO][dD][eE][dD][cC][oO][mM]{0,4}[aA][nN][dD]? .*[A-Za-z0-9+/=]{30,}')
REGEX_COMMON_CMDS = re.compile(r'\b(?:net\s+user|whoami|ipconfig|ifconfig|systeminfo|tasklist|ps\s+-|wget\s+|curl\s+|netstat|nslookup|ping\s+|tracert)\b', re.IGNORECASE)
REGEX_SUSPICIOUS_ARGS = re.compile(r'\b(?:-hidden|-noninteractive|-windowstyle\s+hidden|-executionpolicy\s+bypass|-enc|-w\s+hidden|-noprofile)\b', re.IGNORECASE)

# Persistence Patterns
REGEX_SCHEDULED_TASK = re.compile(r'\b(?:schtasks\s+/create|at\s+\d{1,2}:\d{2}|crontab\s+-e|@reboot)\b', re.IGNORECASE)
REGEX_SERVICE_CREATE = re.compile(r'\b(?:sc\s+create|sc\s+config|new-service|systemctl\s+enable)\b', re.IGNORECASE)
REGEX_STARTUP_LOCATION = re.compile(r'\b(?:HKCU|HKLM)\\Software\\Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce|Explorer\\StartupApproved)\b', re.IGNORECASE)

# Web & Network Attack Patterns
REGEX_SQLI = re.compile(r"(?:'|\")(?:\s*OR\s+|\s*AND\s+|\s*UNION\s+|\s*SELECT\s+|\s*INSERT\s+|\s*UPDATE\s+|\s*DELETE\s+|\s*DROP\s+).*(?:'|\"|\-\-|\#)", re.IGNORECASE)
REGEX_XSS = re.compile(r'<script>.*</script>|<img[^>]+src[^>]+onerror|alert\(.*\)|eval\(.*document\.cookie', re.IGNORECASE)
REGEX_WEBSHELL_KW = re.compile(r'\b(?:shell_exec|passthru|backdoor|rootkit|webshell|c99|r57|cmd=|exec=|system=)\b', re.IGNORECASE)
REGEX_REVERSE_SHELL = re.compile(r'\b(?:nc\s+-[e|v]|netcat|ncat|socat.*exec|bash\s+-i|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*,\s*\d{1,5})', re.IGNORECASE)

# --- Entropy Constants ---
DEFAULT_ENTROPY_BLOCK_SIZE: int = 256  # Block size for entropy calculation
HIGH_ENTROPY_THRESHOLD: float = 7.5    # Threshold for high entropy (potential encryption)
RANDOM_DATA_THRESHOLD: float = 7.8     # Threshold for random/encrypted data
ENTROPY_BLOCK_COUNT_LIMIT: int = 10000 # Maximum number of blocks to analyze

# --- PE Analysis Constants ---
PE_SECTION_ENTROPY_THRESHOLD: float = 7.0     # Suspicious entropy for a PE section
PE_MIN_IMPORT_COUNT: int = 2                  # Minimum expected imports
PE_SUSPICIOUS_SECTIONS: List[str] = [".ndata", "UPX", "pebundle"]
PE_SUSPICIOUS_IMPORTS: List[str] = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"]
PE_RESOURCE_SIZE_LIMIT: int = 50 * 1024 * 1024  # 50MB maximum resource size

# --- YARA-related Constants ---
DEFAULT_YARA_TIMEOUT: int = 60  # Timeout for YARA rules in seconds
DEFAULT_YARA_RULES_PATH: str = "admin/security/forensics/static_analysis/common/yara_rules"
MAX_YARA_MATCHES: int = 100    # Maximum number of YARA matches to return

# --- Script Analysis Constants ---
SCRIPT_FILE_EXTENSIONS: List[str] = [
    '.js', '.py', '.ps1', '.vbs', '.php', '.pl', '.sh', '.bat', '.cmd',
    '.rb', '.lua', '.go', '.java', '.cs', '.ts', '.hta', '.vba', '.asp', '.aspx'
]

# Suspicious script keywords by language
SUSPICIOUS_SCRIPT_KEYWORDS: Dict[str, List[str]] = {
    "general": [
        'eval', 'exec', 'system', 'shell', 'invoke', 'decode', 'base64',
        'obfuscated', 'hidden', 'bypass', 'exploit', 'payload', 'backdoor',
    ],
    "javascript": [
        'eval', 'unescape', 'fromCharCode', 'document.write', 'atob',
        'execScript', 'new Function', 'setTimeout', 'setInterval', 'fetch'
    ],
    "python": [
        'eval', 'exec', 'compile', 'os.system', 'subprocess', 'pickle.loads',
        '__import__', 'base64.decode', 'requests', 'urllib', 'socket.connect'
    ],
    "powershell": [
        'Invoke-Expression', 'IEX', 'Invoke-Command', 'Start-Process',
        'New-Object', 'DownloadString', 'DownloadFile', 'WebClient'
    ],
    "vbscript": [
        'Execute', 'ExecuteGlobal', 'Shell', 'Run', 'CreateObject',
        'WScript.Shell', 'ActiveXObject', 'XMLHttpRequest'
    ],
    "php": [
        'eval', 'exec', 'system', 'shell_exec', 'passthru', 'include',
        'require', 'file_get_contents', 'base64_decode', 'gzinflate',
        'preg_replace', 'assert', 'create_function'
    ]
}

# --- Result Assessment Constants ---
SEVERITY_LEVELS: Dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}

# Risk score thresholds
RISK_THRESHOLD_LOW: float = 0.3
RISK_THRESHOLD_MEDIUM: float = 0.5
RISK_THRESHOLD_HIGH: float = 0.7
RISK_THRESHOLD_CRITICAL: float = 0.9
