import os
import pefile

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

# Packer signatures based on section names
KNOWN_PACKERS = {
    ".upx": "UPX (Ultimate Packer for eXecutables)",
    ".aspack": "ASPack",
    ".vmp": "VMProtect",
    ".themida": "Themida",
    ".enigma": "Enigma Protector",
    ".nsp": "NsPack",
    ".pecompact": "PECompact"
}

SUSPICIOUS_APIS = [
    "VirtualAlloc", "VirtualProtect", "CreateRemoteThread", "WriteProcessMemory", 
    "LoadLibrary", "GetProcAddress", "SetWindowsHookEx", "URLDownloadToFile", 
    "InternetOpenUrl", "CryptAcquireContext", "CreateService", "RegCreateKeyEx",
    "OpenProcess", "ShellExecute", "IsDebuggerPresent"
]

def scan_with_yara(file_path):
    if not YARA_AVAILABLE:
        return [{"rule": "Yara Not Unavailable", "description": "Yara-python is not installed."}]

    rules_dir = os.path.join(os.path.dirname(__file__), "rules")
    if not os.path.exists(rules_dir):
        return []

    yara_matches = []
    # Find all .yar inside rules_dir
    for rule_file in os.listdir(rules_dir):
        if rule_file.endswith(".yar"):
            rule_path = os.path.join(rules_dir, rule_file)
            try:
                rules = yara.compile(filepath=rule_path)
                matches = rules.match(file_path)
                for match in matches:
                    yara_matches.append({
                        "rule": match.rule,
                        "description": match.meta.get("description", "No description available")
                    })
            except Exception as e:
                pass # Ignore broken rules
    return yara_matches

def detect_packers(sections):
    packers = []
    for section in sections:
        sec_name = section.get('name', '').lower().strip()
        # Checking by section name
        for packer_sig, packer_name in KNOWN_PACKERS.items():
            if packer_sig in sec_name and packer_name not in packers:
                packers.append(packer_name)
                
        # Checking by high entropy
        if section.get('entropy', 0) > 7.2 and section.get('virtual_size_int', 0) > 0:
            if "High Entropy (Potential obfuscator)" not in packers:
                packers.append(f"High Entropy section ({section.get('name')})")

    return packers

def calculate_threat_score(sections, imports, yara_matches):
    score = 0
    factors = []

    # 1. Packer and Entropy Analysis
    for sec in sections:
        if sec.get('entropy', 0) > 7.2:
            score += 15
            factors.append(f"High entropy in section {sec.get('name')} (Likely Packed/Obfuscated)")
            break # Only penalize once for entropy

    for sec in sections:
        sec_name = sec.get('name', '').lower().strip()
        for packer_sig in KNOWN_PACKERS.keys():
            if packer_sig in sec_name:
                score += 30
                factors.append(f"Known packer indicator found: {sec_name}")
                break

    # 2. Suspicious Imports Analysis
    suspicious_calls_found = []
    for imp in imports:
        for func in imp.get("functions", []):
            for sus_api in SUSPICIOUS_APIS:
                if sus_api.lower() in func.lower():
                    suspicious_calls_found.append(func)
    
    if len(suspicious_calls_found) > 0:
        score += min(len(suspicious_calls_found) * 5, 40) # Max 40 points from imports
        factors.append(f"Found {len(suspicious_calls_found)} suspicious API imports (e.g., Code Injection, Evasion)")

    # 3. YARA Matches
    if yara_matches and len(yara_matches) > 0:
        score += 30
        factors.append(f"Matched {len(yara_matches)} YARA signature(s)")

    # Normalize score
    final_score = min(max(int(score), 0), 100)
    
    level = "Clean"
    if final_score > 30:
         level = "Suspicious"
    if final_score > 70:
         level = "Malicious"

    return {
        "score": final_score,
        "level": level,
        "factors": factors
    }
