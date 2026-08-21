from typing import Dict, Any

class DNSExporter:
    def generate_sinkhole_formats(self, domain: str) -> str:
        clean_domain = domain.split(":")[0].lower()
        
        output = f"""# ========================================================
# PhishShield AI — Automated DNS Sinkhole Rules
# Target Domain: {clean_domain}
# ========================================================

# 1. Pi-hole / Standard /etc/hosts Format:
0.0.0.0 {clean_domain}
0.0.0.0 www.{clean_domain}
:: {clean_domain}
:: www.{clean_domain}

# 2. BIND 9 Response Policy Zone (RPZ) Format:
{clean_domain} CNAME .
*.{clean_domain} CNAME .

# 3. AdGuard Home / DNS Blocklist Filter Syntax:
||{clean_domain}^
"""
        return output
