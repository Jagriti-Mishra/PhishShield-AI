import re
import socket
import urllib.request
import tldextract
from html.parser import HTMLParser
from typing import Dict, Any, List, Optional, Tuple

class TitleMetaExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = ""
        self.description = ""
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self.in_title = True
        elif tag.lower() == "meta":
            attr_dict = {k.lower(): v for k, v in attrs}
            name = attr_dict.get("name", "").lower()
            prop = attr_dict.get("property", "").lower()
            if name in ["description", "og:description", "twitter:description"] or prop in ["og:description", "twitter:description"]:
                if not self.description:
                    self.description = attr_dict.get("content", "")

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data


# Authoritative Global & Indian Enterprise & Sovereign Government Registry
OFFICIAL_AUTHORITY_REGISTRY: Dict[str, Dict[str, Any]] = {
    # Sovereign Government & Defense (India & Global)
    "nasa": {
        "canonical_name": "NASA (National Aeronautics and Space Administration)",
        "official_domains": ["nasa.gov"],
        "category": "Government & Space Research (Official)",
        "is_sovereign": True
    },
    "drdo": {
        "canonical_name": "Defence Research and Development Organisation (DRDO)",
        "official_domains": ["drdo.gov.in"],
        "category": "Government & Defense (India)",
        "is_sovereign": True
    },
    "isro": {
        "canonical_name": "Indian Space Research Organisation (ISRO)",
        "official_domains": ["isro.gov.in"],
        "category": "Government & Space (India)",
        "is_sovereign": True
    },
    "uidai": {
        "canonical_name": "Unique Identification Authority of India (UIDAI / Aadhaar)",
        "official_domains": ["uidai.gov.in", "myaadhaar.uidai.gov.in"],
        "category": "Government & Identity (India)",
        "is_sovereign": True
    },
    "incometax": {
        "canonical_name": "Income Tax Department (Government of India)",
        "official_domains": ["incometax.gov.in", "incometaxindiaefiling.gov.in"],
        "category": "Government & Taxation (India)",
        "is_sovereign": True
    },
    "epfo": {
        "canonical_name": "Employees' Provident Fund Organisation (EPFO)",
        "official_domains": ["epfindia.gov.in"],
        "category": "Government (India)",
        "is_sovereign": True
    },
    "rbi": {
        "canonical_name": "Reserve Bank of India (RBI)",
        "official_domains": ["rbi.org.in"],
        "category": "Central Banking & Regulatory",
        "is_sovereign": True
    },
    "sebi": {
        "canonical_name": "Securities and Exchange Board of India (SEBI)",
        "official_domains": ["sebi.gov.in"],
        "category": "Financial Regulatory (India)",
        "is_sovereign": True
    },
    "npci": {
        "canonical_name": "National Payments Corporation of India (NPCI / UPI)",
        "official_domains": ["npci.org.in"],
        "category": "Payment Infrastructure (India)",
        "is_sovereign": True
    },
    "bhim": {
        "canonical_name": "BHIM UPI (NPCI)",
        "official_domains": ["bhimupi.org.in"],
        "category": "Payment Infrastructure (India)",
        "is_sovereign": True
    },
    "irctc": {
        "canonical_name": "Indian Railway Catering and Tourism Corporation (IRCTC)",
        "official_domains": ["irctc.co.in"],
        "category": "Government & Railways (India)",
        "is_sovereign": True
    },
    "parivahan": {
        "canonical_name": "Ministry of Road Transport and Highways (Parivahan Sewa)",
        "official_domains": ["parivahan.gov.in"],
        "category": "Government (India)",
        "is_sovereign": True
    },
    "passportindia": {
        "canonical_name": "Passport Seva Portal (Ministry of External Affairs)",
        "official_domains": ["passportindia.gov.in"],
        "category": "Government & Foreign Affairs (India)",
        "is_sovereign": True
    },
    "cbse": {
        "canonical_name": "Central Board of Secondary Education (CBSE)",
        "official_domains": ["cbse.gov.in"],
        "category": "Government & Education (India)",
        "is_sovereign": True
    },
    "upsc": {
        "canonical_name": "Union Public Service Commission (UPSC)",
        "official_domains": ["upsc.gov.in"],
        "category": "Government (India)",
        "is_sovereign": True
    },
    "who": {
        "canonical_name": "World Health Organization (WHO)",
        "official_domains": ["who.int"],
        "category": "International Public Health",
        "is_sovereign": True
    },
    "un": {
        "canonical_name": "United Nations (UN)",
        "official_domains": ["un.org"],
        "category": "International Organization",
        "is_sovereign": True
    },
    "fbi": {
        "canonical_name": "Federal Bureau of Investigation (FBI)",
        "official_domains": ["fbi.gov"],
        "category": "Government & Law Enforcement",
        "is_sovereign": True
    },
    "cia": {
        "canonical_name": "Central Intelligence Agency (CIA)",
        "official_domains": ["cia.gov"],
        "category": "Government & Intelligence",
        "is_sovereign": True
    },

    # Banking & Financial Services
    "uco": {
        "canonical_name": "UCO Bank (Government of India Undertaking)",
        "official_domains": ["uco.bank.in", "ucobank.com"],
        "category": "Banking/Financial (India)",
        "is_sovereign": True
    },
    "sbi": {
        "canonical_name": "State Bank of India (SBI)",
        "official_domains": ["sbi.co.in", "sbi.bank.in", "onlinesbi.sbi", "onlinesbi.com"],
        "category": "Banking/Financial (India)",
        "is_sovereign": False
    },
    "hdfc": {
        "canonical_name": "HDFC Bank Ltd",
        "official_domains": ["hdfcbank.com", "hdfc.com"],
        "category": "Banking/Financial (India)",
        "is_sovereign": False
    },
    "icici": {
        "canonical_name": "ICICI Bank Ltd",
        "official_domains": ["icicibank.com"],
        "category": "Banking/Financial (India)",
        "is_sovereign": False
    },
    "canara": {
        "canonical_name": "Canara Bank",
        "official_domains": ["canarabank.com", "canara.bank.in"],
        "category": "Banking/Financial (India)",
        "is_sovereign": False
    },
    "union": {
        "canonical_name": "Union Bank of India",
        "official_domains": ["unionbankofindia.co.in", "unionbank.bank.in"],
        "category": "Banking/Financial (India)",
        "is_sovereign": False
    },
    "indianbank": {
        "canonical_name": "Indian Bank",
        "official_domains": ["indianbank.in", "indianbank.bank.in"],
        "category": "Banking/Financial (India)",
        "is_sovereign": False
    },
    "centralbank": {
        "canonical_name": "Central Bank of India",
        "official_domains": ["centralbankofindia.co.in", "centralbank.bank.in"],
        "category": "Banking/Financial (India)",
        "is_sovereign": False
    },
    "boi": {
        "canonical_name": "Bank of India (BOI)",
        "official_domains": ["bankofindia.co.in", "bankofindia.bank.in"],
        "category": "Banking/Financial (India)",
        "is_sovereign": False
    },
    "idbi": {
        "canonical_name": "IDBI Bank Ltd",
        "official_domains": ["idbibank.in"],
        "category": "Banking/Financial (India)",
        "is_sovereign": False
    },
    "axis": {
        "canonical_name": "Axis Bank Ltd",
        "official_domains": ["axisbank.com"],
        "category": "Banking/Financial (India)",
        "is_sovereign": False
    },
    "pnb": {
        "canonical_name": "Punjab National Bank (PNB)",
        "official_domains": ["pnbindia.in", "pnb.bank.in"],
        "category": "Banking/Financial (India)",
        "is_sovereign": False
    },
    "bob": {
        "canonical_name": "Bank of Baroda",
        "official_domains": ["bankofbaroda.in", "bob.bank.in"],
        "category": "Banking/Financial (India)",
        "is_sovereign": False
    },
    "kotak": {
        "canonical_name": "Kotak Mahindra Bank",
        "official_domains": ["kotak.com"],
        "category": "Banking/Financial (India)",
        "is_sovereign": False
    },

    # Aviation, Airlines & Travel
    "airindia": {
        "canonical_name": "Air India (Tata Group)",
        "official_domains": ["airindia.com"],
        "category": "Aviation, Airlines & Travel",
        "is_sovereign": False
    },
    "indigo": {
        "canonical_name": "IndiGo Airlines (InterGlobe Aviation)",
        "official_domains": ["goindigo.in"],
        "category": "Aviation, Airlines & Travel",
        "is_sovereign": False
    },
    "spicejet": {
        "canonical_name": "SpiceJet Limited",
        "official_domains": ["spicejet.com"],
        "category": "Aviation, Airlines & Travel",
        "is_sovereign": False
    },
    "vistara": {
        "canonical_name": "Vistara (Tata SIA Airlines)",
        "official_domains": ["airvistara.com"],
        "category": "Aviation, Airlines & Travel",
        "is_sovereign": False
    },
    "makemytrip": {
        "canonical_name": "MakeMyTrip Limited",
        "official_domains": ["makemytrip.com"],
        "category": "Travel, Hospitality & Mobility",
        "is_sovereign": False
    },
    "airbnb": {
        "canonical_name": "Airbnb, Inc.",
        "official_domains": ["airbnb.com"],
        "category": "Travel & Hospitality",
        "is_sovereign": False
    },
    "uber": {
        "canonical_name": "Uber Technologies, Inc.",
        "official_domains": ["uber.com"],
        "category": "Travel, Hospitality & Mobility",
        "is_sovereign": False
    },
    "ola": {
        "canonical_name": "ANI Technologies (Ola Cabs)",
        "official_domains": ["olacabs.com"],
        "category": "Travel, Hospitality & Mobility",
        "is_sovereign": False
    },

    # EdTech, Language Learning & Competitions
    "duolingo": {
        "canonical_name": "Duolingo, Inc.",
        "official_domains": ["duolingo.com"],
        "category": "EdTech & Language Learning",
        "is_sovereign": False
    },
    "unstop": {
        "canonical_name": "Unstop (formerly Dare2Compete)",
        "official_domains": ["unstop.com"],
        "category": "Education & Competitions",
        "is_sovereign": False
    },
    "udemy": {
        "canonical_name": "Udemy, Inc.",
        "official_domains": ["udemy.com"],
        "category": "EdTech & Online Learning",
        "is_sovereign": False
    },
    "coursera": {
        "canonical_name": "Coursera, Inc.",
        "official_domains": ["coursera.org"],
        "category": "Higher Education & Certification",
        "is_sovereign": False
    },
    "leetcode": {
        "canonical_name": "LeetCode, Inc.",
        "official_domains": ["leetcode.com"],
        "category": "EdTech & Competitive Programming",
        "is_sovereign": False
    },
    "kaggle": {
        "canonical_name": "Kaggle (Google LLC)",
        "official_domains": ["kaggle.com"],
        "category": "Data Science & AI Competitions",
        "is_sovereign": False
    },

    # Productivity, Design & Writing SaaS
    "grammarly": {
        "canonical_name": "Grammarly, Inc.",
        "official_domains": ["grammarly.com"],
        "category": "AI Writing & Productivity",
        "is_sovereign": False
    },
    "canva": {
        "canonical_name": "Canva Pty Ltd",
        "official_domains": ["canva.com"],
        "category": "Design & Creative Tools",
        "is_sovereign": False
    },
    "figma": {
        "canonical_name": "Figma, Inc.",
        "official_domains": ["figma.com"],
        "category": "Design & Creative Tools",
        "is_sovereign": False
    },
    "notion": {
        "canonical_name": "Notion Labs, Inc.",
        "official_domains": ["notion.so", "notion.com"],
        "category": "Productivity & Collaboration SaaS",
        "is_sovereign": False
    },
    "slack": {
        "canonical_name": "Slack Technologies (Salesforce)",
        "official_domains": ["slack.com"],
        "category": "Productivity & Collaboration SaaS",
        "is_sovereign": False
    },
    "zoom": {
        "canonical_name": "Zoom Video Communications, Inc.",
        "official_domains": ["zoom.us", "zoom.com"],
        "category": "Productivity & Collaboration SaaS",
        "is_sovereign": False
    },

    # E-Commerce & Retail
    "flipkart": {
        "canonical_name": "Flipkart Internet Private Limited",
        "official_domains": ["flipkart.com"],
        "category": "E-Commerce (India)",
        "is_sovereign": False
    },
    "amazon": {
        "canonical_name": "Amazon.com, Inc.",
        "official_domains": ["amazon.com", "amazon.in"],
        "category": "E-Commerce/Cloud",
        "is_sovereign": False
    },
    "myntra": {
        "canonical_name": "Myntra Designs Private Limited",
        "official_domains": ["myntra.com"],
        "category": "E-Commerce (India)",
        "is_sovereign": False
    },
    "meesho": {
        "canonical_name": "Meesho (Fashnear Technologies)",
        "official_domains": ["meesho.com"],
        "category": "E-Commerce (India)",
        "is_sovereign": False
    },

    # Food Delivery & Quick Commerce
    "swiggy": {
        "canonical_name": "Swiggy (Bundl Technologies)",
        "official_domains": ["swiggy.com"],
        "category": "Food & Quick Commerce",
        "is_sovereign": False
    },
    "zomato": {
        "canonical_name": "Zomato Limited",
        "official_domains": ["zomato.com"],
        "category": "Food Delivery & Tech",
        "is_sovereign": False
    },

    # Developer Tools & Big Tech
    "github": {
        "canonical_name": "GitHub, Inc.",
        "official_domains": ["github.com"],
        "category": "Developer Tools & Cloud",
        "is_sovereign": False
    },
    "gitlab": {
        "canonical_name": "GitLab Inc.",
        "official_domains": ["gitlab.com"],
        "category": "Developer Tools & Cloud",
        "is_sovereign": False
    },
    "dev": {
        "canonical_name": "daily.dev / DEV Community",
        "official_domains": ["daily.dev", "dev.to"],
        "category": "Developer Tools & Community",
        "is_sovereign": False
    },
    "dailydev": {
        "canonical_name": "daily.dev",
        "official_domains": ["daily.dev"],
        "category": "Developer Tools & Community",
        "is_sovereign": False
    },
    "google": {
        "canonical_name": "Google LLC (Alphabet Inc.)",
        "official_domains": ["google.com", "google.co.in"],
        "category": "Technology/Identity",
        "is_sovereign": False
    },
    "microsoft": {
        "canonical_name": "Microsoft Corporation",
        "official_domains": ["microsoft.com", "office.com", "live.com"],
        "category": "Technology/Enterprise",
        "is_sovereign": False
    },
    "apple": {
        "canonical_name": "Apple Inc.",
        "official_domains": ["apple.com", "icloud.com"],
        "category": "Technology/Consumer",
        "is_sovereign": False
    },
    "openai": {
        "canonical_name": "OpenAI, Inc. (ChatGPT)",
        "official_domains": ["openai.com", "chatgpt.com"],
        "category": "Artificial Intelligence & Research",
        "is_sovereign": False
    },
    "anthropic": {
        "canonical_name": "Anthropic PBC (Claude)",
        "official_domains": ["anthropic.com", "claude.ai"],
        "category": "Artificial Intelligence & Research",
        "is_sovereign": False
    },
    "phonepe": {
        "canonical_name": "PhonePe Private Limited",
        "official_domains": ["phonepe.com"],
        "category": "Payment Gateway (India)",
        "is_sovereign": False
    },
    "paytm": {
        "canonical_name": "Paytm (One97 Communications)",
        "official_domains": ["paytm.com"],
        "category": "Fintech & Payments (India)",
        "is_sovereign": False
    },
    "razorpay": {
        "canonical_name": "Razorpay Software Private Limited",
        "official_domains": ["razorpay.com"],
        "category": "Payment Gateway (India)",
        "is_sovereign": False
    },
    "paypal": {
        "canonical_name": "PayPal Holdings, Inc.",
        "official_domains": ["paypal.com"],
        "category": "Payment Gateway (Global)",
        "is_sovereign": False
    },
    "zerodha": {
        "canonical_name": "Zerodha Broking Limited (Kite)",
        "official_domains": ["zerodha.com"],
        "category": "Fintech & Stock Broking",
        "is_sovereign": False
    },
    "netflix": {
        "canonical_name": "Netflix, Inc.",
        "official_domains": ["netflix.com"],
        "category": "Streaming/Media",
        "is_sovereign": False
    },
    "spotify": {
        "canonical_name": "Spotify Technology S.A.",
        "official_domains": ["spotify.com"],
        "category": "Digital Music & Media",
        "is_sovereign": False
    },
    "linkedin": {
        "canonical_name": "LinkedIn Corporation",
        "official_domains": ["linkedin.com"],
        "category": "Professional Networking",
        "is_sovereign": False
    },
    "twitter": {
        "canonical_name": "X Corp. (Twitter)",
        "official_domains": ["x.com", "twitter.com"],
        "category": "Social Network",
        "is_sovereign": False
    }
}

# Sovereign Government Keywords requiring official government TLDs (.gov.in, .gov, .mil, .nic.in, etc.)
SOVEREIGN_GOV_KEYWORDS = {
    "drdo", "isro", "nasa", "uidai", "aadhaar", "incometax", "epfo", "rbi", "sebi",
    "npci", "irctc", "parivahan", "passport", "cbse", "upsc", "ssc", "police",
    "defense", "defence", "army", "navy", "airforce", "cbi", "nia", "aiims",
    "iit", "nit", "iim", "ministry", "rajbhavan", "judiciary", "highcourt", "bhim",
    "fbi", "cia", "whitehouse", "pentagon", "who", "un"
}

AUTHORIZED_SOVEREIGN_TLDS = {
    ".gov.in", ".nic.in", ".gov", ".mil", ".org.in", ".gov.uk", ".gov.au", ".res.in", ".bank.in", ".int"
}

AUTHORIZED_ACADEMIC_TLDS = {
    ".edu", ".ac.in", ".edu.in", ".ac.uk", ".edu.au"
}


class BrandVerifier:
    """Enterprise brand authentication and dynamic official authority registry engine."""

    @staticmethod
    def clean_domain_string(raw_input: str) -> str:
        """Strips protocol, paths, query, hash, port, and leading www from URL or domain string."""
        s = raw_input.strip().lower()
        if "://" in s:
            s = s.split("://")[1]
        s = s.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
        if s.startswith("www."):
            s = s[4:]
        return s

    @staticmethod
    def probe_domain_metadata(domain: str) -> Tuple[Optional[str], Optional[str]]:
        """Live probes website HTML header to extract official company title and description."""
        try:
            socket.gethostbyname(domain)
            req = urllib.request.Request(
                f"https://{domain}",
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 PhishShield/2.4"}
            )
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                content_type = resp.headers.get("Content-Type", "")
                if "text/html" not in content_type:
                    return None, None
                html = resp.read(16384).decode("utf-8", errors="ignore")
                parser = TitleMetaExtractor()
                parser.feed(html)
                title = re.sub(r'\s+', ' ', parser.title.strip()) if parser.title else None
                desc = re.sub(r'\s+', ' ', parser.description.strip()) if parser.description else None
                return title, desc
        except Exception:
            return None, None

    @staticmethod
    def authenticate_brand_candidate(brand_name: str, domain: str) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Validates if a candidate domain is an authentic, authorized official domain for a brand.
        Returns: (is_authenticated, error_reason, verified_metadata)
        """
        clean_domain = BrandVerifier.clean_domain_string(domain)
        b_key = brand_name.strip().lower().replace(" ", "").replace("-", "").replace("_", "")

        ext = tldextract.extract(clean_domain)
        if not ext.domain or not ext.suffix:
            return False, f"Invalid domain syntax '{clean_domain}'. Must be a valid Fully Qualified Domain Name.", None

        tld_dot = f".{ext.suffix}".lower()
        candidate_root = f"{ext.domain}.{ext.suffix}".lower()

        # 1. Check against Authoritative Registry by brand key or domain
        matched_entry = None
        if b_key in OFFICIAL_AUTHORITY_REGISTRY:
            matched_entry = OFFICIAL_AUTHORITY_REGISTRY[b_key]
        elif ext.domain.lower() in OFFICIAL_AUTHORITY_REGISTRY:
            matched_entry = OFFICIAL_AUTHORITY_REGISTRY[ext.domain.lower()]
        else:
            # Check if domain matches any authority's official domain list
            for k, entry in OFFICIAL_AUTHORITY_REGISTRY.items():
                if any(candidate_root == off_d or clean_domain == off_d or clean_domain.endswith(f".{off_d}") for off_d in entry["official_domains"]):
                    matched_entry = entry
                    break

        if matched_entry:
            official_domains = [d.lower() for d in matched_entry["official_domains"]]
            
            # Check if candidate matches any official domain or authorized subdomain
            is_match = any(
                candidate_root == off_d or candidate_root.endswith(f".{off_d}") or clean_domain == off_d or clean_domain.endswith(f".{off_d}")
                for off_d in official_domains
            )

            if not is_match:
                canonical = matched_entry["canonical_name"]
                return (
                    False,
                    f"Registration Blocked: Brand Authentication Failed: '{clean_domain}' is NOT the official domain for '{canonical}'. "
                    f"Authorized official domain(s): {', '.join(official_domains)}. Commercial / lookalike domain rejected.",
                    None
                )

            return True, None, matched_entry

        # 2. Sovereign Government Portals (.gov, .gov.in, .nic.in, .mil, .gov.uk, etc.)
        if tld_dot in AUTHORIZED_SOVEREIGN_TLDS:
            inferred_cat = BrandVerifier.infer_category(brand_name, clean_domain)
            return True, None, {
                "canonical_name": brand_name.upper() if len(brand_name) <= 5 else brand_name.title(),
                "official_domains": [candidate_root],
                "category": inferred_cat,
                "is_sovereign": True
            }

        # 3. Academic & Higher Education Institutions (.edu, .ac.in, .edu.in, .ac.uk)
        if tld_dot in AUTHORIZED_ACADEMIC_TLDS:
            return True, None, {
                "canonical_name": brand_name.upper() if len(brand_name) <= 5 else brand_name.title(),
                "official_domains": [candidate_root],
                "category": "Higher Education & Academic Institution",
                "is_sovereign": False
            }

        # 4. Sovereign Government Keywords attempted on Commercial / Unofficial TLDs
        is_sovereign_intent = (
            b_key in SOVEREIGN_GOV_KEYWORDS or
            any(kw in b_key for kw in ["drdo", "isro", "nasa", "gov", "police", "aadhaar", "ministry", "tax", "defense", "defence", "army", "navy"]) or
            any(kw in ext.domain for kw in ["drdo", "isro", "nasa", "uidai", "epfo", "parivahan", "passportindia", "defense", "defence", "police"])
        )

        if is_sovereign_intent:
            return (
                False,
                f"Registration Blocked: Sovereign Brand Security Violation: '{brand_name.upper()}' is recognized as a Government / Defense entity. "
                f"Government portals require authorized sovereign TLDs (.gov / .gov.in / .nic.in). "
                f"Unofficial commercial domain '{clean_domain}' with TLD '{tld_dot}' is strictly rejected.",
                None
            )

        # 5. Dynamic Live Enterprise Brand Discovery
        title, desc = BrandVerifier.probe_domain_metadata(clean_domain)
        inferred_cat = BrandVerifier.infer_category(brand_name, clean_domain, title, desc)
        canonical = title.split(" - ")[0].split(" | ")[0].strip() if title else brand_name.title()

        return True, None, {
            "canonical_name": canonical,
            "official_domains": [candidate_root],
            "category": inferred_cat,
            "is_sovereign": False
        }

    @staticmethod
    def infer_category(brand_name: str, domain: str, title: Optional[str] = None, desc: Optional[str] = None) -> str:
        """Dynamically infers accurate category/description based on domain, metadata, and brand name."""
        b_lower = brand_name.lower()
        d_lower = domain.lower()
        ext = tldextract.extract(d_lower)
        tld = f".{ext.suffix}".lower()

        # Check lookup first
        q = b_lower.replace(" ", "").replace("-", "").replace("_", "")
        if q in OFFICIAL_AUTHORITY_REGISTRY:
            return OFFICIAL_AUTHORITY_REGISTRY[q]["category"]

        # Sovereign TLDs
        if tld in AUTHORIZED_SOVEREIGN_TLDS:
            if any(w in b_lower or w in d_lower for w in ["nasa", "isro", "space", "cern", "esa", "jaxa"]):
                return "Government & Space Research (Official)"
            if any(w in b_lower or w in d_lower for w in ["drdo", "defense", "defence", "army", "navy", "airforce", "fbi", "cia", "police", "security", "pentagon"]):
                return "Government & Defense (India)"
            if any(w in b_lower or w in d_lower for w in ["tax", "incometax", "revenue", "irs", "customs"]):
                return "Government & Taxation (India)"
            if any(w in b_lower or w in d_lower for w in ["health", "who", "cdc", "nih", "fda", "aiims", "medical"]):
                return "International Public Health"
            return "Government & Public Sector (Official)"

        if tld in AUTHORIZED_ACADEMIC_TLDS:
            return "Higher Education & Academic Institution"

        # Combine text for dynamic NLP categorization
        combined = f"{b_lower} {d_lower} {title or ''} {desc or ''}".lower()

        # 1. Aviation & Airlines
        if any(w in combined for w in ["airindia", "indigo", "spicejet", "vistara", "airline", "airways", "aviation", "flight", "airfare"]):
            return "Aviation, Airlines & Travel"

        # 2. EdTech & Language Learning
        if any(w in combined for w in ["duolingo", "udemy", "coursera", "unstop", "leetcode", "kaggle", "learn", "language", "course", "education", "edtech", "tutor", "vocabulary", "study", "quiz", "academy"]):
            return "EdTech & Language Learning" if any(w in combined for w in ["duolingo", "language", "spanish", "french", "german", "english"]) else "EdTech & Online Learning"

        # 3. Design & Creative Tools
        if any(w in combined for w in ["canva", "figma", "sketch", "photoshop", "design", "graphic", "prototype", "wireframe", "vector", "canvas"]):
            return "Design & Creative Tools"

        # 4. Productivity, Writing & Collaboration
        if any(w in combined for w in ["grammarly", "writing assistant", "grammar", "spell check", "proofreading"]):
            return "AI Writing & Productivity"
        if any(w in combined for w in ["notion", "slack", "zoom", "trello", "asana", "workspace", "collaboration", "task management", "project management", "workflow"]):
            return "Productivity & Collaboration SaaS"

        # 5. Banking & Financial
        if any(w in combined for w in ["bank", "sbi", "hdfc", "icici", "pnb", "axis", "kotak", "rbi", "baroda", "uco", "netbanking", "savings account", "deposit"]):
            return "Banking/Financial (India)"

        # 6. Fintech & Payments
        if any(w in combined for w in ["pay", "wallet", "upi", "fintech", "stripe", "crypto", "binance", "coin", "broking", "trade", "phonepe", "paytm", "razorpay", "paypal", "zerodha", "groww"]):
            return "Payment Gateway & Fintech"

        # 7. Developer Tools & Cloud
        if any(w in combined for w in ["git", "dev", "api", "cloud", "host", "stack", "docker", "server", "github", "gitlab", "dailydev", "daily.dev", "stackoverflow", "postman", "kubernetes"]):
            return "Developer Tools & Cloud"

        # 8. E-Commerce & Retail
        if any(w in combined for w in ["shop", "store", "mart", "cart", "retail", "buy", "deal", "market", "flipkart", "amazon", "myntra", "ajio", "meesho", "nykaa", "ebay", "ecommerce"]):
            return "E-Commerce (India)"

        # 9. Food Delivery & Tech
        if any(w in combined for w in ["food", "eat", "dine", "kitchen", "delivery", "meal", "swiggy", "zomato", "blinkit", "zepto", "restaurant"]):
            return "Food Delivery & Tech"

        # 10. Social & Networking
        if any(w in combined for w in ["social", "chat", "connect", "network", "tweet", "post", "link", "linkedin", "twitter", "meta", "facebook", "instagram", "reddit", "discord", "telegram", "threads"]):
            return "Social Network"

        # 11. Media & Streaming
        if any(w in combined for w in ["stream", "music", "tv", "movie", "video", "play", "game", "media", "cast", "netflix", "spotify", "youtube", "hotstar"]):
            return "Digital Music & Media"

        # 12. Travel & Hospitality
        if any(w in combined for w in ["hotel", "travel", "tour", "stay", "cab", "ride", "room", "airbnb", "uber", "ola", "irctc", "makemytrip"]):
            return "Travel, Hospitality & Mobility"

        # 13. AI / Machine Learning (Strict standalone tokens only)
        tokens = set(re.findall(r'[a-zA-Z0-9]+', combined))
        if tokens.intersection({"ai", "gpt", "openai", "anthropic", "claude", "deepmind", "chatgpt", "gemini", "copilot", "llm", "genai", "neural"}):
            return "Artificial Intelligence & Research"

        return "Enterprise & Cloud Services"

    @staticmethod
    def lookup_brand(query: str) -> Optional[Dict[str, Any]]:
        """
        Intelligent official brand authority lookup and live auto-detection.
        1. Checks curated authority registry.
        2. Checks sovereign & academic TLDs.
        3. Probes live web and DNS for unknown enterprise brands dynamically.
        """
        raw_q = query.strip().lower()
        if not raw_q or len(raw_q) < 2:
            return None

        clean_q = BrandVerifier.clean_domain_string(raw_q)
        is_domain_input = ("." in clean_q)
        ext = tldextract.extract(clean_q)
        q_name = ext.domain.lower() if ext.domain else clean_q
        candidate_root = f"{ext.domain}.{ext.suffix}".lower() if (ext.domain and ext.suffix) else clean_q
        tld_dot = f".{ext.suffix}".lower() if ext.suffix else ""

        # Exact Alias & Typo Map for recognized brands
        alias_map = {
            "airindia": "airindia", "air_india": "airindia", "air-india": "airindia", "air ind": "airindia",
            "airbnb": "airbnb", "air bnb": "airbnb",
            "duolingo": "duolingo", "grammarly": "grammarly", "canva": "canva", "figma": "figma", "notion": "notion",
            "indigo": "indigo", "goindigo": "indigo", "spicejet": "spicejet", "vistara": "vistara",
            "swiigie": "swiggy", "swiggi": "swiggy", "swigy": "swiggy", "swiggie": "swiggy",
            "ubercabs": "uber", "olacabs": "ola",
            "zomat": "zomato",
            "pay": "paytm", "paypal": "paypal", "phonepe": "phonepe",
            "twit": "twitter", "tweet": "twitter", "x": "twitter",
            "leet": "leetcode", "git": "github", "link": "linkedin",
            "micro": "microsoft", "msft": "microsoft",
            "amaz": "amazon", "amzn": "amazon",
            "spot": "spotify",
            "drd": "drdo", "isr": "isro", "aadhaar": "uidai", "aadhar": "uidai",
            "tax": "incometax", "itr": "incometax", "train": "irctc", "railway": "irctc",
            "unst": "unstop", "udem": "udemy", "flipk": "flipkart", "flip": "flipkart",
            "ucobnk": "uco", "ucobank": "uco", "uco": "uco",
            "canarabnk": "canara", "canarabank": "canara",
            "pnbbnk": "pnb", "punjabbank": "pnb",
            "unionbank": "union", "unionbk": "union",
            "centralbank": "centralbank", "centralbk": "centralbank",
            "bankofindia": "boi", "boi": "boi",
            "bob": "bob", "bankofbaroda": "bob"
        }
        raw_norm = raw_q.replace(" ", "").replace("-", "").replace("_", "")
        if raw_norm in alias_map:
            q_name = alias_map[raw_norm]
        elif q_name in alias_map:
            q_name = alias_map[q_name]

        # 1. If user typed domain/URL, match against official authority registry
        if is_domain_input and candidate_root:
            for k, data in OFFICIAL_AUTHORITY_REGISTRY.items():
                official_domains = [d.lower() for d in data["official_domains"]]
                if any(candidate_root == off_d or clean_q == off_d or clean_q.endswith(f".{off_d}") for off_d in official_domains):
                    return {
                        "brand_name": k,
                        "canonical_name": data["canonical_name"],
                        "official_domain": data["official_domains"][0],
                        "official_domains": data["official_domains"],
                        "category": data["category"],
                        "is_sovereign": data["is_sovereign"],
                        "verified": True
                    }
            
            # Sovereign Government TLD lookup (.gov, .gov.in, etc.)
            if tld_dot in AUTHORIZED_SOVEREIGN_TLDS:
                inf_cat = BrandVerifier.infer_category(ext.domain, clean_q)
                c_name = ext.domain.upper() if len(ext.domain) <= 5 else ext.domain.title()
                return {
                    "brand_name": ext.domain,
                    "canonical_name": f"{c_name} (Official Government Portal)",
                    "official_domain": candidate_root,
                    "official_domains": [candidate_root],
                    "category": inf_cat,
                    "is_sovereign": True,
                    "verified": True
                }

            # Academic TLD lookup (.edu, .ac.in)
            if tld_dot in AUTHORIZED_ACADEMIC_TLDS:
                c_name = ext.domain.upper() if len(ext.domain) <= 5 else ext.domain.title()
                return {
                    "brand_name": ext.domain,
                    "canonical_name": f"{c_name} (Academic Institution)",
                    "official_domain": candidate_root,
                    "official_domains": [candidate_root],
                    "category": "Higher Education & Academic Institution",
                    "is_sovereign": False,
                    "verified": True
                }

            # Dynamic live domain probe
            title, desc = BrandVerifier.probe_domain_metadata(clean_q)
            if title or desc:
                inf_cat = BrandVerifier.infer_category(ext.domain, clean_q, title, desc)
                c_name = title.split(" - ")[0].split(" | ")[0].strip() if title else ext.domain.title()
                return {
                    "brand_name": ext.domain,
                    "canonical_name": c_name,
                    "official_domain": candidate_root,
                    "official_domains": [candidate_root],
                    "category": inf_cat,
                    "is_sovereign": False,
                    "verified": True
                }

            return None

        # 2. If user typed brand keyword in registry:
        if q_name in OFFICIAL_AUTHORITY_REGISTRY:
            data = OFFICIAL_AUTHORITY_REGISTRY[q_name]
            return {
                "brand_name": q_name,
                "canonical_name": data["canonical_name"],
                "official_domain": data["official_domains"][0],
                "official_domains": data["official_domains"],
                "category": data["category"],
                "is_sovereign": data["is_sovereign"],
                "verified": True
            }

        # 3. Exact Prefix match on brand keyword
        for k, data in OFFICIAL_AUTHORITY_REGISTRY.items():
            if len(q_name) >= 3 and k.startswith(q_name):
                return {
                    "brand_name": k,
                    "canonical_name": data["canonical_name"],
                    "official_domain": data["official_domains"][0],
                    "official_domains": data["official_domains"],
                    "category": data["category"],
                    "is_sovereign": data["is_sovereign"],
                    "verified": True
                }

        # 4. Dynamic Live Probing for newly typed Brand keywords
        if len(q_name) >= 3:
            candidate_domains = [f"{q_name}.com", f"{q_name}.org", f"{q_name}.in", f"{q_name}.io", f"{q_name}.ai", f"{q_name}.so"]
            for c_dom in candidate_domains:
                title, desc = BrandVerifier.probe_domain_metadata(c_dom)
                if title:
                    inf_cat = BrandVerifier.infer_category(q_name, c_dom, title, desc)
                    c_name = title.split(" - ")[0].split(" | ")[0].split(":")[0].strip() if title else q_name.title()
                    return {
                        "brand_name": q_name,
                        "canonical_name": c_name,
                        "official_domain": c_dom,
                        "official_domains": [c_dom],
                        "category": inf_cat,
                        "is_sovereign": False,
                        "verified": True
                    }

        return None
