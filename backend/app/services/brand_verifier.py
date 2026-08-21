import re
import tldextract
from typing import Dict, Any, List, Optional, Tuple

# Authoritative Global & Indian Enterprise & Sovereign Government Registry
OFFICIAL_AUTHORITY_REGISTRY: Dict[str, Dict[str, Any]] = {
    # Government & Defense (India)
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

    # Banking & Financial Services
    "sbi": {
        "canonical_name": "State Bank of India (SBI)",
        "official_domains": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbi.bank.in"],
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
    "axis": {
        "canonical_name": "Axis Bank Ltd",
        "official_domains": ["axisbank.com"],
        "category": "Banking/Financial (India)",
        "is_sovereign": False
    },
    "pnb": {
        "canonical_name": "Punjab National Bank (PNB)",
        "official_domains": ["pnbindia.in"],
        "category": "Banking/Financial (India)",
        "is_sovereign": False
    },
    "bob": {
        "canonical_name": "Bank of Baroda",
        "official_domains": ["bankofbaroda.in"],
        "category": "Banking/Financial (India)",
        "is_sovereign": False
    },
    "kotak": {
        "canonical_name": "Kotak Mahindra Bank",
        "official_domains": ["kotak.com"],
        "category": "Banking/Financial (India)",
        "is_sovereign": False
    },

    # Fintech & Payment Gateways
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
    "groww": {
        "canonical_name": "Groww (Nextbillion Technology)",
        "official_domains": ["groww.in"],
        "category": "Fintech & Investments",
        "is_sovereign": False
    },
    "cred": {
        "canonical_name": "CRED (Dreamplug Technologies)",
        "official_domains": ["cred.club"],
        "category": "Fintech (India)",
        "is_sovereign": False
    },
    "binance": {
        "canonical_name": "Binance Holdings Ltd",
        "official_domains": ["binance.com"],
        "category": "Cryptocurrency Exchange",
        "is_sovereign": False
    },
    "coinbase": {
        "canonical_name": "Coinbase Global, Inc.",
        "official_domains": ["coinbase.com"],
        "category": "Cryptocurrency Exchange",
        "is_sovereign": False
    },

    # Big Tech, Enterprise Cloud & Identity
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
    "amazon": {
        "canonical_name": "Amazon.com, Inc.",
        "official_domains": ["amazon.com", "amazon.in"],
        "category": "E-Commerce/Cloud",
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
    "airbnb": {
        "canonical_name": "Airbnb, Inc.",
        "official_domains": ["airbnb.com"],
        "category": "Travel & Hospitality",
        "is_sovereign": False
    },
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
    "flipkart": {
        "canonical_name": "Flipkart Internet Private Limited",
        "official_domains": ["flipkart.com"],
        "category": "E-Commerce (India)",
        "is_sovereign": False
    },

    # Developer Platforms, EdTech & AI
    "unstop": {
        "canonical_name": "Unstop (formerly Dare2Compete)",
        "official_domains": ["unstop.com"],
        "category": "Education & Competitions",
        "is_sovereign": False
    },
    "github": {
        "canonical_name": "GitHub, Inc.",
        "official_domains": ["github.com"],
        "category": "Developer Tools & Cloud",
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
    },
    "leetcode": {
        "canonical_name": "LeetCode, Inc.",
        "official_domains": ["leetcode.com"],
        "category": "EdTech & Competitive Programming",
        "is_sovereign": False
    },
    "coursera": {
        "canonical_name": "Coursera, Inc.",
        "official_domains": ["coursera.org"],
        "category": "Higher Education & Certification",
        "is_sovereign": False
    },
    "kaggle": {
        "canonical_name": "Kaggle (Google LLC)",
        "official_domains": ["kaggle.com"],
        "category": "Data Science & AI Competitions",
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
    "myntra": {
        "canonical_name": "Myntra Designs Private Limited",
        "official_domains": ["myntra.com"],
        "category": "E-Commerce (India)",
        "is_sovereign": False
    },
    "airtel": {
        "canonical_name": "Bharti Airtel Limited",
        "official_domains": ["airtel.in", "airtel.com"],
        "category": "Telecommunications & Digital Services",
        "is_sovereign": False
    },
    "jio": {
        "canonical_name": "Reliance Jio Infocomm Limited",
        "official_domains": ["jio.com"],
        "category": "Telecommunications & Digital Services",
        "is_sovereign": False
    },
    "tcs": {
        "canonical_name": "Tata Consultancy Services (TCS)",
        "official_domains": ["tcs.com"],
        "category": "Enterprise Technology & IT Consulting",
        "is_sovereign": False
    },
    "infosys": {
        "canonical_name": "Infosys Limited",
        "official_domains": ["infosys.com"],
        "category": "Enterprise Technology & IT Consulting",
        "is_sovereign": False
    },
    "wipro": {
        "canonical_name": "Wipro Limited",
        "official_domains": ["wipro.com"],
        "category": "Enterprise Technology & IT Consulting",
        "is_sovereign": False
    },
    "bhim": {
        "canonical_name": "BHIM UPI (NPCI)",
        "official_domains": ["bhimupi.org.in"],
        "category": "Payment Infrastructure (India)",
        "is_sovereign": True
    },
    "gitlab": {
        "canonical_name": "GitLab Inc.",
        "official_domains": ["gitlab.com"],
        "category": "Developer Tools & Cloud",
        "is_sovereign": False
    },
    "anthropic": {
        "canonical_name": "Anthropic PBC (Claude)",
        "official_domains": ["anthropic.com", "claude.ai"],
        "category": "Artificial Intelligence",
        "is_sovereign": False
    }
}

# Sovereign Government Keywords requiring official government TLDs (.gov.in, .gov, .mil, .nic.in)
SOVEREIGN_GOV_KEYWORDS = {
    "drdo", "isro", "uidai", "aadhaar", "incometax", "epfo", "rbi", "sebi",
    "npci", "irctc", "parivahan", "passport", "cbse", "upsc", "ssc", "police",
    "defense", "defence", "army", "navy", "airforce", "cbi", "nia", "aiims",
    "iit", "nit", "iim", "ministry", "rajbhavan", "judiciary", "highcourt", "bhim"
}

AUTHORIZED_SOVEREIGN_TLDS = {
    ".gov.in", ".nic.in", ".gov", ".mil", ".org.in", ".ac.in", ".edu.in", ".res.in", ".bank.in"
}


class BrandVerifier:
    """Enterprise brand authentication and official authority registry engine."""

    @staticmethod
    def authenticate_brand_candidate(brand_name: str, domain: str) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Validates if a candidate domain is the authentic official domain for a brand.
        Returns: (is_authenticated, error_reason, verified_metadata)
        """
        b_key = brand_name.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
        clean_domain = domain.strip().lower()

        ext = tldextract.extract(clean_domain)
        if not ext.domain or not ext.suffix:
            return False, f"Invalid domain syntax '{clean_domain}'. Must be a valid Fully Qualified Domain Name.", None

        tld_dot = f".{ext.suffix}".lower()
        candidate_root = f"{ext.domain}.{ext.suffix}".lower()

        # 1. Check against Authoritative Registry if known
        if b_key in OFFICIAL_AUTHORITY_REGISTRY:
            reg_entry = OFFICIAL_AUTHORITY_REGISTRY[b_key]
            official_domains = [d.lower() for d in reg_entry["official_domains"]]
            
            # Check if candidate matches any official domain or subdomain
            is_match = any(
                candidate_root == off_d or candidate_root.endswith(f".{off_d}") or clean_domain == off_d or clean_domain.endswith(f".{off_d}")
                for off_d in official_domains
            )

            if not is_match:
                canonical = reg_entry["canonical_name"]
                return (
                    False,
                    f"Registration Blocked: Brand Authentication Failed: '{clean_domain}' is NOT the official domain for '{canonical}'. "
                    f"Authorized official domain(s): {', '.join(official_domains)}. Commercial / lookalike domain rejected.",
                    None
                )

            return True, None, reg_entry

        # 2. Sovereign / Government Entity TLD Enforcement
        is_sovereign_intent = (
            b_key in SOVEREIGN_GOV_KEYWORDS or
            any(kw in b_key for kw in ["drdo", "isro", "gov", "police", "aadhaar", "ministry", "tax", "defense", "defence", "army", "navy"]) or
            any(kw in ext.domain for kw in ["drdo", "isro", "uidai", "epfo", "parivahan", "passportindia", "defense", "defence", "police"])
        )

        if is_sovereign_intent:
            if tld_dot not in AUTHORIZED_SOVEREIGN_TLDS:
                return (
                    False,
                    f"Registration Blocked: Sovereign Brand Security Violation: '{brand_name.upper()}' is recognized as a Government / Defense entity. "
                    f"Government portals require authorized sovereign TLDs (.gov.in / .gov / .nic.in). "
                    f"Unofficial commercial domain '{clean_domain}' with TLD '{tld_dot}' is strictly rejected.",
                    None
                )

        # 3. New Generic Enterprise Brand Registration
        inferred_cat = BrandVerifier.infer_category(brand_name, clean_domain)
        return True, None, {
            "canonical_name": brand_name.title(),
            "official_domains": [candidate_root],
            "category": inferred_cat,
            "is_sovereign": False
        }

    @staticmethod
    def infer_category(brand_name: str, domain: str) -> str:
        """Dynamically infers accurate category/description based on domain and brand name."""
        b_lower = brand_name.lower()
        d_lower = domain.lower()
        ext = tldextract.extract(d_lower)
        tld = f".{ext.suffix}".lower()

        # Check lookup first
        q = b_lower.replace(" ", "").replace("-", "").replace("_", "")
        if q in OFFICIAL_AUTHORITY_REGISTRY:
            return OFFICIAL_AUTHORITY_REGISTRY[q]["category"]

        # Sovereign TLDs
        if tld in [".gov.in", ".gov", ".nic.in", ".mil"]:
            return "Government & Defense (India)"
        if tld in [".ac.in", ".edu.in", ".edu"]:
            return "Higher Education & Academic Institution"

        # Domain / Keyword Semantics
        if any(w in b_lower or w in d_lower for w in ["bank", "sbi", "hdfc", "icici", "pnb", "axis", "kotak"]):
            return "Banking/Financial (India)"
        if any(w in b_lower or w in d_lower for w in ["pay", "wallet", "upi", "fintech", "stripe", "crypto", "binance", "coin", "broking", "trade"]):
            return "Payment Gateway (India)"
        if any(w in b_lower or w in d_lower for w in ["code", "learn", "course", "study", "compete", "unstop", "hack", "contest", "exam", "quiz", "academy", "leetcode", "kaggle"]):
            return "Education & Competitions"
        if any(w in b_lower or w in d_lower for w in ["git", "dev", "api", "cloud", "host", "stack", "docker", "server", "github", "gitlab"]):
            return "Developer Tools & Cloud"
        if any(w in b_lower or w in d_lower for w in ["shop", "store", "mart", "cart", "retail", "buy", "deal", "market", "flipkart", "amazon", "myntra"]):
            return "E-Commerce (India)"
        if any(w in b_lower or w in d_lower for w in ["social", "chat", "connect", "network", "tweet", "post", "link", "linkedin", "twitter", "meta", "facebook"]):
            return "Professional Networking"
        if any(w in b_lower or w in d_lower for w in ["stream", "music", "tv", "movie", "video", "play", "game", "media", "cast", "netflix", "spotify"]):
            return "Digital Music & Media"
        if any(w in b_lower or w in d_lower for w in ["hotel", "travel", "flight", "tour", "stay", "cab", "ride", "room", "airbnb", "uber", "ola", "irctc"]):
            return "Travel & Hospitality"
        if any(w in b_lower or w in d_lower for w in ["food", "eat", "dine", "kitchen", "delivery", "meal", "swiggy", "zomato"]):
            return "Food Delivery & Tech"
        if any(w in b_lower or w in d_lower for w in ["ai", "gpt", "bot", "neural", "intel", "model", "openai", "anthropic"]):
            return "Artificial Intelligence"

        return "Enterprise & Cloud Services"

    @staticmethod
    def lookup_brand(query: str) -> Optional[Dict[str, Any]]:
        """
        Intelligent bi-directional brand lookup.
        Supports: brand keyword, URL, domain, typo tolerance, alias mapping, and dynamic inference.
        """
        raw_q = query.strip().lower()
        if not raw_q or len(raw_q) < 2:
            return None

        # Clean URL if user typed or pasted domain/URL
        if "://" in raw_q or "/" in raw_q or "." in raw_q:
            clean_q = raw_q.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            if clean_q.startswith("www."):
                clean_q = clean_q[4:]
            ext = tldextract.extract(clean_q)
            q_name = ext.domain.lower() if ext.domain else clean_q
        else:
            clean_q = raw_q
            q_name = raw_q.replace(" ", "").replace("-", "").replace("_", "")

        # Common Alias & Typo Map
        alias_map = {
            "swiigie": "swiggy", "swiggi": "swiggy", "swigy": "swiggy", "swiggie": "swiggy", "swi": "swiggy", "swig": "swiggy",
            "ubercabs": "uber", "ubr": "uber", "ube": "uber",
            "olacabs": "ola",
            "zomat": "zomato", "zoma": "zomato",
            "pay": "paytm", "paypal": "paypal", "phonepe": "phonepe",
            "twit": "twitter", "tweet": "twitter", "x": "twitter",
            "leet": "leetcode", "leetc": "leetcode",
            "git": "github", "gith": "github",
            "link": "linkedin", "linked": "linkedin",
            "micro": "microsoft", "msft": "microsoft", "office": "microsoft",
            "amaz": "amazon", "amzn": "amazon", "prime": "amazon",
            "air": "airbnb", "airb": "airbnb",
            "spot": "spotify", "spoti": "spotify",
            "drd": "drdo", "isr": "isro", "aadhaar": "uidai", "aadhar": "uidai",
            "tax": "incometax", "itr": "incometax",
            "train": "irctc", "railway": "irctc",
            "unst": "unstop", "unsto": "unstop"
        }
        if q_name in alias_map:
            q_name = alias_map[q_name]

        # 1. Exact Key Match in Registry
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

        # 2. Domain / Subdomain Match in Registry
        for k, data in OFFICIAL_AUTHORITY_REGISTRY.items():
            if any(clean_q == off_d or clean_q.endswith(f".{off_d}") or off_d.startswith(clean_q) for off_d in data["official_domains"]):
                return {
                    "brand_name": k,
                    "canonical_name": data["canonical_name"],
                    "official_domain": data["official_domains"][0],
                    "official_domains": data["official_domains"],
                    "category": data["category"],
                    "is_sovereign": data["is_sovereign"],
                    "verified": True
                }

        # 3. Fuzzy / Prefix / Substring Match in Registry
        for k, data in OFFICIAL_AUTHORITY_REGISTRY.items():
            if k.startswith(q_name) or q_name.startswith(k) or q_name in data["canonical_name"].lower():
                return {
                    "brand_name": k,
                    "canonical_name": data["canonical_name"],
                    "official_domain": data["official_domains"][0],
                    "official_domains": data["official_domains"],
                    "category": data["category"],
                    "is_sovereign": data["is_sovereign"],
                    "verified": True
                }

        # 4. Dynamic Auto-Detection for custom brand/domain
        inferred_cat = BrandVerifier.infer_category(q_name, clean_q if "." in clean_q else f"{q_name}.com")
        suggested_dom = clean_q if "." in clean_q else f"{q_name}.com"
        return {
            "brand_name": q_name,
            "canonical_name": q_name.title(),
            "official_domain": suggested_dom,
            "official_domains": [suggested_dom],
            "category": inferred_cat,
            "is_sovereign": False,
            "verified": False
        }
