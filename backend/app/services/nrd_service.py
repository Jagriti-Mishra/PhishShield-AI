import random
import time
import datetime
import uuid
from typing import List, Dict, Any

from app.db.repository import NRDRepository
from app.core.config import settings
from app.core.logging import logger

BRANDS_LIST = [
    "sbi", "hdfc", "icici", "paypal", "razorpay", "google", "microsoft",
    "amazon", "apple", "netflix", "incometax", "uidai", "phonepe", "paytm",
    "axisbank", "kotak", "meta", "binance", "coinbase"
]

PHISH_ACTIONS = [
    "kyc-verification", "reward-points", "instant-loan", "refund-portal",
    "secure-auth", "account-recovery", "prime-giftcard", "subscription-renew",
    "aadhaar-pan-link", "merchant-checkout", "security-alert", "wallet-recharge",
    "tax-settlement", "cashback-claim", "bonus-credit", "login-support",
    "e-filing-verify", "otp-authenticate", "quick-verify", "identity-portal"
]

PHISH_TLDS = [
    ".top", ".xyz", ".online", ".click", ".site", ".buzz", ".club",
    ".info", ".work", ".live", ".icu", ".cam", ".cfd", ".quest"
]

REGISTRARS = [
    "NameSilo LLC", "Tucows Domains", "Hostinger", "Namecheap", "Dynadot",
    "Freenom", "GoDaddy", "Porkbun", "Google LLC", "Cloudflare, Inc."
]

BENIGN_PREFIXES = [
    "green-energy-solar", "urban-coffee-roasters", "apex-tech-portfolio",
    "summit-fitness-gym", "creative-studio-design", "horizon-analytics",
    "pure-nature-organics", "dev-cloud-solutions", "blue-ocean-logistics",
    "quantum-code-labs", "stellar-health-care", "artisan-bakery-shop"
]

BENIGN_TLDS = [".com", ".org", ".io", ".net", ".co", ".app", ".dev", ".eco", ".agency"]

class NRDService:
    def __init__(self, nrd_repo: NRDRepository):
        self.repo = nrd_repo

    def ingest_sample_nrd_feed(self, count: int = 10) -> List[Dict[str, Any]]:
        """Dynamically generates and ingests a fresh stream of newly registered domains."""
        records = []
        now = datetime.datetime.utcnow()

        for _ in range(count):
            is_phish = random.random() < 0.75  # 75% suspicious lookalikes, 25% benign
            rand_suffix = random.randint(10, 999)

            if is_phish:
                brand = random.choice(BRANDS_LIST)
                action = random.choice(PHISH_ACTIONS)
                tld = random.choice(PHISH_TLDS)
                domain = f"{brand}-{action}-{rand_suffix}{tld}"
                registrar = random.choice(REGISTRARS[:6]) # Budget registrars
            else:
                prefix = random.choice(BENIGN_PREFIXES)
                tld = random.choice(BENIGN_TLDS)
                domain = f"{prefix}-{rand_suffix}{tld}"
                registrar = random.choice(REGISTRARS[4:])

            # Recent registration: 0 to 48 hours ago
            hours_ago = random.randint(0, 48)
            reg_date = now - datetime.timedelta(hours=hours_ago, minutes=random.randint(1, 59))

            rec = self.repo.add_nrd_domain(
                domain=domain,
                registrar=registrar,
                reg_date=reg_date,
                source="WHOIS_NRD_LIVE_FEED"
            )
            if rec:
                records.append({
                    "domain": rec.domain,
                    "registrar": rec.registrar,
                    "registration_date": rec.registration_date,
                    "status": rec.status,
                    "risk_score": rec.risk_score
                })

        logger.info(f"Ingested {len(records)} fresh newly registered domains into NRD triage queue")
        return records

    def get_pending_nrd_queue(self, limit: int = 50):
        return self.repo.get_pending(limit=limit)

    def get_all_scanned(self, limit: int = 100):
        return self.repo.get_recent_scanned(limit=limit)
