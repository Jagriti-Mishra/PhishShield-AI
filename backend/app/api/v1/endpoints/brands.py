import tldextract
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from PIL import Image

from app.schemas.brand import BrandRegisterRequest, BrandResponse
from app.db.session import get_db
from app.db.repository import BrandRepository
from app.db.vector_store import VectorStore
from app.services.crawler import StealthCrawler
from app.services.vision_analyzer import VisionAnalyzer
from app.services.url_analyzer import SUSPICIOUS_TLDS, URLAnalyzer
from app.services.brand_verifier import BrandVerifier

router = APIRouter()
vector_store = VectorStore()
crawler = StealthCrawler()
vision_analyzer = VisionAnalyzer(vector_store)
url_analyzer = URLAnalyzer(vector_store)

PHISHING_COMBOSQUAT_KEYWORDS = {
    "kyc", "update", "verify", "verification", "login", "signin",
    "secure", "security", "banking", "online", "portal", "support",
    "account", "wallet", "recover", "authenticate", "alert",
    "reward", "rewards", "point", "points", "claim", "claims",
    "refund", "refunds", "renew", "renewal", "subscription",
    "bonus", "offer", "cashback", "redeem", "subsidy", "gift",
    "promo", "discount", "gov", "tax", "lottery", "bill", "pay"
}

@router.get("/brands")
def list_brands():
    brands_data = vector_store.get_all_brands()
    output = []
    for k, v in brands_data.items():
        output.append({
            "brand_name": k,
            "official_domains": v.get("official_domains", []),
            "category": v.get("category", "General"),
            "phash": v.get("phash"),
            "vector_dim": len(v.get("feature_vector", []))
        })
    return {"count": len(output), "brands": output}

@router.get("/brands/lookup")
def lookup_brand(query: str):
    res = BrandVerifier.lookup_brand(query)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No preloaded authority entry for '{query}'. You can index custom enterprise domains directly."
        )
    return res

@router.post("/brands/add")
def register_brand(req: BrandRegisterRequest, db: Session = Depends(get_db)):
    brand_clean = req.brand_name.strip().lower()
    # Clean input: Extract FQDN even if user pastes full URL (e.g. https://unstop.com/practice/...)
    raw_domain = req.official_domain.strip().lower()
    if "://" in raw_domain:
        parsed_u = urlparse(raw_domain)
        domain_clean = parsed_u.netloc.split(":")[0].strip().lower()
    else:
        domain_clean = raw_domain.split("/")[0].split(":")[0].strip().lower()
    
    if domain_clean.startswith("www."):
        domain_clean = domain_clean[4:]

    if not brand_clean or not domain_clean:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Brand Name and Official Domain are required."
        )

    # ------------------------------------------------------------------------
    # Guard 0: Authoritative Brand & Sovereign Government Verification
    # ------------------------------------------------------------------------
    is_auth, auth_err, auth_meta = BrandVerifier.authenticate_brand_candidate(req.brand_name, domain_clean)
    if not is_auth:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=auth_err
        )
    
    cat = req.category if req.category and req.category != "General" else (auth_meta.get("category") if auth_meta else "Enterprise & Cloud Services")

    # ------------------------------------------------------------------------
    # Guard 1: Domain Syntax & Combosquatting / Typosquat Screening
    # ------------------------------------------------------------------------
    ext = tldextract.extract(domain_clean)
    if not ext.domain or not ext.suffix:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid domain syntax '{domain_clean}'. Must be a valid FQDN."
        )

    tld_dot = f".{ext.suffix}".lower()
    candidate_root = f"{ext.domain}.{ext.suffix}".lower()

    # Detect homoglyphs
    has_homoglyphs, norm_domain = URLAnalyzer.detect_homoglyphs(domain_clean)
    if has_homoglyphs:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Registration Blocked: Homoglyphs/confusable Unicode characters detected in '{domain_clean}'."
        )

    # Combosquatting detection: hyphenated phishing keywords or embedding protected foreign brand names
    domain_tokens = set(domain_clean.replace(".", "-").split("-"))
    has_phish_keyword = bool(domain_tokens.intersection(PHISHING_COMBOSQUAT_KEYWORDS))
    is_suspicious_tld = tld_dot in SUSPICIOUS_TLDS

    sld_parts = ext.domain.split("-")
    has_hyphen_combosquat = len(sld_parts) >= 2 and any(p in PHISHING_COMBOSQUAT_KEYWORDS for p in sld_parts)

    all_existing_brands = vector_store.get_all_brands()
    embeds_foreign_brand = any(
        b_k in ext.domain and b_k != brand_clean and b_k != ext.domain
        for b_k in all_existing_brands.keys()
    )

    if (is_suspicious_tld and (has_phish_keyword or embeds_foreign_brand)) or (has_hyphen_combosquat and (is_suspicious_tld or embeds_foreign_brand)):
        matched_kws = list(domain_tokens.intersection(PHISHING_COMBOSQUAT_KEYWORDS))
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Registration Blocked: Domain '{domain_clean}' exhibits suspicious combosquatting/phishing structure "
                f"(TLD '{tld_dot}', Trigger Tokens: {matched_kws or list(domain_tokens)}). "
                f"Phishing/lookalike domains cannot be registered as authorized brands."
            )
        )

    # ------------------------------------------------------------------------
    # Guard 2: Root-Domain Heritage Guard for Existing Brands
    # ------------------------------------------------------------------------
    existing_brand_profile = vector_store.get_brand(brand_clean)
    if existing_brand_profile:
        existing_official_domains = existing_brand_profile.get("official_domains", [])
        if existing_official_domains:
            # Extract allowed root domains for this brand
            allowed_roots = set()
            for off_d in existing_official_domains:
                off_ext = tldextract.extract(off_d)
                if off_ext.domain and off_ext.suffix:
                    allowed_roots.add(f"{off_ext.domain}.{off_ext.suffix}".lower())

            # If candidate domain belongs to a completely different root domain
            if candidate_root not in allowed_roots:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"Registration Blocked: Root Domain Mismatch! Domain '{domain_clean}' (root: '{candidate_root}') "
                        f"does not match verified root domain(s) for protected brand '{brand_clean.upper()}': {list(allowed_roots)}. "
                        f"Rogue domain injection into existing brand profile rejected."
                    )
                )

    # ------------------------------------------------------------------------
    # Guard 3: Cross-Brand Domain Collision Guard
    # ------------------------------------------------------------------------
    existing_brand_for_domain = vector_store.is_domain_already_registered(domain_clean)
    if existing_brand_for_domain and existing_brand_for_domain != brand_clean:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Registration Conflict: Domain '{domain_clean}' is already registered under brand '{existing_brand_for_domain}'."
        )

    # ------------------------------------------------------------------------
    # Guard 4: Signature Extraction, Indexing & Persistence
    # ------------------------------------------------------------------------
    screenshot_path, _, _ = crawler.capture(f"https://{domain_clean}")
    
    phash = None
    vec = []
    try:
        if screenshot_path:
            img = Image.open(screenshot_path)
            phash = vision_analyzer.compute_phash(img)
            vec = vision_analyzer.extract_feature_vector(img)
    except Exception:
        pass

    # Index into VectorStore
    vector_store.add_brand(
        brand_name=brand_clean,
        official_domains=[domain_clean],
        category=cat,
        phash=phash,
        feature_vector=vec,
        keywords=[brand_clean, domain_clean],
        overwrite=False
    )

    # Persist in Database
    brand_repo = BrandRepository(db)
    brand_repo.upsert_brand({
        "brand_name": brand_clean,
        "official_domain": domain_clean,
        "category": cat,
        "phash": phash,
        "feature_vector": vec,
        "logo_url": req.logo_url
    })

    return {
        "message": f"Brand '{brand_clean}' ({domain_clean}) successfully registered and indexed into Multimodal VectorStore.",
        "brand_name": brand_clean,
        "official_domain": domain_clean,
        "vector_dimensions": len(vec) if vec else 128
    }
