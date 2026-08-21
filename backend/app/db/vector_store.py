import json
import os
import math
from typing import List, Dict, Tuple, Optional, Any
from app.core.config import settings
from app.core.logging import logger

class VectorStore:
    def __init__(self, filename: str = "brand_signatures.json"):
        self.filepath = os.path.join(settings.BRANDS_DIR, filename)
        self.brands: Dict[str, dict] = {}
        self.load()

    def load(self):
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    self.brands = json.load(f)
                logger.info(f"Loaded {len(self.brands)} brand profiles from {self.filepath}")
            except Exception as e:
                logger.error(f"Error loading brand signatures: {e}")
                self.brands = {}
        else:
            self.brands = {}

    def save(self):
        try:
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump(self.brands, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving brand signatures: {e}")

    def add_brand(
        self,
        brand_name: str,
        official_domains: List[str],
        category: str = "Banking/Financial",
        phash: Optional[str] = None,
        feature_vector: Optional[List[float]] = None,
        dom_signature: Optional[Dict[str, Any]] = None,
        keywords: Optional[List[str]] = None,
        overwrite: bool = False
    ):
        clean_name = brand_name.lower().strip()
        cleaned_domains = [d.lower().strip() for d in official_domains if d.strip()]
        
        if not overwrite and clean_name in self.brands:
            existing = self.brands[clean_name]
            # Merge domains without duplicates
            merged_domains = list(dict.fromkeys(existing.get("official_domains", []) + cleaned_domains))
            merged_keywords = list(dict.fromkeys(existing.get("keywords", []) + (keywords or [clean_name])))
            
            self.brands[clean_name] = {
                "brand_name": clean_name,
                "official_domains": merged_domains,
                "category": category or existing.get("category") or "Enterprise & Cloud Services",
                "phash": phash if phash else existing.get("phash"),
                "feature_vector": feature_vector if (feature_vector and len(feature_vector) > 0) else existing.get("feature_vector", []),
                "dom_signature": dom_signature if dom_signature else existing.get("dom_signature", {}),
                "keywords": merged_keywords
            }
        else:
            self.brands[clean_name] = {
                "brand_name": clean_name,
                "official_domains": cleaned_domains,
                "category": category or "Enterprise & Cloud Services",
                "phash": phash,
                "feature_vector": feature_vector or [],
                "dom_signature": dom_signature or {},
                "keywords": keywords or [clean_name]
            }
        self.save()

    def is_domain_already_registered(self, domain: str) -> Optional[str]:
        """Returns the brand name if the domain is already registered, else None"""
        clean_dom = domain.lower().strip()
        all_official = self.get_all_official_domains()
        for off_dom, brand in all_official.items():
            if clean_dom == off_dom:
                return brand
        return None

    def get_all_brands(self) -> Dict[str, dict]:
        return self.brands

    def get_brand(self, brand_name: str) -> Optional[dict]:
        return self.brands.get(brand_name.lower().strip())

    def get_all_official_domains(self) -> Dict[str, str]:
        """Returns mapping of official_domain -> brand_name"""
        mapping = {}
        for brand, data in self.brands.items():
            for dom in data.get("official_domains", []):
                mapping[dom] = brand
        return mapping

    @staticmethod
    def hamming_distance(hash1: str, hash2: str) -> int:
        if not hash1 or not hash2 or len(hash1) != len(hash2):
            return 64
        return sum(c1 != c2 for c1, c2 in zip(hash1, hash2))

    @staticmethod
    def cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
        if not vec1 or not vec2 or len(vec1) != len(vec2):
            return 0.0
        dot = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = math.sqrt(sum(a * a for a in vec1))
        norm2 = math.sqrt(sum(b * b for b in vec2))
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return max(0.0, min(1.0, dot / (norm1 * norm2)))

    def match_visual(self, query_phash: Optional[str], query_vector: Optional[List[float]]) -> Tuple[Optional[str], float, Optional[dict]]:
        """
        Calculates dual-stage visual similarity:
        1. Cosine similarity of feature vector (weight 0.65)
        2. Perceptual Hash inverse hamming distance (weight 0.35)
        """
        best_brand = None
        best_similarity = 0.0
        best_brand_data = None

        for brand_name, data in self.brands.items():
            brand_vec = data.get("feature_vector")
            brand_phash = data.get("phash")

            vec_sim = 0.0
            if query_vector and brand_vec and len(query_vector) == len(brand_vec):
                vec_sim = self.cosine_similarity(query_vector, brand_vec)

            hash_sim = 0.0
            if query_phash and brand_phash:
                h_dist = self.hamming_distance(query_phash, brand_phash)
                hash_sim = max(0.0, 1.0 - (h_dist / 20.0))

            if query_vector and query_phash:
                if vec_sim >= 0.999:
                    combined_sim = vec_sim
                else:
                    combined_sim = (vec_sim * 0.85) + (hash_sim * 0.15)
            elif query_vector:
                combined_sim = vec_sim
            elif query_phash:
                combined_sim = hash_sim
            else:
                combined_sim = 0.0

            if combined_sim > best_similarity:
                best_similarity = combined_sim
                best_brand = brand_name
                best_brand_data = data

        return best_brand, round(best_similarity, 4), best_brand_data
