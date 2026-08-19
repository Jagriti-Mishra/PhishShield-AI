import json
import os
import math
from typing import List, Dict, Optional

class VectorStore:
    def __init__(self, storage_file: str = "brand_vectors.json"):
        self.storage_path = os.path.join(os.path.dirname(__file__), storage_file)
        self.brands: Dict[str, dict] = {}
        self.load()

    def load(self):
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    self.brands = json.load(f)
            except Exception:
                self.brands = {}

    def save(self):
        with open(self.storage_path, "w", encoding="utf-8") as f:
            json.dump(self.brands, f, indent=2)

    def add_brand(self, brand_name: str, official_domain: str, vector: List[float], metadata: dict = None):
        self.brands[brand_name] = {
            "brand_name": brand_name,
            "official_domain": official_domain,
            "vector": vector,
            "metadata": metadata or {}
        }
        self.save()

    def cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        if not vec1 or not vec2 or len(vec1) != len(vec2):
            return 0.0
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = math.sqrt(sum(a * a for a in vec1))
        norm2 = math.sqrt(sum(b * b for b in vec2))
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return dot_product / (norm1 * norm2)

    def find_most_similar(self, query_vector: List[float]) -> tuple[Optional[str], float, Optional[str]]:
        best_brand = None
        best_sim = 0.0
        best_domain = None

        for brand_name, data in self.brands.items():
            sim = self.cosine_similarity(query_vector, data["vector"])
            if sim > best_sim:
                best_sim = sim
                best_brand = brand_name
                best_domain = data["official_domain"]

        return best_brand, round(best_sim, 4), best_domain
