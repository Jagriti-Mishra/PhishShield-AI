import os
from typing import Optional, List, Dict, Any
from PIL import Image
import numpy as np

from app.services.base import BaseAnalyzer, AnalysisContext, AnalysisResult
from app.db.vector_store import VectorStore
from app.core.config import settings
from app.core.logging import logger

class VisionAnalyzer(BaseAnalyzer):
    def __init__(self, vector_store: VectorStore):
        self.vector_store = vector_store

    @staticmethod
    def compute_phash(image: Image.Image) -> str:
        """Computes a robust 64-bit Perceptual Difference Hash (dHash)."""
        try:
            img = image.convert("L").resize((9, 8), Image.Resampling.BILINEAR)
            pixels = np.asarray(img, dtype=np.float32)
            diff = pixels[:, 1:] > pixels[:, :-1]
            return "".join(["1" if b else "0" for b in diff.flatten()])
        except Exception as e:
            logger.error(f"Error computing pHash: {e}")
            return "0" * 64

    @staticmethod
    def extract_feature_vector(image: Image.Image) -> List[float]:
        """Extracts spatial color moments, header branding palette, and 3D RGB color histogram."""
        try:
            img_rgb = image.convert("RGB").resize((128, 128))
            arr = np.asarray(img_rgb, dtype=np.float32) / 255.0

            features = []
            # 1. 4x4 spatial grid color moments (48 means + 48 stds = 96 features)
            for row in range(4):
                for col in range(4):
                    cell = arr[row*32:(row+1)*32, col*32:(col+1)*32, :]
                    means = np.mean(cell, axis=(0, 1))
                    stds = np.std(cell, axis=(0, 1))
                    features.extend(means.tolist())
                    features.extend(stds.tolist())

            # 2. Header branding region mean (rows 5 to 45) -> 3 features
            header_mean = np.mean(arr[5:45, :, :], axis=(0, 1))
            features.extend(header_mean.tolist())

            # 3. 3D Color distribution (27 bins: 3x3x3)
            r_bin = np.clip(np.digitize(arr[:, :, 0], bins=[0.33, 0.66]), 0, 2)
            g_bin = np.clip(np.digitize(arr[:, :, 1], bins=[0.33, 0.66]), 0, 2)
            b_bin = np.clip(np.digitize(arr[:, :, 2], bins=[0.33, 0.66]), 0, 2)
            idx = (r_bin * 9 + g_bin * 3 + b_bin).flatten()
            hist = np.bincount(idx, minlength=27).astype(np.float32)
            hist = (hist / (np.sum(hist) + 1e-6)).tolist()
            features.extend(hist)

            # Pad or trim to exactly 128 dimensions
            if len(features) < 128:
                features.extend([0.0] * (128 - len(features)))
            features = features[:128]

            total_norm = np.linalg.norm(features)
            if total_norm > 0:
                features = (np.array(features) / total_norm).tolist()
            return features
        except Exception as e:
            logger.error(f"Error extracting visual feature vector: {e}")
            return [0.0] * 128

    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        if context.is_official_brand:
            return AnalysisResult(
                engine_name="VISION",
                score=0.0,
                weight=settings.WEIGHT_VISION,
                reasons=[f"Official visual layout verified for '{context.official_brand_name}'"],
                details={"is_clone": False, "matched_brand": context.official_brand_name, "visual_similarity": 1.0}
            )

        screenshot_path = context.screenshot_path
        if not screenshot_path or not os.path.exists(screenshot_path):
            return AnalysisResult(
                engine_name="VISION",
                score=0.0,
                weight=settings.WEIGHT_VISION,
                reasons=["No viewport screenshot available for visual feature extraction"],
                details={"is_clone": False, "visual_similarity": 0.0, "matched_brand": None}
            )

        try:
            image = Image.open(screenshot_path)
            query_phash = self.compute_phash(image)
            query_vector = self.extract_feature_vector(image)
        except Exception as e:
            logger.error(f"Failed to process screenshot {screenshot_path}: {e}")
            return AnalysisResult(
                engine_name="VISION",
                score=0.0,
                weight=settings.WEIGHT_VISION,
                reasons=[f"Visual image decoding error: {str(e)}"],
                details={"is_clone": False, "visual_similarity": 0.0}
            )

        matched_brand, sim, brand_data = self.vector_store.match_visual(query_phash, query_vector)

        is_clone = False
        score = 0.0
        reasons = []
        details = {
            "query_phash": query_phash[:16] + "...",
            "visual_similarity": sim,
            "matched_brand": None,
            "is_clone": False
        }

        # Check if similarity exceeds visual clone threshold
        if matched_brand and brand_data and sim >= settings.VISUAL_CLONE_THRESHOLD:
            brand_phash = brand_data.get("phash", "")
            h_dist = self.vector_store.hamming_distance(query_phash, brand_phash)

            # Legitimate clone matching requires congruent layout geometry (h_dist <= 8)
            if h_dist <= 8:
                official_domains = [d.lower() for d in brand_data.get("official_domains", [])]
                current_domain = context.domain.lower()

                # Check if current domain is authorized for this brand
                is_authorized = any(current_domain == od or current_domain.endswith(f".{od}") for od in official_domains)
                
                if not is_authorized:
                    is_clone = True
                    score = round(sim * 100.0, 2)
                    details["is_clone"] = True
                    details["matched_brand"] = matched_brand
                    details["official_domains"] = official_domains
                    reasons.append(
                        f"Visual Impersonation Detected! Viewport layout has a {round(sim * 100, 1)}% visual match with brand '{matched_brand.upper()}' ({brand_data.get('category')}), but is hosted on unauthorized domain '{current_domain}'"
                    )

        return AnalysisResult(
            engine_name="VISION",
            score=score,
            weight=settings.WEIGHT_VISION,
            reasons=reasons,
            details=details
        )
