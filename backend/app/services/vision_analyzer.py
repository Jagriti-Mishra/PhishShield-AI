import os
import math
from PIL import Image
import numpy as np

try:
    import torch
    import torchvision.models as models
    import torchvision.transforms as transforms
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

try:
    from skimage.metrics import structural_similarity as ssim
    SSIM_AVAILABLE = True
except ImportError:
    SSIM_AVAILABLE = False

from app.db.vector_store import VectorStore

class VisionAnalyzer:
    def __init__(self, vector_store: VectorStore):
        self.vector_store = vector_store
        self.model = None
        self.transform = None
        self._init_model()

    def _init_model(self):
        if TORCH_AVAILABLE:
            try:
                # Load pre-trained MobileNetV3 / ResNet18 feature extractor
                weights = models.ResNet18_Weights.DEFAULT
                self.model = models.resnet18(weights=weights)
                self.model.fc = torch.nn.Identity() # Remove classification head -> 512 embedding
                self.model.eval()

                self.transform = transforms.Compose([
                    transforms.Resize((224, 224)),
                    transforms.ToTensor(),
                    transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
                ])
            except Exception:
                self.model = None

    def extract_embedding(self, image_path: str) -> list:
        if not os.path.exists(image_path):
            return [0.0] * 512

        try:
            image = Image.open(image_path).convert("RGB")
            if TORCH_AVAILABLE and self.model and self.transform:
                tensor = self.transform(image).unsqueeze(0)
                with torch.no_grad():
                    embedding = self.model(tensor).squeeze(0).numpy().tolist()
                return embedding
            else:
                # Fallback histogram feature extraction if PyTorch not active
                resized = image.resize((64, 64))
                arr = np.array(resized, dtype=np.float32) / 255.0
                hist, _ = np.histogram(arr, bins=512, range=(0.0, 1.0))
                norm = np.linalg.norm(hist)
                return (hist / (norm if norm > 0 else 1.0)).tolist()
        except Exception:
            return [0.0] * 512

    def analyze(self, image_path: str, current_domain: str) -> dict:
        if not image_path or not os.path.exists(image_path):
            return {
                "score": 0.0,
                "visual_similarity": 0.0,
                "matched_brand": None,
                "official_domain": None,
                "is_clone": False,
                "reasons": ["No screenshot captured for visual analysis"]
            }

        embedding = self.extract_embedding(image_path)
        matched_brand, sim, official_domain = self.vector_store.find_most_similar(embedding)

        is_clone = False
        score = 0.0
        reasons = []

        if matched_brand and sim >= 0.70:
            # Check domain mismatch
            domain_clean = current_domain.lower().replace("www.", "")
            official_clean = (official_domain or "").lower().replace("www.", "")

            if domain_clean != official_clean and not domain_clean.endswith(f".{official_clean}"):
                is_clone = True
                # Scale similarity to score
                score = round(sim * 100.0, 2)
                reasons.append(f"Visual clone detected! Page layout matches brand '{matched_brand}' ({round(sim * 100, 1)}% visual match) but hosted on unauthorized domain '{current_domain}'")

        return {
            "score": round(score, 2),
            "visual_similarity": sim,
            "matched_brand": matched_brand if is_clone else None,
            "official_domain": official_domain if is_clone else None,
            "is_clone": is_clone,
            "reasons": reasons
        }
