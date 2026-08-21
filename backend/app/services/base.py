from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

@dataclass
class AnalysisContext:
    raw_url: str
    normalized_url: str
    scheme: str
    domain: str
    subdomain: str
    suffix: str
    path: str
    html_content: str = ""
    screenshot_path: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    whois_data: Dict[str, Any] = field(default_factory=dict)
    is_official_brand: bool = False
    official_brand_name: Optional[str] = None

@dataclass
class AnalysisResult:
    engine_name: str
    score: float  # 0.0 to 100.0
    weight: float # 0.0 to 1.0
    reasons: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        """Executes domain-specific detection heuristics and returns AnalysisResult."""
        pass
