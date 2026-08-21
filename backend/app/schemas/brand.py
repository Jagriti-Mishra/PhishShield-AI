from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class BrandRegisterRequest(BaseModel):
    brand_name: str = Field(..., min_length=2, description="Target brand keyword (e.g. razorpay)")
    official_domain: str = Field(..., min_length=3, description="Legitimate primary domain (e.g. razorpay.com)")
    category: Optional[str] = Field(default=None, description="Industry vertical")
    logo_url: Optional[str] = None

class BrandResponse(BaseModel):
    id: Optional[str] = None
    brand_name: str
    official_domain: str
    category: str
    phash: Optional[str] = None
    vector_dim: int = 0
    is_active: bool = True
