import os
import sys

# Ensure backend directory is in python path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "backend"))

if __name__ == "__main__":
    import uvicorn
    from app.core.config import settings
    from app.db.vector_store import VectorStore

    store = VectorStore()
    brand_count = len(store.get_all_brands())

    print("\n" + "="*75)
    print(" [START] PHISHSHIELD AI - PRODUCTION SOC OPERATIONS SERVER (SIH 1454) ")
    print("="*75)
    print(f" [Engine Mode]     Multimodal AI/ML (Vision + DOM + URL + WHOIS + NLP)")
    print(f" [Brand Profiles]  {brand_count} Ground-Truth Signatures Loaded")
    print(f" [SOC Dashboard]   http://127.0.0.1:8000/dashboard/index.html")
    print(f" [OpenAPI Swagger] http://127.0.0.1:8000/docs")
    print(f" [ReDoc API Docs]  http://127.0.0.1:8000/redoc")
    print(f" [Health Check]    http://127.0.0.1:8000/api/v1/health")
    print("="*75 + "\n")

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False)
