import os
import sys
import uvicorn

# Ensure backend directory is in python path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "backend"))

if __name__ == "__main__":
    print("\n" + "="*70)
    print(" [START] STARTING PHISHSHIELD AI SERVER (SIH 1454) ")
    print("="*70)
    print(" [SOC Dashboard] http://127.0.0.1:8000/dashboard/index.html")
    print(" [OpenAPI Docs]  http://127.0.0.1:8000/docs")
    print(" [API Base URL]  http://127.0.0.1:8000/api/v1/health")
    print("="*70 + "\n")

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
