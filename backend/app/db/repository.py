from typing import List, Optional, Dict
from sqlalchemy.orm import Session
from app.db.models import ScanRecord, MonitoredBrand, NRDRecord

class ScanRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, scan_data: dict) -> ScanRecord:
        record = ScanRecord(**scan_data)
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)
        return record

    def get_recent(self, limit: int = 50) -> List[ScanRecord]:
        return self.db.query(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(limit).all()

    def get_by_id(self, scan_id: str) -> Optional[ScanRecord]:
        return self.db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()

    def count_total(self) -> int:
        return self.db.query(ScanRecord).count()

    def count_phishing(self) -> int:
        return self.db.query(ScanRecord).filter(ScanRecord.risk_level.in_(["CRITICAL PHISHING", "HIGH PHISHING"])).count()

class BrandRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_all_active(self) -> List[MonitoredBrand]:
        return self.db.query(MonitoredBrand).filter(MonitoredBrand.is_active == True).all()

    def get_by_name(self, name: str) -> Optional[MonitoredBrand]:
        return self.db.query(MonitoredBrand).filter(MonitoredBrand.brand_name == name.lower()).first()

    def upsert_brand(self, brand_data: dict) -> MonitoredBrand:
        brand_name = brand_data["brand_name"].lower()
        existing = self.get_by_name(brand_name)
        if existing:
            for k, v in brand_data.items():
                setattr(existing, k, v)
            self.db.commit()
            self.db.refresh(existing)
            return existing
        else:
            new_brand = MonitoredBrand(**brand_data)
            self.db.add(new_brand)
            self.db.commit()
            self.db.refresh(new_brand)
            return new_brand

class NRDRepository:
    def __init__(self, db: Session):
        self.db = db

    def add_nrd_domain(self, domain: str, registrar: str = None, reg_date=None, source="WHOIS_NRD") -> Optional[NRDRecord]:
        clean_domain = domain.strip().lower()
        existing = self.db.query(NRDRecord).filter(NRDRecord.domain == clean_domain).first()
        if existing:
            return existing
        rec = NRDRecord(
            domain=clean_domain,
            registrar=registrar,
            registration_date=reg_date,
            source_feed=source,
            status="PENDING"
        )
        self.db.add(rec)
        self.db.commit()
        self.db.refresh(rec)
        return rec

    def get_pending(self, limit: int = 50) -> List[NRDRecord]:
        return self.db.query(NRDRecord).filter(NRDRecord.status == "PENDING").order_by(NRDRecord.created_at.desc()).limit(limit).all()

    def get_pending_count(self) -> int:
        return self.db.query(NRDRecord).filter(NRDRecord.status == "PENDING").count()

    def get_threats_count(self) -> int:
        return self.db.query(NRDRecord).filter(NRDRecord.status.in_(["CRITICAL PHISHING", "HIGH PHISHING", "SUSPICIOUS"])).count()

    def get_benign_count(self) -> int:
        return self.db.query(NRDRecord).filter(NRDRecord.status == "BENIGN").count()

    def update_status(self, domain: str, status: str, risk_score: float = None):
        clean_d = domain.strip().lower()
        rec = self.db.query(NRDRecord).filter(NRDRecord.domain == clean_d).first()
        if rec:
            rec.status = status
            if risk_score is not None:
                rec.risk_score = risk_score
            self.db.commit()

    def get_recent_scanned(self, limit: int = 200) -> List[NRDRecord]:
        return self.db.query(NRDRecord).order_by(NRDRecord.created_at.desc()).limit(limit).all()
