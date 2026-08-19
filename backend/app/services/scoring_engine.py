from app.config import settings

class ScoringEngine:
    def compute(self, url_res: dict, vision_res: dict, dom_res: dict, meta_res: dict) -> dict:
        # 1. If domain is verified as an official brand domain or legitimate subdomain -> Instantly SAFE
        if url_res.get("is_official"):
            return {
                "overall_score": 0.0,
                "risk_level": "SAFE",
                "badge_color": "#10B981", # Green
                "action_recommendation": f"Official verified domain ({url_res.get('netloc')}) for brand '{url_res.get('target_brand_matched')}'. Website is legitimate.",
                "breakdown": {
                    "vision": {"score": 0.0, "weight": settings.WEIGHT_VISION},
                    "dom": {"score": 0.0, "weight": settings.WEIGHT_DOM},
                    "url": {"score": 0.0, "weight": settings.WEIGHT_URL},
                    "metadata": {"score": 0.0, "weight": settings.WEIGHT_METADATA}
                },
                "explainable_reasons": []
            }

        w_vision = settings.WEIGHT_VISION
        w_dom = settings.WEIGHT_DOM
        w_url = settings.WEIGHT_URL
        w_meta = settings.WEIGHT_METADATA

        v_score = vision_res.get("score", 0.0)
        d_score = dom_res.get("score", 0.0)
        u_score = url_res.get("score", 0.0)
        m_score = meta_res.get("score", 0.0)

        # Calculate weighted overall score
        overall_score = (v_score * w_vision) + (d_score * w_dom) + (u_score * w_url) + (m_score * w_meta)

        # Critical Overrides (Red Badge: >= 70%)
        if vision_res.get("is_clone"):
            overall_score = max(overall_score, 98.0)
        if url_res.get("typosquatting_detected"):
            overall_score = max(overall_score, 94.0)
        if url_res.get("homoglyph_detected"):
            overall_score = max(overall_score, 96.0)
        if dom_res.get("insecure_password_post"):
            overall_score = max(overall_score, 92.0)
        if u_score >= 80.0:
            overall_score = max(overall_score, 94.0)
        elif u_score >= 60.0:
            overall_score = max(overall_score, 88.0)

        # Medium Risk Overrides (Yellow Badge: 35% - 69%)
        if not meta_res.get("is_https"):
            overall_score = max(overall_score, 45.0)
        elif m_score >= 35.0:
            overall_score = max(overall_score, 40.0)

        overall_score = min(100.0, round(overall_score, 2))

        # Risk Classification
        if overall_score >= settings.HIGH_RISK_THRESHOLD:
            risk_level = "CRITICAL PHISHING"
            badge_color = "#EF4444" # Red
            action = "BLOCK ACCESS IMMEDIATELY. High-probability phishing domain impersonating legitimate brand."
        elif overall_score >= settings.MEDIUM_RISK_THRESHOLD:
            risk_level = "SUSPICIOUS"
            badge_color = "#F59E0B" # Yellow/Amber
            action = "PROCEED WITH EXTREME CAUTION. Suspicious URL parameters and unverified encryption headers detected."
        else:
            risk_level = "SAFE"
            badge_color = "#10B981" # Green
            action = "Website verified. No significant phishing anomalies detected."

        # Consolidate Explainable Reasons
        all_reasons = []
        all_reasons.extend(vision_res.get("reasons", []))
        all_reasons.extend(dom_res.get("reasons", []))
        all_reasons.extend(url_res.get("reasons", []))
        all_reasons.extend(meta_res.get("reasons", []))

        return {
            "overall_score": overall_score,
            "risk_level": risk_level,
            "badge_color": badge_color,
            "action_recommendation": action,
            "breakdown": {
                "vision": {"score": v_score, "weight": w_vision},
                "dom": {"score": d_score, "weight": w_dom},
                "url": {"score": u_score, "weight": w_url},
                "metadata": {"score": m_score, "weight": w_meta}
            },
            "explainable_reasons": all_reasons
        }
