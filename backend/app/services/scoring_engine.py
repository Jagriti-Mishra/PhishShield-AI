from app.config import settings

class ScoringEngine:
    def compute(self, url_res: dict, vision_res: dict, dom_res: dict, meta_res: dict) -> dict:
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

        # Critical Overrides: If visual clone or form post to raw IP with password occurs
        if vision_res.get("is_clone"):
            overall_score = max(overall_score, 88.0)
        if dom_res.get("insecure_password_post"):
            overall_score = max(overall_score, 82.0)
        if url_res.get("homoglyph_detected") and url_res.get("typosquatting_detected"):
            overall_score = max(overall_score, 78.0)

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
