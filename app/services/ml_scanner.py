"""
ZeroPhish AI — ML Inference Module
Loads the trained ensemble pipeline and provides a predict() function.
Falls back gracefully to heuristic-only if the model file is missing.
"""
import re
import os
import logging
import numpy as np
# ── Import the shared feature extractor so joblib can unpickle the model ──────
# HeuristicFeatures must be importable from the same module path it was saved
# from during training. This import is the fix for the '__main__' pickle error.
from app.services.ml_features import HeuristicFeatures  # noqa: F401

logger = logging.getLogger(__name__)


# ── Paths ─────────────────────────────────────────────────────────────────────
_ML_DIR = os.path.join(os.path.dirname(__file__), "..", "ml")
_MODEL  = os.path.join(_ML_DIR, "model.pkl")
_VEC    = os.path.join(_ML_DIR, "vectorizer.pkl")
_URL_MODEL = os.path.join(_ML_DIR, "url_model.pkl")

# ── State ─────────────────────────────────────────────────────────────────────
_bundle   = None   # dict: {word_tfidf, heuristic, model}
_ml_ready = False

_url_bundle = None
_url_ml_ready = False


def _load() -> bool:
    global _bundle, _ml_ready
    if _ml_ready:
        return True
    try:
        import joblib
        if not os.path.exists(_MODEL) or not os.path.exists(_VEC):
            return False
        bundle = joblib.load(_MODEL)
        # Validate bundle has required keys
        required = {"word_tfidf", "heuristic", "model"}
        if not required.issubset(bundle.keys()):
            logger.error("Model bundle is missing required keys. Re-run train_model.py.")
            return False
        _bundle   = bundle
        _ml_ready = True
        logger.info("✅ ZeroPhish ML ensemble model loaded.")
        return True
    except Exception as e:
        logger.error(f"Failed to load ML model: {e}")
        return False


def _load_url() -> bool:
    global _url_bundle, _url_ml_ready
    if _url_ml_ready:
        return True
    try:
        import joblib
        if not os.path.exists(_URL_MODEL):
            return False
        bundle = joblib.load(_URL_MODEL)
        required = {"vectorizer", "model", "ready"}
        if not required.issubset(bundle.keys()):
            logger.error("URL Model bundle is missing required keys. Re-run train_url_model.py.")
            return False
        _url_bundle   = bundle
        _url_ml_ready = True
        logger.info("✅ ZeroPhish URL ML model loaded.")
        return True
    except Exception as e:
        logger.error(f"Failed to load URL ML model: {e}")
        return False


# ── Text preprocessing (must match train_model.py) ────────────────────────────
def _clean(text: str) -> str:
    if not isinstance(text, str):
        return ""
    text = re.sub(r"http\S+|www\S+", " _URL_ ", text)
    text = re.sub(r"[\w\.-]+@[\w\.-]+\.\w+", " _EMAIL_ ", text)
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s_]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


# ── Public API ────────────────────────────────────────────────────────────────
def predict(text: str) -> dict | None:
    """
    Classify text using the trained ensemble.

    Returns:
        {
          "risk_score":  int   (0–100),
          "result":      str   (Safe | Low Risk | Medium Risk | High Risk),
          "confidence":  float (0.0–1.0),
          "source":      "ml",
        }
        or None if the model is unavailable.
    """
    if not _load():
        return None

    if not text or not text.strip():
        return None

    try:
        from scipy.sparse import hstack, csr_matrix

        cleaned   = _clean(text)
        raw       = [text]           # keep raw for heuristic extractor

        word_vec  = _bundle["word_tfidf"].transform([cleaned])
        heur_vec  = _bundle["heuristic"].transform(raw)

        X = hstack([word_vec, heur_vec])

        spam_prob  = float(_bundle["model"].predict_proba(X)[0][1])
        risk_score = min(int(round(spam_prob * 100)), 100)

        if risk_score >= 70:
            result = "High Risk"
        elif risk_score >= 45:
            result = "Medium Risk"
        elif risk_score >= 20:
            result = "Low Risk"
        else:
            result = "Safe"

        return {
            "risk_score": risk_score,
            "result":     result,
            "confidence": spam_prob,
            "source":     "ml",
        }
    except Exception as e:
        logger.error(f"ML prediction error: {e}")
        return None


def predict_url(url: str) -> dict | None:
    """
    Classify a URL using the trained URL ML model.
    """
    if not _load_url():
        return None

    if not url or not url.strip():
        return None

    try:
        import re
        # The dataset had a heavy bias where safe links were stripped of protocols 
        # and usually ended in a slash or path. We clean the input to match this.
        clean_url = re.sub(r'^(https?://)?(www\.)?', '', url.strip())
        if '/' not in clean_url:
            clean_url += '/'

        X = _url_bundle["vectorizer"].transform([clean_url])
        prob = float(_url_bundle["model"].predict_proba(X)[0][1])
        risk_score = min(int(round(prob * 100)), 100)

        if risk_score >= 70:
            result = "High Risk"
        elif risk_score >= 45:
            result = "Medium Risk"
        elif risk_score >= 20:
            result = "Low Risk"
        else:
            result = "Safe"

        return {
            "risk_score": risk_score,
            "result":     result,
            "confidence": prob,
            "source":     "ml_url",
        }
    except Exception as e:
        logger.error(f"URL ML prediction error: {e}")
        return None


def is_ready() -> bool:
    return _load() or _load_url()
