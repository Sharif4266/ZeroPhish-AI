"""
ZeroPhish AI — Shared ML Feature Extractor
Defined here so it can be imported consistently by both:
  - train_model.py  (during training)
  - ml_scanner.py   (during inference)

This resolves the joblib pickle class-lookup issue where
HeuristicFeatures was previously saved as __main__.HeuristicFeatures
but could not be found at inference time.
"""
import re
import numpy as np
from scipy.sparse import csr_matrix
from sklearn.base import BaseEstimator, TransformerMixin

URGENCY_WORDS = [
    'urgent', 'immediately', 'act now', 'limited time', 'expire',
    'verify', 'suspended', 'confirm', 'validate', 'click here',
    'congratulations', 'winner', 'free', 'prize', 'account',
]


class HeuristicFeatures(BaseEstimator, TransformerMixin):
    """Extract 8 hand-crafted numerical signals from raw text."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        features = np.array([self._extract(text) for text in X], dtype=np.float32)
        return csr_matrix(features)

    def _extract(self, text: str) -> list:
        if not isinstance(text, str):
            text = ""
        lower = text.lower()

        # 1. URL count — more URLs = more suspicious
        url_count = len(re.findall(r'https?://|www\.', lower))

        # 2. Ratio of uppercase letters — SHOUTING in phishing emails
        alpha = sum(c.isalpha() for c in text)
        caps_ratio = sum(c.isupper() for c in text) / max(alpha, 1)

        # 3. Exclamation marks — !! urgency signals !!
        exclamation = text.count('!')

        # 4. Urgency keyword density
        urgency_hits = sum(1 for w in URGENCY_WORDS if w in lower)

        # 5. Dollar / money signs
        money_signs = text.count('$') + text.count('£') + text.count('€')

        # 6. HTML tag presence — raw HTML in email body
        html_tags = len(re.findall(r'<[a-z][^>]*>', lower))

        # 7. Text length (log-scaled) — phishing emails tend to be a specific length
        text_len = np.log1p(len(text))

        # 8. Digit ratio — many digits can signal account numbers, etc.
        digit_ratio = sum(c.isdigit() for c in text) / max(len(text), 1)

        return [
            url_count, caps_ratio, exclamation, urgency_hits,
            money_signs, html_tags, text_len, digit_ratio
        ]
