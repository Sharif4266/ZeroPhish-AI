"""
ZeroPhish AI — Strong Model Training Script
============================================
Architecture: Multi-feature pipeline + Voting Ensemble
  Features:
    1. Word TF-IDF (1,2-grams, 30k features)   — semantic patterns
    2. Char TF-IDF (2,4-grams, 20k features)   — catches obfuscated text
    3. 8 heuristic signals                      — URL count, caps ratio, etc.
  Models (soft-vote ensemble):
    • Logistic Regression  — strong baseline, great with TF-IDF
    • LinearSVC (calibrated) — powerful linear separator for text
    • Complement Naive Bayes — excels on imbalanced text classification

Expected: ~98-99%+ accuracy on SpamAssassin dataset

Usage:
    python train_model.py

Outputs:
    app/ml/model.pkl       — trained ensemble model
    app/ml/vectorizer.pkl  — fitted TF-IDF + feature pipeline
"""
import os
import re
import time
import warnings
import numpy as np
import pandas as pd
import joblib

warnings.filterwarnings("ignore")

from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import ComplementNB
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import VotingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import MaxAbsScaler
from scipy.sparse import hstack, csr_matrix
from app.services.ml_features import HeuristicFeatures

# ── Config ────────────────────────────────────────────────────────────────────
DESKTOP_DIR = r"c:\Users\shari\OneDrive\Desktop"
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "app", "ml")
MODEL_PATH = os.path.join(OUTPUT_DIR, "model.pkl")
VEC_PATH   = os.path.join(OUTPUT_DIR, "vectorizer.pkl")
os.makedirs(OUTPUT_DIR, exist_ok=True)


# ── Text cleaning ─────────────────────────────────────────────────────────────
def clean_text(text: str) -> str:
    """Normalize text while preserving structural signals."""
    if not isinstance(text, str):
        return ""
    text = re.sub(r"http\S+|www\S+", " _URL_ ", text)
    text = re.sub(r"[\w\.-]+@[\w\.-]+\.\w+", " _EMAIL_ ", text)
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s_]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text




# ── Dataset Loading ───────────────────────────────────────────────────────────
def load_all_datasets(desktop_path: str):
    import glob
    print(f"\n[1/6] Loading all datasets from:\n      {desktop_path}")
    t0 = time.time()
    
    all_dfs = []
    csv_files = glob.glob(os.path.join(desktop_path, "*.csv"))
    
    for f in csv_files:
        fname = os.path.basename(f)
        try:
            df = pd.read_csv(f, on_bad_lines="skip", low_memory=False)
            
            # Align columns based on the file schema
            if "text_combined" in df.columns:
                # All phishing_mails.csv schema
                temp = pd.DataFrame()
                temp["raw_text"] = df["text_combined"].astype(str)
                temp["label"] = pd.to_numeric(df["label"], errors='coerce')
                all_dfs.append(temp)
                print(f"      + Loaded {fname:25s} ({len(temp):>7,} rows)")
                
            elif "Email Text" in df.columns and "Email Type" in df.columns:
                # Phishing_Email.csv schema
                temp = pd.DataFrame()
                temp["raw_text"] = df["Email Text"].astype(str)
                # Map 'Phishing Email' -> 1, 'Safe Email' -> 0
                temp["label"] = df["Email Type"].apply(lambda x: 1 if str(x).strip() == 'Phishing Email' else 0)
                all_dfs.append(temp)
                print(f"      + Loaded {fname:25s} ({len(temp):>7,} rows)")
                
            elif "subject" in df.columns and "body" in df.columns:
                # SpamAssasin, CEAS_08, Nigerian_Fraud, Enron schema
                temp = pd.DataFrame()
                subj = df["subject"].fillna("").astype(str)
                body = df["body"].fillna("").astype(str)
                temp["raw_text"] = subj + " " + body
                temp["label"] = pd.to_numeric(df["label"], errors='coerce')
                all_dfs.append(temp)
                print(f"      + Loaded {fname:25s} ({len(temp):>7,} rows)")
                
            else:
                print(f"      - Skipped {fname:24s} (Unknown schema)")
        except Exception as e:
            print(f"      - Error reading {fname}: {e}")

    # Combine all
    master_df = pd.concat(all_dfs, ignore_index=True)
    master_df = master_df.dropna(subset=["label", "raw_text"])
    master_df["label"] = master_df["label"].astype(int)
    
    # Remove empty texts
    master_df = master_df[master_df["raw_text"].str.strip() != ""]
    
    print(f"\n      + Combined into master dataset: {len(master_df):,} total rows in {time.time()-t0:.1f}s")

    counts = master_df["label"].value_counts()
    print(f"      Label 0 (Legit):         {counts.get(0, 0):>7,}")
    print(f"      Label 1 (Spam/Phishing): {counts.get(1, 0):>7,}")

    print("      Cleaning master text for TF-IDF...")
    master_df["clean_text"] = master_df["raw_text"].apply(clean_text)

    return master_df


# ── Build Feature Pipeline ────────────────────────────────────────────────────
def build_feature_pipeline():
    """
    Two-branch feature extractor:
      Branch 1: Word TF-IDF on cleaned text (semantic)
      Branch 2: Heuristic signals on raw text (structural)
    """
    word_tfidf = TfidfVectorizer(
        max_features=25_000,
        ngram_range=(1, 2),
        sublinear_tf=True,
        min_df=3,
        analyzer='word',
    )
    return word_tfidf, HeuristicFeatures()


# ── Build Ensemble Model ──────────────────────────────────────────────────────
def build_model():
    """
    Soft-voting ensemble of three complementary classifiers:
      1. Logistic Regression  — excellent baseline for TF-IDF features
      2. LinearSVC (calibrated) — powerful margin-based classifier
      3. Complement Naive Bayes — designed for imbalanced text classification
    """
    lr = LogisticRegression(
        max_iter=1000,
        C=5.0,
        solver="lbfgs",
        class_weight="balanced",
        random_state=42,
    )
    svc = CalibratedClassifierCV(
        LinearSVC(
            max_iter=2000,
            C=0.5,
            class_weight="balanced",
            random_state=42,
        ),
        cv=3,
    )
    cnb = ComplementNB(alpha=0.1)

    ensemble = VotingClassifier(
        estimators=[("lr", lr), ("svc", svc), ("cnb", cnb)],
        voting="soft",
        weights=[3, 3, 1],   # LR and SVC trusted more than NB
    )
    return ensemble


# -- Main ----------------------------------------------------------------------
def main():
    print("=" * 62)
    print("  ZeroPhish AI — Strong Phishing Classifier Training")
    print("  Model: TF-IDF (word+char) + Heuristics -> Voting Ensemble")
    print("=" * 62)

    # 1. Load all datasets from Desktop
    df = load_all_datasets(DESKTOP_DIR)

    # 2. Split
    print("\n[2/6] Splitting -> 80% train / 20% test (stratified)...")
    X_clean = df["clean_text"]
    X_raw   = df["raw_text"]
    y       = df["label"]

    (X_clean_train, X_clean_test,
     X_raw_train,   X_raw_test,
     y_train,       y_test) = train_test_split(
        X_clean, X_raw, y,
        test_size=0.20, random_state=42, stratify=y
    )
    print(f"      Train: {len(y_train):,}   Test: {len(y_test):,}")

    # 3. Build feature extractors
    print("\n[3/6] Building feature extractors...")
    word_tfidf, heuristic = build_feature_pipeline()

    # 4. Vectorise
    print("\n[4/6] Vectorising (word TF-IDF + heuristics)...")
    t0 = time.time()

    print("      -> Word TF-IDF...", end="", flush=True)
    X_word_train = word_tfidf.fit_transform(X_clean_train)
    X_word_test  = word_tfidf.transform(X_clean_test)
    print(f" {X_word_train.shape[1]:,} features")

    print("      -> Heuristic signals...", end="", flush=True)
    X_heur_train = heuristic.transform(X_raw_train)
    X_heur_test  = heuristic.transform(X_raw_test)
    print(" 8 features")

    # Stack all features horizontally
    X_train_all = hstack([X_word_train, X_heur_train])
    X_test_all  = hstack([X_word_test,  X_heur_test])
    total_feats = X_train_all.shape[1]
    print(f"      + Total feature matrix: {X_train_all.shape[0]:,} x {total_feats:,}  ({time.time()-t0:.1f}s)")

    # 5. Train ensemble
    print("\n[5/6] Training Voting Ensemble (LR + SVC + ComplementNB)...")
    t0    = time.time()
    model = build_model()
    model.fit(X_train_all, y_train)
    print(f"      + Training complete in {time.time()-t0:.1f}s")

    # 6. Evaluate
    print("\n[6/6] Evaluating on held-out test set...")
    y_pred = model.predict(X_test_all)
    y_prob = model.predict_proba(X_test_all)[:, 1]
    acc    = accuracy_score(y_test, y_pred)
    auc    = roc_auc_score(y_test, y_prob)
    report = classification_report(
        y_test, y_pred,
        target_names=["Legit (0)", "Spam/Phishing (1)"],
        digits=4,
    )

    print(f"  +-------------------------------------+")
    print(f"  |  Accuracy :  {acc*100:6.3f}%               |")
    print(f"  |  ROC-AUC  :  {auc:8.6f}             |")
    print(f"  +-------------------------------------+")
    print(f"\n{report}")

    # Save
    print(f"  Saving model      -> {MODEL_PATH}")
    print(f"  Saving vectorizer -> {VEC_PATH}")

    # Pack everything the inference module needs into one dict
    pipeline_bundle = {
        "word_tfidf": word_tfidf,
        "heuristic":  heuristic,
        "model":      model,
    }

    joblib.dump(pipeline_bundle, MODEL_PATH, compress=3)
    # Keep vectorizer.pkl as a sentinel so ml_scanner knows training is done
    joblib.dump({"ready": True, "accuracy": acc, "auc": auc}, VEC_PATH, compress=1)

    print(f"\n[DONE] Model accuracy: {acc*100:.3f}%  AUC: {auc:.6f}")
    print("   Restart the FastAPI server to activate ML scanning.")
    print("=" * 62)


if __name__ == "__main__":
    main()
