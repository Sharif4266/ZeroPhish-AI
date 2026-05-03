import os
import time
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score

# ── Config ────────────────────────────────────────────────────────────────────
CSV_PATH   = r"c:\Users\shari\Downloads\dataset_with_all_features v2.csv"
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "app", "ml")
MODEL_PATH = os.path.join(OUTPUT_DIR, "url_model.pkl")
os.makedirs(OUTPUT_DIR, exist_ok=True)

def main():
    print("==============================================================")
    print("  ZeroPhish AI -> URL Phishing Classifier Training")
    print("  Model: Char TF-IDF -> Logistic Regression")
    print("==============================================================")

    # 1. Load Dataset
    print(f"\n[1/5] Loading dataset from:\n      {CSV_PATH}")
    t0 = time.time()
    df = pd.read_csv(CSV_PATH, usecols=["url", "label"], low_memory=False)
    
    # Drop missing
    df = df.dropna(subset=["url", "label"])
    
    # Map labels: 0=Safe, >0=Malicious (Phishing/Malware/Defacement)
    df["label"] = df["label"].apply(lambda x: 1 if float(x) > 0 else 0)
    
    print(f"      + Loaded {len(df):,} URLs in {time.time()-t0:.1f}s")
    counts = df["label"].value_counts()
    print(f"      Label 0 (Safe):      {counts.get(0, 0):>7,}")
    print(f"      Label 1 (Malicious): {counts.get(1, 0):>7,}")

    # 2. Split (stratified)
    print("\n[2/5] Splitting -> 80% train / 20% test (stratified)...")
    X = df["url"].astype(str)
    y = df["label"]
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    print(f"      Train: {len(X_train):,}   Test: {len(X_test):,}")

    # 3. Vectorise
    print("\n[3/5] Vectorising (Character n-grams)...")
    t0 = time.time()
    
    # We use character n-grams (3 to 5 chars) to catch weird URL structures
    # like 'paypal', 'login', '.xyz', 'admin'
    vectorizer = TfidfVectorizer(
        analyzer='char',
        ngram_range=(3, 5),
        max_features=25_000,
        sublinear_tf=True
    )
    
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec  = vectorizer.transform(X_test)
    print(f"      + Vectorisation complete: {X_train_vec.shape[1]:,} features ({time.time()-t0:.1f}s)")

    # 4. Train Model
    print("\n[4/5] Training Logistic Regression Model...")
    t0 = time.time()
    model = LogisticRegression(max_iter=1000, random_state=42)
    model.fit(X_train_vec, y_train)
    print(f"      + Training complete in {time.time()-t0:.1f}s")

    # 5. Evaluate
    print("\n[5/5] Evaluating on held-out test set...")
    y_pred = model.predict(X_test_vec)
    y_prob = model.predict_proba(X_test_vec)[:, 1]
    
    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)
    
    print("  +-------------------------------------+")
    print(f"  |  Accuracy :  {acc*100:.3f}%               |")
    print(f"  |  ROC-AUC  :  {auc:.6f}             |")
    print("  +-------------------------------------+")
    print("\n", classification_report(y_test, y_pred, target_names=["Safe (0)", "Malicious (1)"]))

    # 6. Save Bundle
    bundle = {
        "vectorizer": vectorizer,
        "model": model,
        "ready": True
    }
    joblib.dump(bundle, MODEL_PATH, compress=1)
    print(f"  Saving URL model -> {MODEL_PATH}")

    print(f"\n[DONE] URL Model accuracy: {acc*100:.3f}%")
    print("==============================================================")

if __name__ == "__main__":
    main()
