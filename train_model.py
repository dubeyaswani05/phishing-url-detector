"""
train_model.py
---------------
Trains a Random Forest classifier on dataset.csv and saves it to
model.pkl. Also prints accuracy, a confusion matrix, and feature
importances - all useful talking points for the viva.

Why Random Forest?
- Works well on small/medium tabular datasets (our case: 14 numeric features)
- Doesn't need feature scaling
- Gives feature importances "for free", which is great for explaining
  *why* the model thinks a URL is phishing - important for a security
  use case where the demo has to justify its answer.
"""

import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

from feature_extraction import FEATURE_NAMES


def main():
    df = pd.read_csv("dataset.csv")

    X = df[FEATURE_NAMES]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=150, max_depth=10, random_state=42
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    print(f"Test accuracy: {acc * 100:.2f}%\n")
    print("Confusion matrix (rows=actual, cols=predicted) [legit, phishing]:")
    print(confusion_matrix(y_test, y_pred))
    print("\nClassification report:")
    print(classification_report(y_test, y_pred, target_names=["legit", "phishing"]))

    print("Feature importances (most predictive first):")
    importances = sorted(
        zip(FEATURE_NAMES, model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    for name, score in importances:
        print(f"  {name:28s} {score:.3f}")

    joblib.dump(model, "model.pkl")
    print("\nSaved trained model to model.pkl")


if __name__ == "__main__":
    main()
