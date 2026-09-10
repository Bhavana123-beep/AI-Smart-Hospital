"""Train the project disease classifier from the supplied CSV files.

This is a demonstration model, not a clinical diagnostic system.  The supplied
data contain many repeated synthetic records, so its validation scores must not
be interpreted as real-world medical accuracy.
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "dataset"
MODEL_PATH = BASE_DIR / "model" / "disease_model.pkl"
REPORT_PATH = BASE_DIR / "model" / "model_evaluation.json"
TARGET = "prognosis"
RANDOM_STATE = 42


def clean_dataset(path: Path) -> tuple[pd.DataFrame, pd.Series]:
    data = pd.read_csv(path)
    if TARGET not in data:
        raise ValueError(f"{path} does not contain the required {TARGET!r} target column.")
    features = data.drop(columns=[TARGET])
    # This source's Unnamed: 133 field is entirely empty and is not a symptom.
    features = features.loc[:, ~features.columns.str.match(r"^Unnamed:", case=False)].copy()
    features = features.fillna(0).astype("int8")
    return features, data[TARGET].astype(str).str.strip()


def metrics(y_true, y_pred) -> dict:
    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    weighted = report["weighted avg"]
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 6),
        "precision_weighted": round(float(weighted["precision"]), 6),
        "recall_weighted": round(float(weighted["recall"]), 6),
        "f1_weighted": round(float(weighted["f1-score"]), 6),
    }


def main() -> None:
    train_x, train_y = clean_dataset(DATA_DIR / "Training.csv")
    test_x, test_y = clean_dataset(DATA_DIR / "Testing.csv")
    if list(train_x.columns) != list(test_x.columns):
        raise ValueError("Training and testing feature columns do not match exactly.")

    params = dict(
        n_estimators=300,
        min_samples_leaf=2,
        min_samples_split=4,
        max_features="sqrt",
        class_weight="balanced",
        random_state=RANDOM_STATE,
        # One process keeps this script compatible with restricted Windows hosts.
        n_jobs=1,
    )
    # A reproducible split gives a useful development check.  The supplied
    # Testing.csv remains untouched for final evaluation.
    x_fit, x_validation, y_fit, y_validation = train_test_split(
        train_x, train_y, test_size=0.20, stratify=train_y, random_state=RANDOM_STATE
    )
    validation_model = RandomForestClassifier(**params).fit(x_fit, y_fit)
    validation_predictions = validation_model.predict(x_validation)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    cv_scores = cross_val_score(RandomForestClassifier(**params), train_x, train_y, cv=cv, n_jobs=1)

    final_model = RandomForestClassifier(**params).fit(train_x, train_y)
    train_predictions = final_model.predict(train_x)
    test_predictions = final_model.predict(test_x)
    labels = [str(label) for label in final_model.classes_]
    report = {
        "model": "RandomForestClassifier",
        "parameters": params,
        "target": TARGET,
        "features": list(train_x.columns),
        "feature_count": len(train_x.columns),
        "class_count": int(train_y.nunique()),
        "training_rows": len(train_x),
        "testing_rows": len(test_x),
        "training": metrics(train_y, train_predictions),
        "validation_split": metrics(y_validation, validation_predictions),
        "cross_validation_accuracy": {
            "mean": round(float(cv_scores.mean()), 6),
            "standard_deviation": round(float(cv_scores.std()), 6),
            "folds": [round(float(score), 6) for score in cv_scores],
        },
        "testing": metrics(test_y, test_predictions),
        "confusion_matrix_labels": labels,
        "confusion_matrix": confusion_matrix(test_y, test_predictions, labels=labels).tolist(),
        "limitations": (
            "Training.csv has repeated synthetic rows; random row splits and the supplied test set "
            "can therefore overstate performance. These values are not clinical accuracy."
        ),
    }
    MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(final_model, MODEL_PATH)
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Saved {MODEL_PATH} ({len(train_x.columns)} features, {train_y.nunique()} classes).")
    print(json.dumps({key: report[key] for key in ("training", "validation_split", "cross_validation_accuracy", "testing")}, indent=2))
    print(f"Saved evaluation report to {REPORT_PATH}.")


if __name__ == "__main__":
    main()
