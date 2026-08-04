import numpy as np
import xgboost as xgb
from sklearn.metrics import accuracy_score

try:
    X_test = np.load(r'e:\Nid\models\X_test_processed.npy')
    y_test = np.load(r'e:\Nid\models\y_test.npy')
    model = xgb.XGBClassifier()
    model.load_model(r'e:\Nid\models\xgb_nids_engine.json')
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"XGBoost Accuracy: {acc*100:.2f}%")
except Exception as e:
    print(f"Error calculating XGBoost accuracy: {e}")
