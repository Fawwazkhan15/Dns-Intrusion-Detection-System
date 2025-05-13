import csv
import numpy as np
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

csv_file = "dns_features.csv"
model_file = "dns_classifier.pkl"

def train_model():
    if not os.path.exists(csv_file):
        print("❌ Error: Feature file not found! Training aborted.")
        return
    
    print("📊 Loading dataset for training...")
    data = np.genfromtxt(csv_file, delimiter=',', skip_header=1)

    if data.size == 0:
        print("❌ Error: No data found in feature file. Training aborted.")
        return

    X = data[:, :-1]  # Features
    y = data[:, -1]   # Labels

    # Check for malicious samples
    if np.sum(y) == 0:
        print("⚠️ Warning: No malicious data found! Adding synthetic malicious samples...")
        malicious_samples = np.array([
            [80, 12, 400, 1],  # High query length, subdomain count
            [90, 15, 450, 1],
            [100, 20, 500, 1]
        ])
        data = np.vstack((data, malicious_samples))
        X = data[:, :-1]
        y = data[:, -1]

    # Split dataset into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    print("🚀 Training the Random Forest model...")
    model = RandomForestClassifier()
    model.fit(X_train, y_train)

    # Save the trained model
    joblib.dump(model, model_file)
    print("✅ Model trained and saved as dns_classifier.pkl.")

if __name__ == "__main__":
    train_model()
