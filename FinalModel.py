
import pandas as pd
import numpy as np
import pickle
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from tensorflow.keras.utils import to_categorical
from tensorflow.keras.models import Sequential, clone_model
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping
import matplotlib.pyplot as plt
import seaborn as sns

df_train = pd.read_csv("/kaggle/input/unsw-nb15/UNSW_NB15_training-set.csv")
df_test = pd.read_csv("/kaggle/input/unsw-nb15/UNSW_NB15_testing-set.csv")
df = pd.concat([df_train, df_test], ignore_index=True)

df['attack_cat'] = df['attack_cat'].fillna('Normal')
label_encoder = LabelEncoder()
df['attack_cat'] = label_encoder.fit_transform(df['attack_cat'])
num_classes = len(label_encoder.classes_)

categorical_cols = ['proto', 'service', 'state']
for col in categorical_cols:
    df[col] = LabelEncoder().fit_transform(df[col])

X = df.drop(columns=['id', 'label', 'attack_cat'], errors='ignore')
X = X.select_dtypes(include=[np.number])
y = df['attack_cat'].values

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

with open("label_encoder.pkl", "wb") as f:
    pickle.dump(label_encoder, f)

X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, stratify=y, random_state=42)
y_train_cat = to_categorical(y_train, num_classes=num_classes)
y_test_cat = to_categorical(y_test, num_classes=num_classes)

def build_model(input_shape, num_classes):
    model = Sequential([
        Dense(256, activation='relu', input_shape=(input_shape,)),
        Dropout(0.4),
        Dense(128, activation='relu'),
        Dropout(0.3),
        Dense(64, activation='relu'),
        Dropout(0.2),
        Dense(num_classes, activation='softmax')
    ])
    model.compile(optimizer=Adam(0.001), loss='categorical_crossentropy', metrics=['accuracy'])
    return model

clients = 5
X_splits = np.array_split(X_train, clients)
y_splits = np.array_split(y_train_cat, clients)

global_model = build_model(X_train.shape[1], num_classes)

for rnd in range(10):
    print(f"\n🔁 Federated Round {rnd+1}")
    weights = []
    for i in range(clients):
        local_model = clone_model(global_model)
        local_model.set_weights(global_model.get_weights())
        local_model.compile(optimizer=Adam(0.001), loss='categorical_crossentropy', metrics=['accuracy'])

        early_stop = EarlyStopping(monitor='loss', patience=2, restore_best_weights=True)
        local_model.fit(X_splits[i], y_splits[i], epochs=6, batch_size=64, verbose=0, callbacks=[early_stop])

        weights.append(local_model.get_weights())

    new_weights = [np.mean(w, axis=0) for w in zip(*weights)]
    global_model.set_weights(new_weights)

y_pred_probs = global_model.predict(X_test, verbose=0)
y_pred = np.argmax(y_pred_probs, axis=1)

print("\n📊 Final Classification Report:")
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(12, 8))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=label_encoder.classes_,
            yticklabels=label_encoder.classes_)
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.show()
