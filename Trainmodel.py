from sklearn.ensemble import RandomForestClassifier
import pandas as pd

def train_and_save_model():
    # Read flow dataset
    flow_dataset = pd.read_csv('FlowStatsfile.csv')

    # Data preprocessing
    flow_dataset.iloc[:, 2] = flow_dataset.iloc[:, 2].str.replace('.', '')
    flow_dataset.iloc[:, 3] = flow_dataset.iloc[:, 3].str.replace('.', '')
    flow_dataset.iloc[:, 5] = flow_dataset.iloc[:, 5].str.replace('.', '')

    X_flow = flow_dataset.iloc[:, :-1].values
    X_flow = X_flow.astype('float64')
    y_flow = flow_dataset.iloc[:, -1].values

    # Model training
    classifier = RandomForestClassifier(n_estimators=10, criterion="entropy", random_state=0)
    flow_model = classifier.fit(X_flow, y_flow)

    # Save the model
    import joblib
    joblib.dump(flow_model, 'flow_model.pkl')

if __name__ == "__main__":
    train_and_save_model()
