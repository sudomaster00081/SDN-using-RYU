import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score
import pickle

def train_and_save_model():
    flow_dataset = pd.read_csv('FlowStatsfile.csv')

    flow_dataset.iloc[:, 2] = flow_dataset.iloc[:, 2].str.replace('.', '')
    flow_dataset.iloc[:, 3] = flow_dataset.iloc[:, 3].str.replace('.', '')
    flow_dataset.iloc[:, 5] = flow_dataset.iloc[:, 5].str.replace('.', '')

    X_flow = flow_dataset.iloc[:, :-1].values
    X_flow = X_flow.astype('float64')

    y_flow = flow_dataset.iloc[:, -1].values

    X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.25, random_state=0)

    classifier = RandomForestClassifier(n_estimators=10, criterion="entropy", random_state=0)
    flow_model = classifier.fit(X_flow_train, y_flow_train)

    y_flow_pred = flow_model.predict(X_flow_test)

    print("------------------------------------------------------------------------------")
    print("confusion matrix")
    cm = confusion_matrix(y_flow_test, y_flow_pred)
    print(cm)

    acc = accuracy_score(y_flow_test, y_flow_pred)
    print("success accuracy = {0:.2f} %".format(acc * 100))
    fail = 1.0 - acc
    print("fail accuracy = {0:.2f} %".format(fail * 100))
    print("------------------------------------------------------------------------------")

    # Save the trained model
    pickle.dump(flow_model, open('flow_model.pkl', 'wb'))

if __name__ == "__main__":
    train_and_save_model()