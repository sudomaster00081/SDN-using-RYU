import pandas as pd
import joblib

def load_model_and_predict():
    # Load the trained model
    flow_model = joblib.load('flow_model.pkl')

    try:
        # Read predicted flow dataset
        predict_flow_dataset = pd.read_csv('PredictFlowStatsfile.csv')
        predict_flow_dataset.iloc[:, 2] = predict_flow_dataset.iloc[:, 2].str.replace('.', '')
        predict_flow_dataset.iloc[:, 3] = predict_flow_dataset.iloc[:, 3].str.replace('.', '')
        predict_flow_dataset.iloc[:, 5] = predict_flow_dataset.iloc[:, 5].str.replace('.', '')

        # Preprocess data for prediction
        X_predict_flow = predict_flow_dataset.iloc[:, :].values
        X_predict_flow = X_predict_flow.astype('float64')

        # Predict using the loaded model
        y_flow_pred = flow_model.predict(X_predict_flow)

        # Process predictions
        legitimate_trafic = sum(1 for i in y_flow_pred if i == 0)
        ddos_trafic = len(y_flow_pred) - legitimate_trafic
        victim = None

        if ddos_trafic > 0:
            victim = int(predict_flow_dataset.iloc[y_flow_pred.argmax(), 5]) % 20

        # Log predictions
        print("Predictions:")
        print("Legitimate traffic:", legitimate_trafic)
        print("DDoS traffic:", ddos_trafic)
        if ddos_trafic > 0:
            print("Victim is host: h{}".format(victim))
        else:
            print("No DDoS attack detected.")

    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    load_model_and_predict()
