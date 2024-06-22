import numpy as np
import pickle
import pandas as pd

# Load your SOM model and define other necessary variables
with open('som.p', 'rb') as infile:
    som = pickle.load(infile)

# Calculate the reference point G
g = np.median(som.get_weights(), axis=(0, 1))

# Function to calculate distance between input sample V and reference point G
def calculate_distance(v, g):
    return np.linalg.norm(v - g)

# Function to classify input sample as attack or normal and return the prediction
def predict_ddos(input_sample, d_threshold, sigma):
    distance_to_g = calculate_distance(input_sample, g)
    p_d_greater_than_x = 1 - np.exp(- (distance_to_g / sigma)**2)  # Cumulative distribution function
    is_attack = distance_to_g > d_threshold or p_d_greater_than_x > 0.6  # You can adjust the threshold as needed
    return 1 if is_attack else 0

# Function to encapsulate prediction process
def make_prediction(input_value):
    preprocessed_input = preprocess_input(input_value)
    d_threshold = 0.1  # Predefined distance threshold
    sigma = 0.2  # Probability threshold
    prediction = predict_ddos(preprocessed_input, d_threshold, sigma)
    return prediction

def normalize_with_tanh_estimator_single(data_row, mean_std_dict):
    normalized_row = []
    print("data_row", data_row )
    for i, val in enumerate(data_row):
        mu, sigma = mean_std_dict[i]
        normalized_val = 0.5 * (np.tanh(0.1 * ((val - mu) / sigma)) + 1)
        normalized_row.append(normalized_val)
# Keep excluded columns as they are
    return normalized_row

def preprocess_input(input_value):
    # Implement any necessary preprocessing steps here
    mean_std_dict = [(8.263881658687838, 4.671149926162893), (0.9246188369475715, 0.5443941383426818), (0.7003273029028211, 0.7272171514281917), (0.3280379809243417, 0.18777105312169787), (455704.77437325905, 391359.48898741446)]
    normalized = normalize_with_tanh_estimator_single(input_value, mean_std_dict)
    return normalized

# Example usage
# input_value = [0.4400012 , 0.41588544, 0.45199712, 0.41352742, 0.44222034] # With 1
# input_value = [0.43795354, 0.45224061, 0.46415426, 0.47427353, 0.44225198] # With 0
# input_value = [2.536088222091784,0.0686003391241183,0.0465273995620474,0.0557031009586454,1724] # with 0
input_value = [11.957352256041853,1.3045211901472402,0.7669488700322542,0.3644649601632569,837313] # with 1
print("input value =",input_value)

# preprocessed_input = input_value
# expected_value = [0.438995 , 0.422020 , 0.455169   ,  0.427986  ,   0.442258 ]
# print("Expected value:", expected_value)
# print("Preprocessed input value:", preprocessed_input)




# Make a prediction using the encapsulated function
prediction = make_prediction(input_value)

print("Predicted label for the input value:", prediction)
