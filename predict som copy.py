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
def make_prediction(input_value, d_threshold, sigma):
    prediction = predict_ddos(input_value, d_threshold, sigma)
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
    mean_std_dict = [(9.437737497582425, 4.234022502390504), (1.0014830681710152, 0.4148545486662927), (0.783486142367573, 0.5773500479812647), (0.38101732217098544, 0.17530338230820758), (111228.13152610442, 75499.55601941863)]
    normalized = normalize_with_tanh_estimator_single(input_value, mean_std_dict)
    print("Normalized", normalized)

    return normalized

# Example usage
# input_value = [0.4400012 , 0.41588544, 0.45199712, 0.41352742, 0.44222034]
# input_value = [0.43795354, 0.45224061, 0.46415426, 0.47427353, 0.44225198]
input_value = [2.763893 , 1.445125 , 3.094029, 0.999693, 582]
print("input value =",input_value)
preprocessed_input = preprocess_input(input_value)
print("Preprocessed input value:", preprocessed_input)

d_threshold = 0.1  # Predefined distance threshold
sigma = 0.2  # Probability threshold

# Make a prediction using the encapsulated function
prediction = make_prediction(preprocessed_input, d_threshold, sigma)

print("Predicted label for the input value:", prediction)
