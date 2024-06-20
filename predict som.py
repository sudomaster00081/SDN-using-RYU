import numpy as np
import pickle
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

# Example usage
# input_value = [2.536088, 0.068600 ,0.046527 ,0.055703 ,1724] # Example input value (you can replace this with your actual data)
# input_value = [0.43795354, 0.45224061, 0.46415426, 0.47427353, 0.44225198]
input_value = [0.4400012 , 0.41588544, 0.45199712, 0.41352742, 0.44222034]
d_threshold = 0.1  # Predefined distance threshold
sigma = 0.2  # Probability threshold

# Make a prediction
prediction = predict_ddos(input_value, d_threshold, sigma)

print("Predicted label for the input value:", prediction)
