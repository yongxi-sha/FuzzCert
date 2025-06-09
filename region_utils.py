import numpy as np
import pickle

def deserialize_input(data, input_dtype):
    region_data, area = pickle.loads(data)
    low, high = region_data
    low = np.array(low, dtype=input_dtype)
    high = np.array(high, dtype=input_dtype)
    return (low, high, ()), area