import random
import pickle

def my_mutator(data, max_size, seed):

    random.seed(seed)

    mutated_region = region
    high = region.high
    low = region.low
    ceil = 1
    floor = 0
    random_mod = np.random.uniform(floor, ceil, size=high.shape)
    sign = np.random.choice([-1, 1], size=high.shape)

    new_high = high + (sign * random_mod)
    new_low = low + (sign * random_mod)

    mutated_region.high = new_high
    mutated_region.low = new_low

    encoded_region = pickle.dumps(mutated_region)

    if len(encoded_region) <= max_size:
        return encoded_region[:max_size]
    else:
        raise NotImplementedError(f"returned encoded_region exceed max_len: {max_size}")
