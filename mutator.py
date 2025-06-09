import numpy as np
import pickle

def my_mutator(data, max_size, seed):
    # this is a ramdom mutation example
    # we need custom the "region" and "area"
    '''
    random.seed(seed)
    np.random.seed(seed)
    try:
        region_data, area = pickle.loads(data)
        low, high = region_data
        low = np.array(low, dtype=input_dtype)
        high = np.array(high, dtype=input_dtype)
        region = (low, high, ())
    except Exception:
        region = random_region()
        area = 1.0

    region = mutate_region(region)
    area += random.uniform(-0.05, 0.05)
    area = max(area, 0.0)

    # serialize as (list, list), area
    serialized = pickle.dumps(((region[0].tolist(), region[1].tolist()), area))
    return serialized[:max_size]
    '''
    pass  # no-op for now