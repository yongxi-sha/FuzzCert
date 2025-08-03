def mutator(data, max_size, seed: int):
    """
    data: input data - region - in bytes
    max_size: What should this indicate? If we want the region shape to stay the same?
    seed: random seed value
    returns byte of modified data
    """

    random.seed(seed)
    region = bytearray(data)

    high = region[0]
    low = region[1]

    ceil = 2
    floor = 0

    random_mod = random.uniform(floor, ceil)

    if random.choice([True, False]):
        new_high = high + random_mod
        new_low = low + random_mod
    else:
        new_high = high - random_mod
        new_low = low - random_mod


    mutated_region = [new_high, new_low, region[2:]]
    return bytes(mutated_region)


def mutator_all_pos(data, max_size, seed: int):
    """
    data: input data - region - in bytes
    max_size: What should this indicate? If we want the region shape to stay the same?
    seed: random seed value
    returns byte of modified data
    """

    random.seed(seed)
    region = bytearray(data)

    high = region[0]
    low = region[1]

    ceil = 1
    floor = 0

    # creates a random float between floor and ceil for each region position
    random_mod = np.random.uniform(floor, ceil, size=high.shape)

    # randomize sign for each region position (either add or subtract random_mod)
    sign = np.random.choice([-1, 1], size=high.shape)

    new_high = high + (sign * random_mod)
    new_low = low + (sign * random_mod)

    mutated_region = [new_high, new_low, region[2:]]

    mutated_region_bytes = bytes(mutated_region)

    if mutated_region_bytes <= max_size:
        return bytes(mutated_region)
    else:
        print("region is larger than max_size")

def TestOneInput(config, region, sets, from_=UNKNOWN):
     pre_set = {
        "UNKNOWN": sets[UNKNOWN].set.size(),
        "SAFE": sets[ALL_SAFE].set.size(),
        "UNSAFE": sets[ALL_UNSAFE].set.size(),
        "SOME_UNSAFE": sets[SOME_UNSAFE].queue.qsize()
        }

     falsify(config, region, sets['reporter'].get_area(region), sets, from_=UNKNOWN)

     post_set = {
        "UNKNOWN": sets[UNKNOWN].set.size(),
        "SAFE": sets[ALL_SAFE].set.size(),
        "UNSAFE": sets[ALL_UNSAFE].set.size(),
        "SOME_UNSAFE": sets[SOME_UNSAFE].queue.qsize()
        }
     if falsify_predicate(pre_set, post_set):
         print("success")
     else:
         print("failure")


def falsify_predicate(pre_size: dict, post_size: dict) -> bool:
    """
    :param pre_size: The size of each set prior to falsify call
    :param post_size: The size of each set after call to falsify
    :return: bool: Checks correctness and returns True/False
    """
    total_pre = sum(value for value in pre_size.values())
    total_post = sum(value for value in post_size.values())

    delta_unk = post_size["UNKNOWN"] - pre_size["UNKNOWN"]
    delta_someunsafe = post_size["SOME_UNSAFE"] - pre_size["SOME_UNSAFE"]

    total_delta = total_post - total_pre

    # total change should be 1 -> we pulled out a region then place it back after falsify
    # unknown or some unsafe can grow by 1 but not both at the same time
    if total_delta == 1 and delta_someunsafe in [0,1] and delta_unk in [0,1] and delta_someunsafe != delta_unk:
        return True
    else:
        return False