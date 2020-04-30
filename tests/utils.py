def dict_contains(superset, subset):
    for k, v in subset.items():
        try:
            v_cmp = superset[k]
            if isinstance(v, list):
                if isinstance(v_cmp, list):
                    if sorted(v) != sorted(v_cmp):
                        return False
                else:
                    return False
            elif v != v_cmp:
                return False
        except KeyError:
            return False

    return True
