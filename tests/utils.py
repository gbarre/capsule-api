def dict_contains(superset, subset):
    superset_o = DictArrayCompare(superset)
    subset_o = DictArrayCompare(subset)

    return (subset_o <= superset_o)


class DictArrayCompare:

    def __init__(self, v):
        self.value = v

    def __le__(self, other):
        if isinstance(self.value, type(other.value)):
            if isinstance(self.value, dict):
                if len(self.value) <= len(other.value):
                    try:
                        for k, v in self.value.items():
                            v1 = DictArrayCompare(v)
                            v2 = DictArrayCompare(other.value[k])
                            if not (v1 <= v2):
                                return False
                    except KeyError:
                        return False
                else:
                    return False
            elif isinstance(self.value, list):
                if len(self.value) <= len(other.value):
                    li = [DictArrayCompare(j) for j in other.value]
                    for i in self.value:
                        v1 = DictArrayCompare(i)
                        present = False
                        for k in li:
                            if v1 <= k:
                                present = True
                                break
                        if not present:
                            return False
                else:
                    return False
            else:
                return (self.value == other.value)
        else:
            return False

        return True


api_version = '/v1'

bad_id = "XYZ"
unexisting_id = "ffffffff-ffff-ffff-ffff-ffffffffffff"
