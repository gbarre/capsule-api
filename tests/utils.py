#from pprint import pprint

def dict_contains(superset, subset):
    superset_o = DictArrayCompare(superset)
    subset_o = DictArrayCompare(subset)

    return (subset_o <= superset_o)


class DictArrayCompare:

    def __init__(self, v):
        self.value = v

    def __le__(self, other):
        if type(self.value) is type(other.value):
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
                    l = [DictArrayCompare(j) for j in other.value]
                    for i in self.value:
                        v1 = DictArrayCompare(i)
                        present = False
                        for k in l:
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


