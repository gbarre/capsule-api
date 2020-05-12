#from pprint import pprint

def dict_contains(superset, subset):
    #pprint(superset)
    #print("====")
    #pprint(subset)
    for k, v in subset.items():
        try:
            v_cmp = superset[k]
            if DictArrayCompare(v_cmp) != DictArrayCompare(v):
                return False

            # print(v)
            # print(v_cmp)
            # print("===")
            # if isinstance(v, list):
            #     if isinstance(v_cmp, list):
            #         ### et si v et v_cmp sont des list de dict ???
            #         if sorted(v) != sorted(v_cmp):
            #             return False
            #     else:
            #         return False
            # elif isinstance(v, dict):
            #     if isinstance(v_cmp, dict):
            #         res = dict_contains(v_cmp, v)
            #         if res == False:
            #             return False
            #     else:
            #         return False
            # elif v != v_cmp:
            #     return False

        except KeyError:
            return False

    return True


class DictArrayCompare:

    def __init__(self, v):
        self.value = v

    def __eq__(self, other):
        if type(self.value) is type(other.value):
            if isinstance(self.value, dict):
                if len(self.value) == len(other.value):
                    try:
                        for k, v in self.value.items():
                            v1 = DictArrayCompare(v)
                            v2 = DictArrayCompare(other.value[k])
                            if v1 != v2:
                                return False
                    except KeyError:
                        return False
                else:
                    return False
            elif isinstance(self.value, list):
                if len(self.value) == len(other.value):
                    l = [DictArrayCompare(j) for j in other.value]
                    for i in self.value:
                        v1 = DictArrayCompare(i)
                        if v1 not in l:
                            return False
                else:
                    return False
            else:
                return (self.value == other.value)
        else:
            return False

        return True

