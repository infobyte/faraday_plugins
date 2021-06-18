from xmltodict import parse
from json import dumps
from re import findall

class GenerateDTO:
    data = ""
    def __init__(self, data, *args, **kwargs):
        self.data = data

    def make_all(self, name):
        if not isinstance(self.data, dict):
            json_data = parse(self.data)
        self.create_file(name, json_data)
        data = self.generate_json_dto(json_data)
        import ipdb;
        ipdb.set_trace()
        # self.create_file(f"{name}2", data)

    def create_file(self, name, kwargs):
        with open(f"readed_data/{name}.json", "w") as file:
            file.write(dumps(kwargs, indent=4))

    def generate_json_dto(self, json_data, main="main"):
        data = {}
        for k, v in json_data.items():
            if isinstance(v, dict):

                data [k] = {
                    "value": self.generate_json_dto(v, k),
                    "type": dict,
                    "sub_type": k.capitalize()
                }
                continue

            if isinstance(v, list):
                join_data = self.join_all_data(v)
                data [k] = {
                    "value": self.generate_json_dto(join_data, k),
                    "type": list,
                    "sub_type": k.capitalize()
                }
                continue


            data[k] = {
                "value": v,
                "type": type(v)
            }
        # import ipdb;
        # ipdb.set_trace()
        self.print_dto_file(data, main)

        return data

    def join_all_data(self, array):
        data = {}
        for i in array:
            data.update(i)
        return data

    def print_dto_file(self, data, key="main"):
        print(f"")
        print(f"")
        print(f"class {key.capitalize()}:")
        print(f"    def __init__(self, node):")
        print(f"        self.node = node")
        for k, v in data.items():
            key = self.parse_key(k.lower())

            if v.get("type") == dict:
                print(f"    @property")
                print(f"    def {key}(self) -> {v['sub_type']}:")
                print(f"        return {v['sub_type']}(self.node.find('{k}'))")
                continue
            if v.get("type") == list:
                print(f"    @property")
                print(f"    def {key}(self) -> List[{v['sub_type']}]:")
                print(f"        return [{v['sub_type']}(i) for i in self.node.findall('{k}', [])]")
                continue
            print(f"")
            print(f"    @property")
            print(f"    def {key}(self) -> {v['type'].__name__}:")
            if "_attr" not in key:
                print(f"        return {v['sub_type']}(self.node.find('{k}'))")
            else:
                print(f"        return {v['sub_type']}(self.node.get('{k}'))")


    def parse_key(self, string):
        if "@" in string.lower():
            string = string.lower().replace("@", "")+"_attr"

        if "#" in string.lower():
            string = string.lower().replace("#", "")
        return string