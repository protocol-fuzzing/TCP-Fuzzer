import tomllib
from jsonschema import validate


class TOMLParser:
    """This class is responsible for parsing the mappers config file, written in TOML"""

    config = {}
    

    schema = {
        "type": "object",
        "properties": {
            "Learner": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string"},
                    "port": {"type": "integer"}
                },
                "required": ["ip", "port"],
                "additionalProperties": False
            },
            "SUT": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string"},
                    "port": {"type": "integer"},
                    "waittime": {"type": "number"}
                },
                "required": ["ip", "port", "waittime"],
                "additionalProperties": False
            },
            "DPI": {
                "type": "object",
                "properties": {
                    "enabled": {"type": "boolean"},
                    "alerts_file": {"type": "string", "minLength": 1},
                    "waittime": {"type": "number", "minimum": 0}
                },
                "required": ["enabled"],
                "allOf": [
                    {
                        "if": {
                            "properties": {
                                "enabled": {"const": True}
                            }
                        },
                        "then": {
                            "required": ["alerts_file"]
                        }
                    }
                ],
                "additionalProperties": False
            }
        }
    }


    def __init__(self, file):
        with open(file, 'rb') as f:
            self.config = tomllib.load(f)
            validate(self.config, self.schema)
            print(self.config)

    def getConfig(self):
        return self.config    
