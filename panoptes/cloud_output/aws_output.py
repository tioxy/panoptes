import json
import yaml
from pprint import pprint


def output_json(analysis):
    print("JSON")
    return None


def output_yml(analysis):
    output = yaml.dump(
        analysis,
        default_flow_style=False,
        allow_unicode=True,
    )
    print(output)
    return None


def output_print(analysis):
    print("PRINT")
    return None


if __name__ == "__main__":
    None
