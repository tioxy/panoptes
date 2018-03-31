import json
import yaml
from pprint import pprint


def output_json(analysis):
    output = json.dumps(
        analysis,
        indent=4,
        sort_keys=True
    )
    print(output)
    return None


def output_yml(analysis):
    output = yaml.dump(
        analysis,
        default_flow_style=False,
        allow_unicode=True,
    )
    print(output)
    return None


def output_human(analysis):
    print("human")
    return None


if __name__ == "__main__":
    None
