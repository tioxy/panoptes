import json
import yaml


def print_json(analysis):
    """
    Prints in the screen a prettified JSON version from any analysis
    """
    output = json.dumps(
        analysis,
        indent=4,
        sort_keys=True
    )
    print(output)
    return None


def print_yml(analysis):
    """
    Prints in the screen an YML version from any analysis
    """
    output = yaml.dump(
        analysis,
        default_flow_style=False,
        allow_unicode=True,
    )
    print(output)
    return None
