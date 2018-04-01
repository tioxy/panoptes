""" Panoptes - Cloud Output - AWS

Collection of functions to print AWS analysis output.
"""

import json
import yaml


def output_json(analysis):
    """
    Prints in the screen a prettified JSON version from AWS analysis dictionary
    """
    output = json.dumps(
        analysis,
        indent=4,
        sort_keys=True
    )
    print(output)
    return None


def output_yml(analysis):
    """
    Prints in the screen an YML version from AWS analysis dictionary
    """
    output = yaml.dump(
        analysis,
        default_flow_style=False,
        allow_unicode=True,
    )
    print(output)
    return None


def output_human(analysis):
    """
    Converts the AWS analysis dictionary into human readable output
    """
    print("human")
    return None


if __name__ == "__main__":
    pass
