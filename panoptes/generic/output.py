""" Panoptes - Generic - Output
Responsible for generic outputs used through Panoptes module
"""

import json
import yaml


def print_json(analysis):
    """
    Converts the any analysis dictionary into prettified JSON output
    """
    output = json.dumps(
        analysis,
        indent=4,
        sort_keys=True
    )
    print(output)


def print_yml(analysis):
    """
    Converts the any analysis dictionary into YML output
    """
    output = yaml.dump(
        analysis,
        default_flow_style=False,
        allow_unicode=True,
    )
    print(output)
