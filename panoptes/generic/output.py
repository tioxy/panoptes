""" Panoptes - Generic - Output
Responsible for generic outputs used through Panoptes module
"""

import json
import yaml
import colorama


def print_json(analysis):
    """
    Converts the any analysis dictionary into prettified JSON output
    """
    return json.dumps(
        analysis,
        indent=4,
        sort_keys=True
    )


def print_yml(analysis):
    """
    Converts the any analysis dictionary into YML output
    """
    return yaml.dump(
        analysis,
        default_flow_style=False,
        allow_unicode=True,
    )


def generate_alert_message(content):
    """
    Receives the ALERT message content and colorizes it
    """
    return (
        colorama.Style.RESET_ALL
        + colorama.Fore.LIGHTRED_EX
        + "ALERT: {}".format(content)
        + colorama.Style.RESET_ALL
    )


def generate_info_message(content):
    """
    Receives the INFO message content and colorizes it
    """
    return (
        colorama.Style.RESET_ALL
        + colorama.Fore.LIGHTCYAN_EX
        + "INFO: {}".format(content)
        + colorama.Style.RESET_ALL
    )


def generate_warning_message(content):
    """
    Receives the WARNING message content and colorizes it
    """
    return (
        colorama.Style.RESET_ALL
        + colorama.Fore.YELLOW
        + "WARNING: {}".format(content)
        + colorama.Style.RESET_ALL
    )
