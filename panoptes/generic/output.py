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
        allow_unicode=True,
        default_flow_style=False,
    )


def generate_alert_message(content):
    """
    Receives the ALERT message content and colorizes it
    """
    return (
        colorama.Style.RESET_ALL
        + colorama.Fore.LIGHTRED_EX
        + f"ALERT: {content}"
        + colorama.Style.RESET_ALL
    )


def generate_info_message(content):
    """
    Receives the INFO message content and colorizes it
    """
    return (
        colorama.Style.RESET_ALL
        + colorama.Fore.LIGHTCYAN_EX
        + f"INFO: {content}"
        + colorama.Style.RESET_ALL
    )


def generate_warning_message(content):
    """
    Receives the WARNING message content and colorizes it
    """
    return (
        colorama.Style.RESET_ALL
        + colorama.Fore.YELLOW
        + f"WARNING: {content}"
        + colorama.Style.RESET_ALL
    )


def generate_section_message(content):
    """
    Receives the SECTION message content and colorizes it
    """
    return (
        colorama.Style.RESET_ALL
        + colorama.Style.BRIGHT
        + colorama.Fore.LIGHTGREEN_EX
        + content
        + colorama.Style.RESET_ALL
    )


def generate_header_message(content, special_char="=", special_len=61):
    horizontal = special_len * special_char
    return(
        colorama.Style.RESET_ALL
        + colorama.Style.BRIGHT
        + colorama.Fore.LIGHTGREEN_EX
        + horizontal + "\n"
        + centralize_content_from_base_string(
            content=content,
            base_string=horizontal,
        ) + "\n"
        + horizontal
        + colorama.Style.RESET_ALL
    )


def centralize_content_from_base_string(content, base_string):
    def get_necessary_spaces(content, base_string):
        return (len(base_string) - len(content)) // 2 * " "
    return (
        get_necessary_spaces(content, base_string)
        + content
        + get_necessary_spaces(content, base_string)
    )
