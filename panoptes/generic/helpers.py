""" Panoptes - Generic - Helpers

Just a collection of generic functions to help cloud provider analysis
"""

import datetime
import dateutil
import json
import yaml
import panoptes


def get_current_time() -> str:
    """
    Returns a datetime object with ISO 8601 format
    """
    return datetime.datetime.now().isoformat()


def generate_human_time(time: datetime.datetime) -> str:
    """
    Generates a human-readable string from a datetime object
    """
    return time.strftime("%b %d %Y, %H:%M:%S")


def convert_string_datetime(timestr: str) -> datetime.datetime:
    """
    Converts any string into a datetime object
    """
    return dateutil.parser.parse(timestr)


def parse_whitelist_file(whitelist_path: str) -> list:
    """
    Receives a whitelist_path containing 1 IP/CIDR per line and returns a list
    """
    with open(whitelist_path, 'r') as whitelist_file:
        whitelist = whitelist_file.read().splitlines()
    return whitelist


def parse_analysis_file(analysis_path: str) -> dict:
    """
    Receives an analysis_path containing a Panoptes generated analysis
    """
    analysis = {}

    with open(analysis_path, 'r') as analysis_file:
        if ".json" in analysis_path:
            analysis = json.load(analysis_file)
        if ".yml" in analysis_path or ".yaml" in analysis_path:
            analysis = yaml.load(analysis_file)

    if not analysis:
        raise panoptes.generic.exceptions.PanoptesFileExtensionMissing(
            "You are missing a supported file extension. "
            "Make sure your file extension is supported and named properly."
        )
    return analysis


def write_analysis_file(analysis: dict, analysis_path: str, analysis_output: str):
    """
    Receives an analysis_path and writes a file containing the generated analysis 
    """ 
    with open(analysis_path, 'w') as analysis_file:
        if analysis_output == "json":
            json.dump(
                analysis, 
                analysis_file,
                indent=4,
                sort_keys=True
            )
        if analysis_output == "yml":
            yaml.dump(
                analysis, 
                analysis_file,
                allow_unicode=True,
                default_flow_style=False,
            )
    return None
