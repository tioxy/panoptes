""" Panoptes - Generic - Helpers

Just a collection of generic functions to help cloud provider analysis
"""

import datetime
import dateutil
import json
import yaml

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
    with open(analysis_path, 'r') as analysis_file:
        if ".json" in analysis_path:
            analysis = json.load(analysis_file)
        if ".yml" in analysis_path or ".yaml" in analysis_path:
            analysis = yaml.load(analysis_file)
    return analysis
