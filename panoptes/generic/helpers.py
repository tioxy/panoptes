""" Panoptes - Generic - Helpers

Just a collection of generic functions to help cloud provider analysis
"""

from datetime import datetime


def get_current_time() -> str:
    """
    Returns a datetime object with ISO 8601 format
    """
    return datetime.now().isoformat()


def parse_whitelist_file(whitelist_path: str) -> list:
    """
    Receives a whitelist_path containing 1 IP/CIDR per line and returns a list
    """
    with open(whitelist_path, 'r') as whitelist_file:
        whitelist = whitelist_file.read().splitlines()
    return whitelist
