""" Panoptes - Generic - Analysis

Just a collection of generic functions to help cloud provider analysis
"""

from datetime import datetime


def get_current_time():
    """
    Returns a datetime object with ISO 8601 format
    """
    return datetime.now().isoformat()
