""" Panoptes - Generic - Parser
Responsible for generic parsers used through Panoptes module
"""


def parse_whitelist_file(whitelist_path):
    """
    Receives a whitelist_path containing 1 IP/CIDR per line and returns a list
    """
    with open(whitelist_path, 'r') as whitelist_file:
        whitelist = whitelist_file.read().splitlines()
    return whitelist
