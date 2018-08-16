def parse_whitelist_file(whitelist_path):
    with open(whitelist_path, 'r') as whitelist_file:
        whitelist = whitelist_file.read().splitlines()
    return whitelist
