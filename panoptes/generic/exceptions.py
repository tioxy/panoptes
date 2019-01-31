""" Panoptes - Generic - Exceptions

Collection of custom exceptions used to handle Generic errors
"""


class PanoptesFileExtensionMissing(Exception):
    def __init__(self, message):
        super().__init__(message)
