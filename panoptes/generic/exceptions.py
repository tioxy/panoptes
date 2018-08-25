""" Panoptes - Exceptions

Just a collection of custom exceptions used to handle errors
"""


class PanoptesAuthError(Exception):
    def __init__(self, message):
        super().__init__(message)
