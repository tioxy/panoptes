""" Panoptes - AWS - Exceptions

Collection of custom exceptions used to handle AWS errors
"""


class PanoptesAWSCreateSessionError(Exception):
    def __init__(self, message):
        super().__init__(message)
