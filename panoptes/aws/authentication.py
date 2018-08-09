""" Panoptes - AWS - Authentication

Using AWS best practices forcing the user to write Named Profiles instead of
direct IAM credentials through CLI.
"""

import boto3


def get_client(region, profile):
    """
    Generates a Boto3 session from named profile and region inputs
    """
    try:
        client = boto3.Session(
            profile_name=profile,
            region_name=region,
        )
    except Exception:
        client = None
        error = (
            "ERROR - Panoptes could not authenticate to AWS, "
            "check if your credentials exist and work."
        )
        print(error)
        # Log variable error here
    return client


if __name__ == "__main__":
    pass
