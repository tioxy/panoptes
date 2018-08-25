""" Panoptes - AWS - Authentication

Using AWS best practices forcing the user to write Named Profiles instead of
direct IAM credentials through CLI.
"""

import boto3
import panoptes.generic.exceptions


def get_client(region, profile=None, session_token=None):
    """
    Generates a Boto3 session from named profile and region inputs
    """
    aws_client = boto3.Session(
        profile_name=profile,
        region_name=region,
        aws_session_token=session_token,
    )

    if aws_client.get_credentials():
        return aws_client
    else:
        raise panoptes.generic.exceptions.PanoptesAuthError(
            "Panoptes could not authenticate to AWS. "
            "Check if your credentials exist and work."
        )


if __name__ == "__main__":
    pass
