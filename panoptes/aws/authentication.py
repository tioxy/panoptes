""" Panoptes - AWS - Authentication

Using AWS best practices forcing the user to write Named Profiles instead of
direct IAM credentials through CLI.
"""

import boto3
import panoptes


def create_session(
        region: str,
        profile: str = None,
        session_token: str = None) -> boto3.session.Session:
    """
    Generates a Boto3 session from named profile and region inputs
    """
    session = boto3.Session(
        profile_name=profile,
        region_name=region,
        aws_session_token=session_token,
    )
    if not session.get_credentials():
        raise panoptes.aws.exceptions.PanoptesAWSCreateSessionError(
            "Panoptes could not authenticate to AWS. "
            "Check if your credentials exist and work."
        )
    return session


def get_session_info(session: boto3.session.Session) -> str:
    """
    Get ARN from the current session
    """
    return session.client('sts').get_caller_identity()['Arn']


def get_boto_clients(session: boto3.session.Session) -> dict:
    """
    Receives the session, and return all Panoptes used Boto3 Clients
    """
    return {
        'ec2': session.client('ec2'),
        'rds': session.client('rds'),
        'elb': session.client('elb'),
        'elbv2': session.client('elbv2'),
        'lambda': session.client('lambda'),
        'elasticache': session.client('elasticache'),
        'ecs': session.client('ecs'),
    }


if __name__ == "__main__":
    pass
