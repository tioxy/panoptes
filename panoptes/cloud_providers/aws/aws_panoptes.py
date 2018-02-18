import boto3
import cloud_providers.aws


class AWSWhitelist:
    def __init__(self, aws_client):
        safe_ips = []
        safe_ips += self.get_vpc_ranges(aws_client)
        safe_ips += self.get_subnet_ranges(aws_client)
        safe_ips += self.get_running_instances_ips(aws_client)
        safe_ips += self.get_elastic_ips(aws_client)
        self.safe_ips = safe_ips

    def get_vpc_ranges(self, aws_client):
        return []

    def get_subnet_ranges(self, aws_client):
        return []

    def get_running_instances_ips(self, aws_client):
        return []

    def get_elastic_ips(self, aws_client):
        return []


def analyze_security_groups(aws_client, whitelist):
    if whitelist is None:
        whitelist = []

    aws_whitelist = AWSWhitelist(aws_client)
    whitelist += aws_whitelist.safe_ips

    print(whitelist)
    return None


if __name__ == "__main__":
    None
