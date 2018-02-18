import boto3
import cloud_providers.aws
from pprint import pprint


class AWSWhitelist:
    def __init__(self, aws_client):
        safe_ips = []
        safe_ips += self.get_vpc_ranges(aws_client)
        safe_ips += self.get_subnet_ranges(aws_client)
        safe_ips += self.get_instances_ips(aws_client)
        safe_ips += self.get_elastic_ips(aws_client)
        self.safe_ips = safe_ips

    def get_vpc_ranges(self, aws_client):
        ec2 = aws_client.client('ec2')
        boto_vpcs = ec2.describe_vpcs()
        vpc_ranges = [vpc['CidrBlock'] for vpc in boto_vpcs['Vpcs']]
        return vpc_ranges

    def get_subnet_ranges(self, aws_client):
        ec2 = aws_client.client('ec2')
        boto_subnets = ec2.describe_subnets()
        subnet_ranges = [
            subnet['CidrBlock'] for subnet in boto_subnets['Subnets']
        ]
        return subnet_ranges

    def get_instances_ips(self, aws_client):
        ec2 = aws_client.client('ec2')
        boto_instances = ec2.describe_instances()
        instances_ips = []
        for instance in boto_instances['Reservations']:
            instance_network = instance['Instances'][0]['NetworkInterfaces'][0]
            for net_interface in instance_network['PrivateIpAddresses']:
                instances_ips.append(
                    net_interface['PrivateIpAddress']
                )
                if 'Association' in net_interface.keys():
                    instances_ips.append(
                        net_interface['Association']['PublicIp']
                    )
        return instances_ips

    def get_elastic_ips(self, aws_client):
        return []


def analyze_security_groups(aws_client, whitelist):
    if whitelist is None:
        whitelist = []

    aws_whitelist = AWSWhitelist(aws_client)
    whitelist += aws_whitelist.safe_ips

    pprint(whitelist)
    return None


if __name__ == "__main__":
    None
