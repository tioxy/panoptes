import boto3
import cloud_providers.aws
from pprint import pprint


class AWSWhitelist:
    def __init__(self, aws_client):
        safe_ips = []
        safe_ips += self.get_vpc_ranges(aws_client)
        safe_ips += self.get_subnet_ranges(aws_client)
        safe_ips += self.get_vpc_instances_ips(aws_client)
        safe_ips += self.get_elastic_ips(aws_client)
        self.safe_ips = safe_ips

    def get_vpc_ranges(self, aws_client):
        ec2 = aws_client.client('ec2')
        boto_vpcs = ec2.describe_vpcs()
        vpc_ranges = [
            vpc['CidrBlock'] for vpc in boto_vpcs['Vpcs']
        ]
        vpc_ranges = list(set(vpc_ranges))
        return vpc_ranges

    def get_subnet_ranges(self, aws_client):
        ec2 = aws_client.client('ec2')
        boto_subnets = ec2.describe_subnets()
        subnet_ranges = [
            subnet['CidrBlock'] for subnet in boto_subnets['Subnets']
        ]
        subnet_ranges = list(set(subnet_ranges))
        return subnet_ranges

    def get_vpc_instances_ips(self, aws_client):
        ec2 = aws_client.client('ec2')
        boto_instances = ec2.describe_instances()
        vpc_instances_ips = []
        for instance_json in boto_instances['Reservations']:
            for instance in instance_json['Instances']:
                for instance_network in instance['NetworkInterfaces']:
                    if 'Association' in instance_network.keys():
                        vpc_instances_ips.append(instance_network['Association']['PublicIp'] + '/32')

                    if 'PrivateIpAddress' in instance_network.keys():
                        vpc_instances_ips.append(instance_network['PrivateIpAddress'] + '/32')

                    if 'PrivateIpAddresses' in instance_network.keys():
                        for private_ip in instance_network['PrivateIpAddresses']:
                            if 'Association' in private_ip.keys():
                                vpc_instances_ips.append(private_ip['Association']['PublicIp'] + '/32')
                            if 'PrivateIpAddress' in private_ip.keys():
                                vpc_instances_ips.append(private_ip['PrivateIpAddress'] + '/32')
        vpc_instances_ips = list(set(vpc_instances_ips))
        return vpc_instances_ips

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
