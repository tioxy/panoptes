import boto3
import cloud_providers.aws
from pprint import pprint


class AWSWhitelist:
    def __init__(self, aws_client):
        self.safe_ips = list(set(self.get_vpc_ranges(aws_client)
                                 + self.get_subnet_ranges(aws_client)
                                 + self.get_vpc_instances_ips(aws_client)
                                 + self.get_elastic_ips(aws_client)))

    def get_vpc_ranges(self, aws_client):
        ec2 = aws_client.client('ec2')
        boto_vpcs = ec2.describe_vpcs()
        vpc_ranges = [
            vpc['CidrBlock'] for vpc in boto_vpcs['Vpcs']
        ]
        return vpc_ranges

    def get_subnet_ranges(self, aws_client):
        ec2 = aws_client.client('ec2')
        boto_subnets = ec2.describe_subnets()
        subnet_ranges = [
            subnet['CidrBlock'] for subnet in boto_subnets['Subnets']
        ]
        return subnet_ranges

    def get_vpc_instances_ips(self, aws_client):
        ec2 = aws_client.client('ec2')
        boto_instances = ec2.describe_instances()
        vpc_instances_ips = []
        for instance_json in boto_instances['Reservations']:
            for instance in instance_json['Instances']:
                for instance_net in instance['NetworkInterfaces']:
                    if 'Association' in instance_net.keys():
                        vpc_instances_ips.append(
                            instance_net['Association']['PublicIp'] + '/32'
                        )
                    if 'PrivateIpAddress' in instance_net.keys():
                        vpc_instances_ips.append(
                            instance_net['PrivateIpAddress'] + '/32'
                        )
                    if 'PrivateIpAddresses' in instance_net.keys():
                        for private_ip in instance_net['PrivateIpAddresses']:
                            if 'Association' in private_ip.keys():
                                vpc_instances_ips.append(
                                    private_ip['Association']['PublicIp'] + '/32'
                                )
                            if 'PrivateIpAddress' in private_ip.keys():
                                vpc_instances_ips.append(
                                    private_ip['PrivateIpAddress'] + '/32'
                                )
        return vpc_instances_ips

    def get_elastic_ips(self, aws_client):
        ec2 = aws_client.client('ec2')
        boto_elastic_ips = ec2.describe_addresses()
        elastic_ips = []
        for elastic_ip in boto_elastic_ips['Addresses']:
            if 'PrivateIpAddress' in elastic_ip.keys():
                elastic_ips.append(
                    elastic_ip['PrivateIpAddress'] + '/32'
                )
            elastic_ips.append(
                elastic_ip['PublicIp'] + '/32'
            )
        return elastic_ips


def analyze_security_groups(aws_client, whitelist_file=None):
    analyze_response_analysis = {
        "SecurityGroups": {
            "UnusedByInstances": [
                {
                    "Name": str,
                    "GroupId": str,
                    "Description": str,
                    "VpcId": str,
                }
            ],
            "UnsafeGroups": [
                {
                    "GroupName": str,
                    "GroupId": str,
                    "Description": str,
                    "UnsafePorts": [
                        {
                            "FromPort": str,
                            "ToPort": str,
                            "IpProtocol": str,
                            "CidrIp": str,
                        },
                    ]
                },
            ],
        }
    }

    if whitelist_file is None:
        whitelist_file = []

    aws_whitelist = AWSWhitelist(aws_client)
    whitelist = whitelist_file + aws_whitelist.safe_ips

    pprint(whitelist)
    return None


def remove_unused_security_groups():
    return None


def remove_unsafe_security_groups():
    return None


if __name__ == "__main__":
    None
