""" Panoptes - AWS - Whitelist

Generates the dynamic whitelist of AWS Resources, considering them not harmful
and known resources
"""

import concurrent.futures
import boto3
import panoptes


def list_all_safe_ips(session: boto3.session.Session) -> list:
    """
    Function responsible for aggregating all methods and removing duplicates
    """
    all_safe_ips = []
    boto_clients = panoptes.aws.authentication.get_boto_clients(session)
    resources_to_whitelist = [
        (get_vpc_ranges, boto_clients['ec2']),
        (get_subnet_ranges, boto_clients['ec2']),
        (get_vpc_instance_ips, boto_clients['ec2']),
        (get_elastic_ips, boto_clients['ec2']),
    ]
    with concurrent.futures.ThreadPoolExecutor() as executor:
        running_workers = []
        for whitelist_function in resources_to_whitelist:
            running_workers.append(executor.submit(*whitelist_function))

        for future in concurrent.futures.as_completed(running_workers):
            all_safe_ips += future.result()
    return all_safe_ips


def get_vpc_ranges(ec2) -> list:
    """
    List VPCs CIDR ranges in the account
    """
    boto_vpcs = ec2.describe_vpcs()
    vpc_ranges = [
        vpc['CidrBlock'] for vpc in boto_vpcs['Vpcs']
    ]
    return vpc_ranges


def get_subnet_ranges(ec2) -> list:
    """
    List Subnets CIDR ranges in the account
    """
    boto_subnets = ec2.describe_subnets()
    subnet_ranges = [
        subnet['CidrBlock'] for subnet in boto_subnets['Subnets']
    ]
    return subnet_ranges


def get_vpc_instance_ips(ec2) -> list:
    """
    List Public and Private IPs from EC2 instances inside a VPC in the
    account
    """
    boto_instances = ec2.describe_instances()
    vpc_instances_ips = []
    for instance_obj in boto_instances['Reservations']:
        for instance in instance_obj['Instances']:
            for instance_net in instance['NetworkInterfaces']:
                if 'Association' in instance_net:
                    vpc_instances_ips.append(
                        instance_net['Association']['PublicIp'] + '/32'
                    )
                if 'PrivateIpAddress' in instance_net:
                    vpc_instances_ips.append(
                        instance_net['PrivateIpAddress'] + '/32'
                    )
                if 'PrivateIpAddresses' in instance_net:
                    for priv_ip in instance_net['PrivateIpAddresses']:
                        if 'Association' in priv_ip:
                            vpc_instances_ips.append(
                                priv_ip['Association']['PublicIp'] + '/32'
                            )
                        if 'PrivateIpAddress' in priv_ip:
                            vpc_instances_ips.append(
                                priv_ip['PrivateIpAddress'] + '/32'
                            )
    return vpc_instances_ips


def get_elastic_ips(ec2) -> list:
    """
    List all Elastic IPs reserved in the account
    """
    boto_elastic_ips = ec2.describe_addresses()
    elastic_ips = []
    for elastic_ip in boto_elastic_ips['Addresses']:
        if 'PrivateIpAddress' in elastic_ip:
            elastic_ips.append(
                elastic_ip['PrivateIpAddress'] + '/32'
            )
        elastic_ips.append(
            elastic_ip['PublicIp'] + '/32'
        )
    return elastic_ips


if __name__ == "__main__":
    pass
