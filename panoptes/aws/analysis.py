""" Panoptes - AWS - Analysis

Responsible to the entire AWS analysis. Here the dynamic whitelist,
the logic behind unknown ingress rules and unused security groups are created.
"""

import panoptes.aws.whitelist


class AWSAnalysis:
    """
    Class used to gather data and format dictionaries to the final analysis
    """
    def __init__(self):
        pass

    def list_ec2_attached_secgroups(self, aws_client):
        """
        List security groups attached to EC2 instances
        """
        ec2_attached_groups = []
        ec2 = aws_client.client('ec2')
        boto_ec2_instances = ec2.describe_instances()
        for instance_obj in boto_ec2_instances['Reservations']:
            for instance in instance_obj['Instances']:
                for security_group in instance['SecurityGroups']:
                    ec2_attached_groups.append(
                        security_group['GroupId']
                    )
        return list(set(ec2_attached_groups))

    def list_rds_attached_secgroups(self, aws_client):
        """
        List security groups attached to RDS instances
        """
        rds_attached_groups = []
        rds = aws_client.client('rds')
        boto_rds_instances = rds.describe_db_instances()
        for db_instance_obj in boto_rds_instances['DBInstances']:
            for security_group in db_instance_obj['VpcSecurityGroups']:
                rds_attached_groups.append(
                    security_group['VpcSecurityGroupId']
                )
        return list(set(rds_attached_groups))

    def list_elb_attached_secgroups(self, aws_client):
        """
        List security groups attached to Elastic Load Balancers
        """
        elb_attached_groups = []
        elb = aws_client.client('elb')
        boto_load_balancers = elb.describe_load_balancers()
        for elb_obj in boto_load_balancers['LoadBalancerDescriptions']:
            for security_group in elb_obj['SecurityGroups']:
                elb_attached_groups.append(
                    security_group
                )
        return list(set(elb_attached_groups))

    def list_elbv2_attached_secgroups(self, aws_client):
        """
        List security groups attached to Elastic Load Balancers V2
        """
        elbv2_attached_groups = []
        elbv2 = aws_client.client('elbv2')
        boto_load_balancers = elbv2.describe_load_balancers()
        for elbv2_obj in boto_load_balancers['LoadBalancers']:
            if 'SecurityGroups' in elbv2_obj.keys():
                for security_group in elbv2_obj['SecurityGroups']:
                    elbv2_attached_groups.append(
                        security_group
                    )
        return list(set(elbv2_attached_groups))

    def list_lambda_attached_secgroups(self, aws_client):
        """
        List security groups attached to Lambda functions
        """
        lambda_attached_groups = []
        lambda_aws = aws_client.client('lambda')
        boto_lambda_aws = lambda_aws.list_functions()
        for lambda_obj in boto_lambda_aws['Functions']:
            if 'VpcConfig' in lambda_obj.keys():
                for security_group in (
                        lambda_obj['VpcConfig']['SecurityGroupIds']
                ):
                    lambda_attached_groups.append(
                        security_group
                    )
        return list(set(lambda_attached_groups))

    def list_elasticache_attached_secgroups(self, aws_client):
        """
        List security groups attached to ElastiCache
        """
        elasticache_attached_groups = []
        ecache = aws_client.client('elasticache')

        boto_elasticache = ecache.describe_cache_clusters()
        for elasticache_obj in boto_elasticache['CacheClusters']:
            for security_group in elasticache_obj['CacheSecurityGroups']:
                elasticache_attached_groups.append(
                    security_group['CacheSecurityGroupName']
                )
            if 'SecurityGroups' in elasticache_obj.keys():
                for security_group in elasticache_obj['SecurityGroups']:
                    elasticache_attached_groups.append(
                        security_group['SecurityGroupId']
                    )
        try:
            boto_elasticache = ecache.describe_cache_security_groups()
            for elasticache_obj in boto_elasticache['CacheSecurityGroups']:
                for security_group in elasticache_obj['EC2SecurityGroups']:
                    elasticache_attached_groups.append(
                        security_group['EC2SecurityGroupName']
                    )
        except Exception as e:
            pass
        return list(set(elasticache_attached_groups))

    def list_ecs_attached_secgroups(self, aws_client):
        """
        List security groups attached to ECS Services
        """
        ecs_attached_groups = []
        ecs = aws_client.client('ecs')

        ecs_clusters = [
            ecs_clusters for ecs_clusters in ecs.list_clusters()['clusterArns']
        ]

        ecs_cluster_services = []
        for cluster in ecs_clusters:
            boto_services = ecs.list_services(cluster=cluster)
            if boto_services['serviceArns']:
                ecs_cluster_services.append(
                    {
                        'ClusterName': cluster,
                        'Services': boto_services['serviceArns'],
                    }
                )

        ECS_SERVICE_API_LIMIT = 10
        for cluster in ecs_cluster_services:
            for i in range(0, len(cluster['Services']), ECS_SERVICE_API_LIMIT):
                boto_ecs = ecs.describe_services(
                    cluster=cluster['ClusterName'],
                    services=cluster['Services'][i:i+ECS_SERVICE_API_LIMIT]
                )
                for ecs_obj in boto_ecs['services']:
                    if 'networkConfiguration' in ecs_obj.keys():
                        for security_group in (
                                ecs_obj['networkConfiguration']
                                       ['awsvpcConfiguration']
                                       ['securityGroups']
                        ):
                            ecs_attached_groups.append(
                                security_group
                            )
        return list(set(ecs_attached_groups))

    def get_all_security_groups(self, aws_client):
        """
        Get all security groups created
        """
        ec2 = aws_client.client('ec2')
        all_security_groups = ec2.describe_security_groups()['SecurityGroups']
        return all_security_groups

    def generate_unused_secgroup_entry(self, security_group):
        """
        Generates a dictionary from an unused security group to the analysis
        response
        """
        if 'VpcId' not in security_group.keys():
            vpc_id = 'no-vpc'
        else:
            vpc_id = security_group['VpcId']
        unused_group = {
            'GroupName': security_group['GroupName'],
            'GroupId': security_group['GroupId'],
            'Description': security_group['Description'],
            'VpcId': vpc_id,
        }
        return unused_group

    def generate_unsafe_secgroup_entry(self, security_group,
                                             unsafe_ingress_entries):
        """
        Generates a dictionary from an unsafe security group, receiving all
        unsafe ingress entries related to this security group to the analysis
        response
        """
        unsafe_group = {
            "GroupName": security_group['GroupName'],
            "GroupId": security_group['GroupId'],
            "Description": security_group['Description'],
            "UnsafePorts": unsafe_ingress_entries,
        }
        return unsafe_group

    def generate_unsafe_ingress_entry(self, ingress_entry, unsafe_ip):
        """
        Generates a dictionary from an unsafe ingress entry to the analysis
        response
        """
        unsafe_ingress = {
            "IpProtocol": ingress_entry["IpProtocol"],
            "CidrIp": unsafe_ip,
        }
        if "FromPort" in ingress_entry.keys():
            unsafe_ingress["FromPort"] = ingress_entry["FromPort"]
        if "ToPort" in ingress_entry.keys():
            unsafe_ingress["ToPort"] = ingress_entry["ToPort"]
        return unsafe_ingress


def analyze_security_groups(aws_client, whitelist=[]):
    """
    The main analysis function

    Parameters:
        - aws_client:
            Type: boto3.Session
            Description: Client object from cloud_authentication modules

        - whitelist:
            Type: list
            Description: List of whitelisted CIDR from optional input file

    DesiredReturn:
            "SecurityGroups": {
                "UnusedGroups": [
                    {
                        "GroupName": str,
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
                                "FromPort": int,
                                "ToPort": int,
                                "IpProtocol": str,
                                "CidrIp": str,
                            },
                        ]
                    },
                ],
            }
    """
    response = {
        'SecurityGroups': {
            'UnusedGroups': [],
            'UnsafeGroups': [],
        }
    }

    whitelist += panoptes.aws.whitelist.get_safe_ips(aws_client)

    analysis = AWSAnalysis()
    services_attachedgroups = {
        "ec2": analysis.list_ec2_attached_secgroups(aws_client),
        "rds": analysis.list_rds_attached_secgroups(aws_client),
        "elb": analysis.list_elb_attached_secgroups(aws_client),
        "elbv2": analysis.list_elbv2_attached_secgroups(aws_client),
        "lambda": analysis.list_lambda_attached_secgroups(aws_client),
        "ec": analysis.list_elasticache_attached_secgroups(aws_client),
        "ecs": analysis.list_ecs_attached_secgroups(aws_client),
    }

    all_attached_groups = []
    for service, attached_groups in services_attachedgroups.items():
        all_attached_groups += attached_groups

    all_security_groups = analysis.get_all_security_groups(aws_client)
    for security_group in all_security_groups:
        # Validating if group is unused
        if (
                security_group['GroupName'] not in all_attached_groups and
                security_group['GroupId'] not in all_attached_groups
        ):
            response['SecurityGroups']['UnusedGroups'].append(
                analysis.generate_unused_secgroup_entry(
                    security_group=security_group
                )
            )

        # Validating if group is unsafe
        unsafe_ingress_entries = []
        for ingress_entry in security_group["IpPermissions"]:
            for allowed_ip in ingress_entry["IpRanges"]:
                if allowed_ip['CidrIp'] not in whitelist:
                    unsafe_ingress_entries.append(
                        analysis.generate_unsafe_ingress_entry(
                            ingress_entry=ingress_entry,
                            unsafe_ip=allowed_ip['CidrIp'],
                        )
                    )
        if unsafe_ingress_entries:
            response['SecurityGroups']['UnsafeGroups'].append(
                analysis.generate_unsafe_secgroup_entry(
                    security_group=security_group,
                    unsafe_ingress_entries=unsafe_ingress_entries,
                )
            )
    return response


if __name__ == "__main__":
    pass
