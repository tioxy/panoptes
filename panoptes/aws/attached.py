""" Panoptes - AWS - Attached

Functions responsible for listing and grouping all attached security
groups within AWS resources.
"""

import concurrent.futures
import boto3
import panoptes


def list_all_attached_secgroups(session: boto3.session.Session) -> list:
    """
    Lists and groups all attached security groups within AWS resources
    """
    all_attached_groups = []
    boto_clients = panoptes.aws.authentication.get_boto_clients(session)
    
    services_with_security_groups = [
        (list_ec2_attached_secgroups, boto_clients['ec2']),
        (list_rds_attached_secgroups, boto_clients['rds']),
        (list_elb_attached_secgroups, boto_clients['elb']),
        (list_elbv2_attached_secgroups, boto_clients['elbv2']),
        (list_lambda_attached_secgroups, boto_clients['lambda']),
        (list_elasticache_attached_secgroups, boto_clients['elasticache']),
        (list_ecs_attached_secgroups, boto_clients['ecs']),
    ]

    with concurrent.futures.ThreadPoolExecutor() as executor:
        running_workers = []
        for list_attached_function in services_with_security_groups:
            running_workers.append(executor.submit(*list_attached_function))

        for future in concurrent.futures.as_completed(running_workers):
            all_attached_groups += future.result()
    return all_attached_groups


def list_ec2_attached_secgroups(ec2) -> list:
    """
    List security groups attached to EC2 instances
    """
    ec2_attached_groups = []
    boto_ec2_instances = ec2.describe_instances()
    for instance_obj in boto_ec2_instances['Reservations']:
        for instance in instance_obj['Instances']:
            for security_group in instance['SecurityGroups']:
                ec2_attached_groups.append(
                    security_group['GroupId']
                )
    return ec2_attached_groups


def list_rds_attached_secgroups(rds) -> list:
    """
    List security groups attached to RDS instances
    """
    rds_attached_groups = []
    boto_rds_instances = rds.describe_db_instances()
    for db_instance_obj in boto_rds_instances['DBInstances']:
        for security_group in db_instance_obj['VpcSecurityGroups']:
            rds_attached_groups.append(
                security_group['VpcSecurityGroupId']
            )
    return rds_attached_groups


def list_elb_attached_secgroups(elb) -> list:
    """
    List security groups attached to Elastic Load Balancers
    """
    elb_attached_groups = []
    boto_load_balancers = elb.describe_load_balancers()
    for elb_obj in boto_load_balancers['LoadBalancerDescriptions']:
        for security_group in elb_obj['SecurityGroups']:
            elb_attached_groups.append(
                security_group
            )
    return elb_attached_groups


def list_elbv2_attached_secgroups(elbv2) -> list:
    """
    List security groups attached to Elastic Load Balancers V2
    """
    elbv2_attached_groups = []
    boto_load_balancers = elbv2.describe_load_balancers()
    for elbv2_obj in boto_load_balancers['LoadBalancers']:
        if 'SecurityGroups' in elbv2_obj:
            for security_group in elbv2_obj['SecurityGroups']:
                elbv2_attached_groups.append(
                    security_group
                )
    return elbv2_attached_groups


def list_lambda_attached_secgroups(lambda_aws) -> list:
    """
    List security groups attached to Lambda functions
    """
    lambda_attached_groups = []
    boto_lambda = lambda_aws.list_functions()
    for lambda_obj in boto_lambda['Functions']:
        if 'VpcConfig' in lambda_obj:
            for security_group in (
                    lambda_obj['VpcConfig']['SecurityGroupIds']
            ):
                lambda_attached_groups.append(
                    security_group
                )
    return lambda_attached_groups


def list_elasticache_attached_secgroups(ecache) -> list:
    """
    List security groups attached to ElastiCache
    """
    elasticache_attached_groups = []
    boto_elasticache = ecache.describe_cache_clusters()
    for elasticache_obj in boto_elasticache['CacheClusters']:
        for security_group in elasticache_obj['CacheSecurityGroups']:
            elasticache_attached_groups.append(
                security_group['CacheSecurityGroupName']
            )
        if 'SecurityGroups' in elasticache_obj:
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
    return elasticache_attached_groups


def list_ecs_attached_secgroups(ecs) -> list:
    """
    List security groups attached to ECS Services
    """
    ecs_attached_groups = []

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
                if 'networkConfiguration' in ecs_obj:
                    for security_group in (
                        ecs_obj['networkConfiguration']['awsvpcConfiguration']['securityGroups']
                    ):
                        ecs_attached_groups.append(
                            security_group
                        )
    return ecs_attached_groups
