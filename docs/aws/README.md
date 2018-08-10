# Panoptes - AWS

- [Information](README.md#info)
    - [Dynamic Whitelist](README.md#info-dynamic-whitelist)
    - [Limitations](README.md#info-limitations)
- [Commands](README.md#comm)
    - [panoptes aws analyze](README.md#comm-analyze)
- [Panoptes for Developers](README.md#integrating)


<br>

----

## [Information](#info)
### [Dynamic Whitelist](#info-dynamic-whitelist)
Panoptes generates automatically a list of IP's which it does not consider harmful from the desired cloud provider. Inside AWS, it generates from:
- VPC ranges
- Subnet ranges
- Private IPs from EC2 VPC Instances
- Public IPs from EC2 VPC Instances
- Elastic IPs

<br>

### [Limitations](#info-limitations)
The Automatic AWS Whitelist feature can't whitelist *public* and *private* IP's from **EC2 Classic**, so make sure that those instances have an *Elastic IP* attached and their security groups are pointing to the new *Elastic IP* attached instead of the default EC2 Classic ones.

<br>

----

## [Commands](#comm)

### [panoptes aws analyze](#comm-analyze)
Generate the analysis output
##### Options
- **```--region```** : (Required) AWS Region to list the security groups


- **```--profile```** : (Default: ```default```) AWS CLI configured profile which will be used


- **```--output```** : (Default: ```human```) Which kind of output you want the analysis.
    - ```human``` : Colorful human ouput
    - ```json``` : JSON prettified output
    - ```human``` : YAML prettified output


- **```--whitelist```** : Path to [whitelist](../whitelist_sample.txt) with declared safe IPs and CIDR

#### Requirements
You need specific IAM permissions to analyze without headaches. There are some ways to give Panoptes permission to analyze content:

**```The Fast Way```** : Attach the policy ```ReadOnlyAccess``` to the user/role

**```The "Compliance" Way```** : Create an IAM Policy from [this .json file](aws_analyze_policy.json) and attach it to the user/role


##### Example
```sh
panoptes aws analyze --region us-east-1 --profile my-aws-profile --output yml --whitelist /path/to/my/whitelist.txt
```
