# PAN0PTES
# STILL BEING CODED
Analyze your security groups and see any kinds of breaches.

### Automatic AWS Whitelist technique:
- VPC ranges
- Subnet ranges
- Instance Private IP's
- Instance Public IP's
- Elastic IP's

*OBS*: The Automatic AWS Whitelist feature can't neither whitelist public nor private IP's from EC2 Classic, so make sure that those instances have an Elastic IP attached and their security groups are pointing to the new Elastic IP attached instead of the default EC2 Classic default ones.
