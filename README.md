# PANOPTES

Panoptes is an automatic security group analyzer focused on reducing the amount of toiling. Mainly focused on AWS, built to be extensible in the future and support the big cloud providers out there.

![Panoptes Usage](https://s3.amazonaws.com/tioxy.github/panoptes/sample.gif)

<br>

## [Prerequisites](#prerequisites)
-----
#### For AWS usage
- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/installing.html) installed and configured with your IAM credentials (if you want more customization use [Named Profiles](https://docs.aws.amazon.com/cli/latest/userguide/cli-multiple-profiles.html))

<br>

## [Installation](#installation)
-----
Get the latest version of the package from your terminal with *pip*:
```bash
pip install panoptes --upgrade
```

<br>

## [Getting Started](#getting-started)

-----
If you want to see the available options:
```bash
panoptesctl aws analyze --help
```

Generate an AWS analysis with human readable output:
```bash
panoptesctl aws analyze --region <YOUR_REGION_CODE>
```

Generate an AWS analysis with an YML output and a Named Profile from AWS CLI:
```bash
panoptesctl aws analyze --region <YOUR_REGION_CODE> --profile <YOUR_PROFILE> --output yml
```
*Check out [AWS Regions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html) to see available region codes*


<br>

## [Whitelisting](#whitelisting)
-----

### Manually
If you wish to whitelist IPs, not letting the analysis mark them as **Unsafe**, you can define a sample file with the desired IPs and CIDRs, like the following one:

<br>

**your_whitelist.txt**
```
111.111.111.111/32
123.123.123.123/32
```
And then run the analysis with the parameter *--whitelist*:
```
panoptesctl aws analyze --region <YOUR_REGION_CODE> --output yml --whitelist /PATH/TO/your_whitelist.txt
```

<br>

### Automatically
Panoptes generates automatically a list of IPs which it does not consider harmful from the desired cloud provider.

<br>

#### AWS autogenerated
- VPC ranges
- Subnet ranges
- Private IPs from EC2 VPC Instances
- Public IPs from EC2 VPC Instances
- Elastic IPs

<br>

## [Limitations](#limitations)
----
The Automatic AWS Whitelist feature can't whitelist *public* and *private* IP's from **EC2 Classic**, so make sure that those instances have an *Elastic IP* attached and their security groups are pointing to the new *Elastic IP* attached instead of the default EC2 Classic ones.
