# ThreatPrep
Configuration and Preparedness Auditing for AWS Accounts

## Installing
You can use pip to install the awsthreatprep module from this git repository by using the command.

```
pip install git+git://github.com/ThreatResponse/ThreatPrep@master
```

### Installation example with docker
Below we show a working installation procedure in a minimized [python docker container](https://hub.docker.com/_/python/).

```
$ docker run -it -e AWS_ACCESS_KEY_ID=AWSACCESSKEYHERE -e AWS_SECRET_ACCESS_KEY=AWSSECRETACCESSKEYHERE python:2 bash

root@3009:/# pip install git+git://github.com/ThreatResponse/ThreatPrep@master
Collecting git+git://github.com/ThreatResponse/ThreatPrep@master
  Cloning git://github.com/ThreatResponse/ThreatPrep (to master) to /tmp/pip-qwKkjA-build
Collecting boto3 (from awsthreatprep==0.1.1)
  Downloading boto3-1.4.0-py2.py3-none-any.whl (117kB)
    100% |████████████████████████████████| 122kB 1.2MB/s
Collecting jmespath<1.0.0,>=0.7.1 (from boto3->awsthreatprep==0.1.1)
  Downloading jmespath-0.9.0-py2.py3-none-any.whl
Collecting s3transfer<0.2.0,>=0.1.0 (from boto3->awsthreatprep==0.1.1)
  Downloading s3transfer-0.1.2-py2.py3-none-any.whl (49kB)
    100% |████████████████████████████████| 51kB 1.1MB/s
Collecting botocore<1.5.0,>=1.4.1 (from boto3->awsthreatprep==0.1.1)
  Downloading botocore-1.4.49-py2.py3-none-any.whl (2.5MB)
    100% |████████████████████████████████| 2.5MB 641kB/s
Collecting futures<4.0.0,>=2.2.0; python_version == "2.6" or python_version == "2.7" (from s3transfer<0.2.0,>=0.1.0->boto3->awsthreatprep==0.1.1)
  Downloading futures-3.0.5-py2-none-any.whl
Collecting docutils>=0.10 (from botocore<1.5.0,>=1.4.1->boto3->awsthreatprep==0.1.1)
  Downloading docutils-0.12.tar.gz (1.6MB)
    100% |████████████████████████████████| 1.6MB 1.0MB/s
Collecting python-dateutil<3.0.0,>=2.1 (from botocore<1.5.0,>=1.4.1->boto3->awsthreatprep==0.1.1)
  Downloading python_dateutil-2.5.3-py2.py3-none-any.whl (201kB)
    100% |████████████████████████████████| 204kB 1.9MB/s
Collecting six>=1.5 (from python-dateutil<3.0.0,>=2.1->botocore<1.5.0,>=1.4.1->boto3->awsthreatprep==0.1.1)
  Downloading six-1.10.0-py2.py3-none-any.whl
Building wheels for collected packages: docutils
  Running setup.py bdist_wheel for docutils ... done
  Stored in directory: /root/.cache/pip/wheels/db/de/bd/b99b1e12d321fbc950766c58894c6576b1a73ae3131b29a151
Successfully built docutils
Installing collected packages: jmespath, futures, docutils, six, python-dateutil, botocore, s3transfer, boto3, awsthreatprep
  Running setup.py install for awsthreatprep ... done
Successfully installed awsthreatprep-0.1.1 boto3-1.4.0 botocore-1.4.49 docutils-0.12 futures-3.0.5 jmespath-0.9.0 python-dateutil-2.5.3 s3transfer-0.1.2 six-1.10.0

root@3009:/# python -m awsthreatprep.checker > output.json

root@3009:/# head -n 30 output.json
{
    "S3": {
        "generals": [],
        "collections": [
            {
                "category": "S3",
                "status": "FAIL",
                "reason": "",
                "resource_name": "threatpreptest45",
                "description": "Checks for basic S3 security settings.",
                "check_name": "S3CheckCollection",
                "subchecks": [
                    {
                        "category": "S3",
                        "status": "PASS",
                        "reason": "S3 versioning is enabled for this bucket",
                        "resource_name": "threatpreptest45",
                        "description": "Checks if versioning is enabled on a S3 bucket.",
                        "check_name": "S3VersioningEnabledCheck",
                        "subchecks": []
                    },
                    {
                        "category": "S3",
                        "status": "PASS",
                        "reason": "S3 logging is enabled for this bucket",
                        "resource_name": "threatpreptest45",
                        "description": "Checks if logging is enabled on a S3 bucket.",
                        "check_name": "S3LoggingEnabledCheck",
                        "subchecks": []
                    },

```

## Import from module

```
from awsthreatprep.checker import Checker
c = Checker()
```


## How to use

```
root@3009a5bc9817:/# python
Python 2.7.12 (default, Aug 26 2016, 20:43:47)
[GCC 4.9.2] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import pprint
>>> from awsthreatprep.checker import Checker
>>> c = Checker()
>>> c.run_checks()
>>> c.results_dict.keys()
['S3', 'IAM', 'CloudWatch', 'VPC', 'CloudTrail']
>>> c.results_dict['S3'].keys()
['generals', 'collections']
>>> pprint.pprint(c.results_dict['S3']['collections'][0])
{'category': 'S3',
 'check_name': 'S3CheckCollection',
 'description': 'Checks for basic S3 security settings.',
 'reason': '',
 'resource_name': 'threatpreptest45',
 'status': 'FAIL',
 'subchecks': [{'category': 'S3',
                'check_name': 'S3VersioningEnabledCheck',
                'description': 'Checks if versioning is enabled on a S3 bucket.',
                'reason': 'S3 versioning is enabled for this bucket',
                'resource_name': 'threatpreptest45',
                'status': 'PASS',
                'subchecks': []},
               {'category': 'S3',
                'check_name': 'S3LoggingEnabledCheck',
                'description': 'Checks if logging is enabled on a S3 bucket.',
                'reason': 'S3 logging is enabled for this bucket',
                'resource_name': 'threatpreptest45',
                'status': 'PASS',
                'subchecks': []},
               {'category': 'S3',
                'check_name': 'S3OpenPermissionCheck',
                'description': 'Checks for a permission open to the world on a S3 bucket.',
                'reason': 'S3 permission READ is granted to AllUsers',
                'resource_name': 'threatpreptest45',
                'status': 'FAIL',
                'subchecks': []},
               {'category': 'S3',
                'check_name': 'S3OpenPermissionCheck',
                'description': 'Checks for a permission open to the world on a S3 bucket.',
                'reason': 'S3 permission "WRITE" is not granted to AllUsers',
                'resource_name': 'threatpreptest45',
                'status': 'PASS',
                'subchecks': []}]}
>>>
```
### IAM Policy

The following policy can be used to run ThreatPrep. It is a reduced version of the ReadOnlyAccess policy (arn:aws:iam::aws:policy/ReadOnlyAccess). 

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "cloudwatch:DescribeAlarms",
                "ec2:DescribeRegions",
                "ec2:DescribeVpcs",
                "ec2:DescribeFlowLogs",
                "iam:GenerateCredentialReport",
                "iam:GetCredentialReport",
                "iam:ListRoles",
                "iam:ListAttachedUserPolicies",
                "s3:GetBucketVersioning",
                "s3:GetBucketLogging",
                "s3:GetBucketAcl",
                "s3:ListAllMyBuckets",
                "s3:ListBucket"
            ],
            "Resource": "*"
        }
    ]
}
```


### Organization of results

After running the `run_checks` method, the results are organized in the `results_dict` property of the Checker object. There are four keys in the `results_dict` dictionary: `S3`, `IAM`, `CloudWatch`, `VPC`, `CloudTrail`. Each of these keys represents an AWS service or feature where checks are run.

These groups are further broken down into two more categories: `generals` or `collections`. If a check is a general check, it is looking for something that is not specific to a particular resource, such as determining if any CloudTrail trails exist. If a check is a collections check, it is running (usually multiple) checks on a single resource.  

In the example above, the S3 bucket `threatpreptest45` is the resource being checked by the `S3CheckCollection`, the first result in the `S3` group of `collections` checks. The status of a `CheckCollection` is `PASS` if all of the subchecks are `PASS`, otherwise, it is `FAIL`.
