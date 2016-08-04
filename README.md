# ThreatPrep
Configuration and Preparedness Auditing for AWS Accounts

## Installing

```
pip install git+ssh://github.com/ThreatResponse/ThreatPrep@master
```

## Import from module

```
from awsthreatresponse.checker import Checker
c = Checker()
```


## How to use

```
$ python
Python 2.7.6 (default, Jun 22 2015, 17:58:13)
[GCC 4.8.2] on linux2
Type "help", "copyright", "credits" or "license" for more information.

>>> import checker
>>> c = checker.Checker()
>>> c.run_checks()
>>> len(c.results)
24
>>> print c.results[0]
FAIL     VPCFlowLogCheck vpc-8a5bbfee Flow log has DeliverLogsErrorMessage: Access error
>>> check_test =  c.results[0]
>>> check_test.get_check_name()
'VPCFlowLogCheck'
>>> check_test.get_description()
'Checks if a VPC has flow logging enabled and if the logging occurs without error.'
>>> c.results[2]
<s3_checks.S3CheckCollection object at 0x7f071484b5d0>
>>> print c.results[2]
FAIL     S3CheckCollection amcctest45 3/4 PASS
>>> c.results[2].subchecks
[<s3_checks.S3VersioningEnabledCheck object at 0x7f071484b250>, <s3_checks.S3LoggingEnabledCheck object at 0x7f071484b210>, <s3_checks.S3OpenPermissionCheck object at 0x7f071481a950>, <s3_checks.S3OpenPermissionCheck object at 0x7f071481af10>]
>>> for subcheck in c.results[2].subchecks:
...   print subcheck
...
PASS     S3VersioningEnabledCheck amcctest45 S3 versioning is enabled for this bucket
PASS     S3LoggingEnabledCheck amcctest45 S3 logging is enabled for this bucket
FAIL     S3OpenPermissionCheck amcctest45 S3 permission READ is granted to AllUsers
PASS     S3OpenPermissionCheck amcctest45 S3 permission "WRITE" is not granted to AllUsers

```
