import argparse
import boto3
import botocore
import csv
import datetime
import dateutil
import StringIO
import time
import os

import cloudtrail_checks
import s3_checks
import iam_checks
import misc_checks
import collections
import json


class Checker(object):
    def __init__(self, region='us-east-1'):
        self.check_categories = ['S3','IAM', 'VPC', 'CloudWatch', 'CloudTrail']
        self.ec2 = boto3.resource("ec2", region_name=region)
        self.ec2_client = boto3.client("ec2", region_name=region)
        self.cloudwatch = boto3.resource("cloudwatch", region_name=region)
        self.cloudwatch_client = boto3.client("cloudwatch", region_name=region)
        self.cloudtrail_client = boto3.client('cloudtrail', region_name=region)
        self.iam = boto3.resource("iam", region_name=region)
        self.iam_client = boto3.client("iam", region_name=region)
        self.s3 = boto3.resource("s3", region_name=region)

        self.results = []
        self.results_dict = {}

    def append_general(self, check):
        self.results.append(check)
        if check.category not in self.results_dict:
            self.results_dict[check.category] =dict(generals=[], collections=[])
        self.results_dict[check.category]['generals'].append(check.to_dict())

    def append_collection(self, check):
        self.results.append(check)
        if check.category not in self.results_dict:
            self.results_dict[check.category] =dict(generals=[], collections=[])
        self.results_dict[check.category]['collections'].append(check.to_dict())

    def run_checks(self, check_categories=None):
        check_categories = check_categories or self.check_categories
        if type(check_categories) != list:
            check_categories = [ check_categories ]
        self.results_dict = {
            key:dict(generals=[],collections=[])
            for key in check_categories
        }
        for category in check_categories:
            if category == 'S3':
                self.s3_check()
            elif category == 'IAM':
                self.iam_checks()
            elif category == 'VPC':
                self.check_vpcs()
            elif category == 'CloudWatch':
                self.check_cloudwatch_billing()
            elif category == 'CloudTrail':
                self.cloudtrail_checks()


    def get_flattened_results(self):
        results = []
        for x in self.results:
            results.append(x)
            results.extend(x.subchecks)
        return results

    def get_category_stats(self):
        """Get a count of CheckState results for each category of checks.
        Ignore collection counts to avoid duplications"""
        flat_results = self.get_flattened_results()
        categories = list(set([x.category for x in flat_results]))
        metrics = {}
        for category in categories:
            metrics[category] = collections.Counter([
                x.status for x in filter(
                    lambda y: len(y.subchecks) == 0 and y.category==category,
                    flat_results
                )
            ])
        return metrics

    def get_iam_credential_report(self):
        report = None
        while report == None:
            try:
                report = self.iam_client.get_credential_report()
            except botocore.exceptions.ClientError as e:
                if 'ReportNotPresent' in e.message:
                    self.iam_client.generate_credential_report()
                else:
                    raise e
                time.sleep(5)
        document = StringIO.StringIO(report['Content'])
        reader = csv.DictReader(document)
        report_rows = []
        for row in reader:
            report_rows.append(row)
        return report_rows

    def get_flowlogs_by_vpc_id(self, ec2_client):
        ''' Returns a dict of vpc_id:flow_log_dict '''
        response = ec2_client.describe_flow_logs()
        return { x['ResourceId']:x for x in response['FlowLogs'] }

    def check_vpcs(self):
        #collect vpc ids
        regions = get_regions()
        for region in regions:
            ec2 = boto3.resource('ec2', region_name=region)
            ec2_client = boto3.client('ec2', region_name=region)
            ids = [ x.id for x in ec2.vpcs.all() ]
            flowlogs = self.get_flowlogs_by_vpc_id(ec2_client)

            for vpc_id in ids:
                vpc_dict = flowlogs.get(vpc_id, None)
                self.append_collection(
                    misc_checks.VPCFlowLogCheck(vpc_id, vpc_dict)
                    )

    def check_cloudwatch_billing(self):
        regions = get_regions()
        self.append_collection(
                misc_checks.CloudWatchBillingAlertEnabledCollection(
                    regions
                )
        )
    def s3_check(self):
        for bucket in self.s3.buckets.all():
            check = s3_checks.S3CheckCollection()
            check.collect_tests(bucket)
            self.append_collection(check)

    def iam_checks(self):
        report_rows = self.get_iam_credential_report()
        self.append_general(iam_checks.IAMRootAccessKeyDisabled(report_rows))
        self.append_general(
            iam_checks.IAMRolesAreCreatedCheck(self.iam.roles.all())
        )
        for row in report_rows:
            check = iam_checks.IAMUserCheckCollection()
            check.collect_tests(row)
            self.append_collection(check)

    def cloudtrail_checks(self):
        trail_list = self.cloudtrail_client.describe_trails()['trailList']
        self.append_general(
            cloudtrail_checks.CloudTrailLogAllCheck(trail_list)
        )
        for trail in trail_list:
            check = cloudtrail_checks.CloudTrailCheckCollection()
            check.collect_tests(trail)
            self.append_collection(check)

    def print_results(self):
        for result in self.results:
            print result
            if len(result.subchecks) > 0:
                for subcheck in result.subchecks:
                    print ' -',subcheck
                print ''

def get_regions():
    client = boto3.client('ec2', region_name='us-east-1')
    regions = [ x['RegionName'] for x in client.describe_regions()['Regions']]
    return regions

if __name__ == '__main__':
    checker = Checker()
    checker.run_checks()
    results = checker.results_dict

    print json.dumps(results, indent=4)
