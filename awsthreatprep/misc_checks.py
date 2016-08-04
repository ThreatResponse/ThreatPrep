import common
import boto3

class CloudWatchBillingAlertEnabledCollection(common.BaseCheck):
    """Checks each region to see if there is an Alert based on Billing metrics."""
    def __init__(self, regions):
        self.category='CloudWatch'
        self.resource_name=''
        self.subchecks = []
        self.regions = regions
        self.test()
    def test(self):
        for region in self.regions:
            cloudwatch=boto3.resource('cloudwatch',region_name=region)
            self.subchecks.append(
                CloudWatchBillingAlertEnabledCheck(
                    region,
                    cloudwatch.alarms.all()
                )
            )
        if any(x.status == common.CheckState.PASS for x in self.subchecks):
            self.status = common.CheckState.PASS
            self.reason = 'Atleast one CloudWatch Billing Alert is Enabled'
        else:
            self.status = common.CheckState.FAIL
            self.reason = 'No CloudWatch Billing Alerts are Enabled'


class CloudWatchBillingAlertEnabledCheck(common.BaseCheck):
    """Checks to see if there is an Alert based on Billing metrics."""


    '''
    # This code does not seem to find results
    response = self.cloudwatch_client.describe_alarms_for_metric(
        MetricName = 'EstimatedCost',
        Namespace='AWS/Billing'
    )
    '''

    def __init__(self, region_name, all_alarms):
        self.category='CloudWatch'
        self.resource_name = region_name
        self.subchecks = []
        self.all_alarms = all_alarms
        self.test()

    def test(self):
        billing_alerts = filter(
            lambda x: x.namespace == 'AWS/Billing' and \
                x.metric_name == 'EstimatedCharges',
            self.all_alarms
        )
        self.reason = '{0} Billing alerts are enabled in CloudWatch region {1}.'.format(
            len(billing_alerts), self.resource_name
        )
        if len(billing_alerts) > 0:
            self.status = common.CheckState.PASS
        else:
            self.status = common.CheckState.FAIL

class VPCFlowLogCheck(common.BaseCheck):
    """Checks if a VPC has flow logging enabled and if the logging occurs
    without error."""

    def __init__(self, vpc_id, vpc_dict=None):
        self.category='VPC'
        self.vpc_id = vpc_id
        self.vpc_dict = vpc_dict
        self.resource_name = vpc_id
        self.status = common.CheckState.UNTESTED
        self.subchecks = []
        self.reason = ''
        self.test()
    def test(self):
        if self.vpc_dict == None:
            self.status = common.CheckState.FAIL
            self.reason = "No flow log found"
            return
        error_message = self.vpc_dict.get('DeliverLogsErrorMessage', '')
        if error_message != '':
            self.status = common.CheckState.FAIL
            self.reason = 'Flow log has DeliverLogsErrorMessage: {0}'.format(
                error_message
            )
            return
        flowlog_status = self.vpc_dict.get('FlowLogStatus', '')
        if flowlog_status != 'ACTIVE':
            self.status = common.CheckState.self.FAIL
            self.reason = 'Flow log has FlowLogStatus: {0}'.format(
                flowlog_status
            )
            return
        self.status = common.CheckState.PASS
