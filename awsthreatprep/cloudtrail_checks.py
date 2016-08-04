
import common

class CloudTrailCheckCollection(common.BaseCheck):
    """Checks for basic CloudTrail security settings."""

    def __init__(self):
        return super(CloudTrailCheckCollection, self).__init__(category='CloudTrail')

    def collect_tests(self, trail):
        self.resource_name = trail['Name']
        self.subchecks.append(CloudTrailFileValidationCheck(trail))
        if all(x==common.CheckState.PASS for x in self.subchecks):
            self.status = common.CheckState.PASS
        else:
            self.status = common.CheckState.FAIL

class CloudTrailCheck(common.BaseCheck):
    """Baseclass for CloudTrail checks."""

    def __init__(self, trail):
        self.category='CloudTrail'
        self.trail = trail
        self.resource_name = self.trail['Name']
        self.status = common.CheckState.UNTESTED
        self.subchecks = []
        self.reason = ''
        self.test()

    def test(self):
        raise NotImplemented('Subclasses should be used')

class CloudTrailFileValidationCheck(CloudTrailCheck):
    """Check if LogFileValidation is enabled."""

    def test(self):
        if self.trail['LogFileValidationEnabled']:
            self.reason = 'LogFileValidation is enabled.'
            self.status = common.CheckState.PASS
        else:
            self.reason = 'LogFileValidation is not enabled.'
            self.status = common.CheckState.FAIL

class CloudTrailLogAllCheck(common.BaseCheck):
    """Checks if a logs exists that is MultiRegional and includes global service
    events."""

    def __init__(self, trails):
        self.category='CloudTrail'
        self.trails = trails
        self.resource_name = ''
        self.subchecks = []
        self.status = common.CheckState.UNTESTED
        self.reason = ''
        self.test()

    def test(self):
        multiregional_trails = filter(
            lambda x: x['IsMultiRegionTrail'] == True and \
             x['IncludeGlobalServiceEvents'] == True,
             self.trails
        )
        if len(multiregional_trails) > 0:
            self.reason = 'Multiregional trails are enabled.'
            self.status = common.CheckState.PASS
        else:
            self.reason = 'No multiregional trails.'
            self.status = common.CheckState.FAIL
