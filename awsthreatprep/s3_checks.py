import common

class S3CheckCollection(common.BaseCheck):
    """Checks for basic S3 security settings."""

    def __init__(self):
        return super(S3CheckCollection, self ).__init__(category='S3')

    def collect_tests(self, s3_object):
        self.resource_name = s3_object.name
        self.subchecks.append(S3VersioningEnabledCheck(s3_object))
        self.subchecks.append(S3LoggingEnabledCheck(s3_object))
        self.subchecks.append(S3OpenPermissionCheck(s3_object, 'READ'))
        self.subchecks.append(S3OpenPermissionCheck(s3_object, 'WRITE'))
        if all(x.status==common.CheckState.PASS for x in self.subchecks):
            self.status = common.CheckState.PASS
        else:
            self.status = common.CheckState.FAIL

class S3VersioningEnabledCheck(common.BaseCheck):
    """Checks if versioning is enabled on a S3 bucket."""

    def __init__(self, s3_object):
        self.s3_name= s3_object.name
        self.resource_name= s3_object.name
        self.s3_object = s3_object
        self.status = common.CheckState.UNTESTED
        self.category = 'S3'
        self.reason = ''
        self.subchecks = []
        self.test()

    def test(self):
        versioning_enabled = self.s3_object.Versioning().status == 'Enabled'
        if versioning_enabled:
            self.status = common.CheckState.FAIL
            self.reason = 'S3 versioning is not enabled for this bucket'
        else:
            self.status = common.CheckState.PASS
            self.reason = 'S3 versioning is enabled for this bucket'

class S3LoggingEnabledCheck(common.BaseCheck):
    """Checks if logging is enabled on a S3 bucket."""

    def __init__(self, s3_object):
        self.category = 'S3'
        self.s3_name= s3_object.name
        self.resource_name= s3_object.name
        self.s3_object = s3_object
        self.status = common.CheckState.UNTESTED
        self.reason = ''
        self.subchecks = []
        self.test()

    def test(self):
        logging_enabled = self.s3_object.Logging().logging_enabled is not None
        if logging_enabled:
            self.status = common.CheckState.FAIL
            self.reason = 'S3 logging is not enabled for this bucket'
        else:
            self.status = common.CheckState.PASS
            self.reason = 'S3 logging is enabled for this bucket'

class S3OpenPermissionCheck(common.BaseCheck):
    """Checks for a permission open to the world on a S3 bucket."""

    def __init__(self, s3_object, permission="READ"):
        self.category = 'S3'
        self.s3_name= s3_object.name
        self.resource_name= s3_object.name
        self.permission = permission
        self.s3_object = s3_object
        self.status = common.CheckState.UNTESTED
        self.reason = ''
        self.subchecks = []
        self.test()

    def grant_is_open_read(self, grant):
        result = grant['Grantee'].get('Type', None)== 'Group' and \
        grant['Grantee'].get('URI',None) == \
            'http://acs.amazonaws.com/groups/global/AllUsers' and \
            grant['Permission'] == self.permission
        return result

    def test(self):
        grants = self.s3_object.Acl().grants
        if any( self.grant_is_open_read(grant) for grant in grants ):
            self.status = common.CheckState.FAIL
            self.reason = 'S3 permission {0} is granted to AllUsers'.format(
                self.permission
            )

        else:
            self.status = common.CheckState.PASS
            self.reason = 'S3 permission "{0}" is not granted to AllUsers'.format(
                self.permission
            )
