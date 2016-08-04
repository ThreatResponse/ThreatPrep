import common
import datetime
import dateutil
import boto3

import config

class IAMRootAccessKeyDisabled(common.BaseCheck):
    """Checks to see if access keys are disabled for the root account."""
    def __init__(self, rows):
        self.category = 'IAM'
        self.resource_name = '<root_account>'
        self.rows = rows
        self.status = common.CheckState.UNTESTED
        self.subchecks = []
        self.reason = ''
        self.test()
    def test(self):
        root_account = filter(
            lambda x: x['user'] == '<root_account>',
            self.rows
        )
        if len(root_account) != 1:
            self.status = common.CheckState.ERROR
            self.reason = 'Looking for 1 <root_account> but found {0}'.format(
                len(root_account)
            )
            return
        user_dict = root_account[0]
        key_keys = 'access_key_{0}_active'
        active_keys = filter(
            lambda x: user_dict[key_keys.format(x)] == 'true',
            range(1,3)
        )
        if len(active_keys) != 0:
            self.status = common.CheckState.FAIL
            self.reason = 'The root account should have 0 access keys but found {0}'.format(
                len(active_keys)
            )
        else:
            self.status = common.CheckState.PASS
            self.reason = 'The root account access keys are disabled.'

class IAMRolesAreCreatedCheck(common.BaseCheck):
    """Checks to see if any roles are created."""
    def __init__(self, all_roles):
        self.category = 'IAM'
        self.all_roles = all_roles
        self.resource_name = ''
        self.subchecks = []
        self.test()

    def test(self):
        roles =[ x for x in self.all_roles]
        self.reason = '{0} roles are created.'.format(
            len(roles)
        )
        if len(roles) > 0:
            self.status = common.CheckState.PASS
        else:
            self.status = common.CheckState.FAIL

class IAMUserCheckCollection(common.BaseCheck):
    """Checks for all IAM User security configurations."""

    def __init__(self):
        return super(IAMUserCheckCollection, self).__init__(category='IAM')

    def collect_tests(self, user_dict):
        self.resource_name = user_dict['user']
        self.subchecks.append(IAMUserMFAEnabledCheck(user_dict))
        self.subchecks.append(IAMUserPasswordChangeCheck(user_dict))
        self.subchecks.append(IAMUserAccessKeyChangeCheck(user_dict))
        if self.resource_name != '<root_account>':
            self.subchecks.append(
                IAMUserHasAdministratorAccessPolicyCheck(user_dict)
            )

        if all(x.status==common.CheckState.PASS for x in self.subchecks):
            self.status = common.CheckState.PASS
        else:
            self.status = common.CheckState.FAIL

class IAMUserCheck(common.BaseCheck):
    def __init__(self, user_dict):
        self.category = 'IAM'
        self.user_dict= user_dict
        self.resource_name = self.user_dict['user']
        self.status = common.CheckState.UNTESTED
        self.reason = ''
        self.subchecks = []
        self.test()
    def test(self):
        raise NotImplemented('This method should be called on subclasses of this class')

class IAMUserMFAEnabledCheck(IAMUserCheck):
    """Checks if the account has MFA enabled."""
    def test(self):
        if self.user_dict['mfa_active'] == 'true':
            self.status = common.CheckState.PASS
        else:
            self.status = common.CheckState.FAIL

class IAMUserHasAdministratorAccessPolicyCheck(IAMUserCheck):
    """Checks if the account has the AdministratorAccess policy."""
    def test(self):
        policy = 'arn:aws:iam::aws:policy/AdministratorAccess'
        user = boto3.resource('iam').User(self.user_dict['user'])
        attached_admin_policies = filter(
            lambda x: x.arn == policy,
            user.attached_policies.all()
        )
        if len(attached_admin_policies) > 0:
            self.reason = 'This user has the {0} policy.'.format(policy)
            self.status = common.CheckState.FAIL
        else:
            self.status = common.CheckState.PASS
            self.reason = 'This user does not have the {0} policy.'.format(policy)



class IAMUserPasswordChangeCheck(IAMUserCheck):
    """Checks if the account has password changed in last X days."""
    def test(self):
        if self.user_dict['password_enabled'] == 'true' :
            last_changed = dateutil.parser.parse(self.user_dict['password_last_changed'])
            now = datetime.datetime.utcnow().replace(tzinfo=last_changed.tzinfo)
            diff = now - last_changed
            delta = datetime.timedelta(
                days=config.config['PASSWORD_ROTATION_DAYS']
            )
            if diff > delta:
                self.reason = 'Password has not been changed in {0} days'.format(
                    delta.days
                )
                self.status = common.CheckState.FAIL
            else:
                self.status = common.CheckState.PASS
        elif self.user_dict['password_last_changed'] == 'not_supported':
            self.reason = 'password_last_changed field is not supported'
            self.status = common.CheckState.ERROR
        else:
            self.reason = 'Password is not enabled'
            self.status = common.CheckState.PASS



class IAMUserAccessKeyChangeCheck(IAMUserCheck):
    '''Tests if the account has access keys changed in X days'''

    def key_rotated(self, key_id):
        active_key = 'access_key_{0}_active'.format(key_id)
        if self.user_dict[active_key] != 'true':
            return True #since the key is not active, call it rotated
        last_rotated_key = 'access_key_{0}_last_rotated'.format(key_id)
        last_rotated = self.user_dict[last_rotated_key]
        try:
            last_rotated_date = dateutil.parser.parse(last_rotated)
        except ValueError as e:
            return False #The key has not been rotated so the value is N/A
        delta = datetime.timedelta(days=config.config['ACCESS_KEY_ROTATION_DAYS'])
        now = datetime.datetime.now().replace(tzinfo=last_rotated_date.tzinfo)
        diff = now-last_rotated_date
        if diff > delta:
            return False
        return True


    def test(self):
        rotated_keys = {
            k:self.key_rotated(k)
            for k in [1,2]
        }
        if all(rotated_keys.values()):
            self.status = common.CheckState.PASS
            self.reason = 'Active keys have been rotated within {0} days'.format(
                config.config['ACCESS_KEY_ROTATION_DAYS']
            )
        else:
            self.status = common.CheckState.FAIL
            self.reason = '{0} active keys have not been rotated within {1} days'.format(
                len(filter(lambda x: x==False, rotated_keys.values())),
                config.config['ACCESS_KEY_ROTATION_DAYS']
            )


class IAMRecentAccountActivity(IAMUserCheck):
    """Tests if the account has been used recently."""
    def test(self):
        last_used_times = []
        if self.user_dict['access_key_1_active'] == 'true':
            last_used_times.append(
                dateutil.parser.parse(
                    self.user_dict['access_key_1_last_used_date']
                )
            )
        if self.user_dict['access_key_2_active'] == 'true':
            last_used_times.append(
                dateutil.parser.parse(
                    self.user_dict['access_key_2_last_used_date']
                )
            )
        if self.user_dict['password_enabled'] in ['true', 'not_supported'] and \
            self.user_dict['password_last_used'] != 'no_information':
            last_used_times.append(
                dateutil.parser.parse(
                    self.user_dict['password_last_used']
                )
            )
        if len(last_used_times) == 0:
            self.reason = 'Account has never been used'
            self.status = common.CheckState.FAIL
            return
        last_used = max(last_used_times)
        now = datetime.datetime.utcnow()
        now = now.replace(tzinfo=last_used.tzinfo)
        delta = datetime.timedelta(days=config.config['ACCOUNT_INACTIVE_DAYS'])
        difference = now - last_used
        if delta < difference:
            self.reason = 'Account last used {0} days ago.'.format(difference.days)
            self.status = common.CheckState.FAIL
        else:
            self.status = common.CheckState.PASS
