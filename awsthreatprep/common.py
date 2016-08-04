import re

class CheckState(object):
    """Enum for describing the state of a check."""
    UNTESTED = 'UNTESTED'
    PASS = 'PASS'
    FAIL = 'FAIL'
    ERROR = 'ERROR'

class BaseCheck(object):
    """Base class for checks."""
    def __init__(self,
            resource_name='', category='', status=CheckState.UNTESTED,
            subchecks=None, reason='' ):
        self.resource_name = resource_name
        self.category = category
        self.status = status
        self.subchecks = subchecks or []
        self.reason = reason
    def get_description(self):
        """Gets the docstring of the instance."""
        return re.sub('\n\W+',' ', self.__doc__)

    def get_check_name(self):
        """Gets the class name without the module and trims the '> at the end.
        """
        return  str(self.__class__).split('.')[-1][:-2]
    def __str__(self):
        check_name = self.get_check_name()
        if len(self.subchecks)==0:
            reason = self.reason
        else:
            passing_checks = filter(
                lambda x: x.status==CheckState.PASS,
                self.subchecks
            )
            reason = '{0}/{1} PASS'.format(
                len(passing_checks),
                len(self.subchecks)
            )
        return '{status:<8} {check_name:<12} {resource_name} {reason}'.format(
            status=self.status,
            check_name=check_name,
            resource_name=self.resource_name,
            reason=reason
        )
    def to_dict(self):
        return dict(
            status = self.status,
            category = self.category,
            check_name = self.get_check_name(),
            description = self.get_description(),
            resource_name = self.resource_name,
            reason = self.reason,
            subchecks = [ x.to_dict() for x in self.subchecks]
        )
