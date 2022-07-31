
class N3MapError(Exception):
    def __str__(self):
        return ''.join(map(str, self.args))

class NSECError(N3MapError):
    pass

class NSECWalkError(N3MapError):
    pass

class NSEC3Error(N3MapError):
    pass

class NSEC3WalkError(N3MapError):
    pass

class ZoneChangedError(N3MapError):
    def __str__(self):
        return ''.join(map(str, self.args)) + '\nzone may have been modified'

class InvalidPortError(N3MapError):
    def __str__(self):
        return "invalid port specified: " + str(self.args[0])

class TimeOutError(N3MapError):
    def __str__(self):
        return 'timeout: ' + ''.join(map(str, self.args))

class UnexpectedResponseStatus(N3MapError):
    def __init__(self, status):
        self.status = status

    def __str__(self):
        return 'received unexpected response status ' + str(self.status)


class MaxRetriesError(N3MapError):
    def __str__(self):
        return 'timeout: ' + ''.join(map(str, self.args))

class MaxNsErrors(N3MapError):
    pass

class QueryError(N3MapError):
    def __str__(self):
        return 'received bad response'
    pass

class InvalidDomainNameError(N3MapError):
    def __str__(self):
        return "invalid domain name: " + ''.join(map(str, self.args))

class MaxLabelLengthError(N3MapError):
    def __str__(self):
        return "maximum domain name label length exceeded"
class MaxLabelValueError(N3MapError):
    def __str__(self):
        return "maximum domain name label value exceeded"

class MaxDomainNameLengthError(N3MapError):
    def __str__(self):
        return "maximum domain name length exceeded"

class ParseError(N3MapError):
    pass

class FileParseError(N3MapError):
    def __init__(self, filename, line, msg):
        super(FileParseError, self).__init__(filename, line, msg)
        self.filename = filename
        self.line = line
        self.msg = msg
    def __str__(self):
        return self.filename + ':' + str(self.line) + ": " + str(self.msg)

