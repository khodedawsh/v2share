class V2ShareError(Exception):
    """Base class for all v2share exceptions"""


class NotSupportedError(Exception):
    """indicating that the proxy is somehow not supported by v2share"""


class TransportNotSupportedError(Exception):
    """indicating that the specified transport is not supported"""


class ProtocolNotSupportedError(Exception):
    """indicating that the protocol is not supported"""
