"""Error types the CLI turns into readable messages instead of stack traces."""


class RiskTranslatorError(Exception):
    """Base class for every error the user should see as a plain message."""


class InputError(RiskTranslatorError):
    """The scan file, CVE list or assets file is missing or malformed."""


class ConfigError(RiskTranslatorError):
    """A configuration file (such as the ISO 27001 mapping) is missing or malformed."""


class SourceUnavailable(Exception):
    """A public data source (NVD, EPSS or KEV) could not be reached or gave bad data.

    This is deliberately not a RiskTranslatorError: the run carries on and the
    affected fields are marked as missing.
    """
