"""Application layer exceptions."""


class ApplicationError(Exception):
    """Base exception for application layer."""
    pass


class OrganizationError(ApplicationError):
    """Error during organization operations."""
    pass


class InventoryError(ApplicationError):
    """Error during inventory collection."""
    pass


class CostError(ApplicationError):
    """Error during cost collection."""
    pass


class PostureError(ApplicationError):
    """Error during posture collection."""
    pass


class AdvisorError(ApplicationError):
    """Error during Trusted Advisor operations."""
    pass


class ReportWriterError(ApplicationError):
    """Error during report writing."""
    pass


class ConfigurationError(ApplicationError):
    """Error in configuration."""
    pass


class SecurityHubError(ApplicationError):
    """Error during Security Hub operations."""
    pass


class IdentityCenterError(ApplicationError):
    """Error during IAM Identity Center operations."""
    pass


class OrgPolicyError(ApplicationError):
    """Error during organization policy operations."""
    pass
