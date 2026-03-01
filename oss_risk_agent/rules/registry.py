"""Rule registry skeleton."""

from __future__ import annotations

from dataclasses import dataclass, field

from .base import Rule
from .builtin import (
    A0SbomFullAnalysisRule,
    A1KnownVulnerabilitiesRule,
    A2UnpinnedDependencyVersionsRule,
    A3UnsignedArtifactsRule,
    B1GithubActionsShaPinningRule,
    B2OverPrivilegedWorkflowRule,
    B3UnpinnedDockerDigestRule,
    B4CurlPipeBashRule,
    C1ContainerRunsAsRootRule,
    C2SecretsExposureRule,
    C3DangerousApiUsageRule,
    C4CorsWildcardRule,
    D1MaintenanceInactivityRule,
    D2BusFactorOneRule,
    D3NoSecurityOperationRule,
    D4PatchDelayRule,
    E1GplAgplLicenseRule,
    E2IncompatibleLicenseMixRule,
    E3UndefinedLicenseRule,
    F1DebugEnabledRule,
    F2HttpOnlyCommunicationRule,
    F3AdminEndpointExposedRule,
)


@dataclass(slots=True)
class RuleRegistry:
    rules: list[Rule] = field(default_factory=list)

    @classmethod
    def default(cls) -> "RuleRegistry":
        """Build default rule set.

        TODO: load enabled rules from configuration and rule packages.
        """
        return cls(
            rules=[
                A0SbomFullAnalysisRule(),
                A1KnownVulnerabilitiesRule(),
                A2UnpinnedDependencyVersionsRule(),
                A3UnsignedArtifactsRule(),
                B1GithubActionsShaPinningRule(),
                B2OverPrivilegedWorkflowRule(),
                B3UnpinnedDockerDigestRule(),
                B4CurlPipeBashRule(),
                C1ContainerRunsAsRootRule(),
                C2SecretsExposureRule(),
                C3DangerousApiUsageRule(),
                C4CorsWildcardRule(),
                D1MaintenanceInactivityRule(),
                D2BusFactorOneRule(),
                D3NoSecurityOperationRule(),
                D4PatchDelayRule(),
                E1GplAgplLicenseRule(),
                E2IncompatibleLicenseMixRule(),
                E3UndefinedLicenseRule(),
                F1DebugEnabledRule(),
                F2HttpOnlyCommunicationRule(),
                F3AdminEndpointExposedRule(),
            ]
        )
