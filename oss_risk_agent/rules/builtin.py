"""Built-in rule skeleton implementations.

Each rule currently provides framework-only behavior and returns no findings.
Detailed detection logic will be implemented in later iterations.
"""

from __future__ import annotations

from pathlib import Path

from oss_risk_agent.models.risk import RiskRecord

from .base import Rule


class _SkeletonRule(Rule):
    """Common no-op implementation for rule scaffolding."""

    def evaluate(self, target: Path, mode: str) -> list[RiskRecord]:
        _ = (target, mode)
        return []


class A0SbomFullAnalysisRule(_SkeletonRule):
    """A-0: SBOM full analysis."""

    def __init__(self) -> None:
        super().__init__(rule_id="A-0", category="A", title="SBOM full analysis")


class A1KnownVulnerabilitiesRule(_SkeletonRule):
    """A-1: Known vulnerabilities in dependencies."""

    def __init__(self) -> None:
        super().__init__(rule_id="A-1", category="A", title="Known vulnerabilities")


class A2UnpinnedDependencyVersionsRule(_SkeletonRule):
    """A-2: Unpinned dependency versions."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="A-2",
            category="A",
            title="Unpinned dependency versions",
        )


class A3UnsignedArtifactsRule(_SkeletonRule):
    """A-3: Signature verification missing for artifacts."""

    def __init__(self) -> None:
        super().__init__(rule_id="A-3", category="A", title="Unsigned artifacts")


class B1GithubActionsShaPinningRule(_SkeletonRule):
    """B-1: GitHub Actions SHA pinning."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="B-1",
            category="B",
            title="GitHub Actions SHA pinning",
        )


class B2OverPrivilegedWorkflowRule(_SkeletonRule):
    """B-2: Over-privileged workflow permissions."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="B-2",
            category="B",
            title="Over-privileged workflow permissions",
        )


class B3UnpinnedDockerDigestRule(_SkeletonRule):
    """B-3: Docker image digest not pinned."""

    def __init__(self) -> None:
        super().__init__(rule_id="B-3", category="B", title="Unpinned Docker digest")


class B4CurlPipeBashRule(_SkeletonRule):
    """B-4: Direct execution via curl|bash."""

    def __init__(self) -> None:
        super().__init__(rule_id="B-4", category="B", title="curl | bash execution")


class C1ContainerRunsAsRootRule(_SkeletonRule):
    """C-1: Container runs as root."""

    def __init__(self) -> None:
        super().__init__(rule_id="C-1", category="C", title="Container runs as root")


class C2SecretsExposureRule(_SkeletonRule):
    """C-2: Secrets exposure in repository contents."""

    def __init__(self) -> None:
        super().__init__(rule_id="C-2", category="C", title="Secrets exposure")


class C3DangerousApiUsageRule(_SkeletonRule):
    """C-3: Dangerous API usage."""

    def __init__(self) -> None:
        super().__init__(rule_id="C-3", category="C", title="Dangerous API usage")


class C4CorsWildcardRule(_SkeletonRule):
    """C-4: Wildcard CORS configuration."""

    def __init__(self) -> None:
        super().__init__(rule_id="C-4", category="C", title="CORS wildcard")


class D1MaintenanceInactivityRule(_SkeletonRule):
    """D-1: Maintenance inactivity risk."""

    def __init__(self) -> None:
        super().__init__(rule_id="D-1", category="D", title="Maintenance inactivity")


class D2BusFactorOneRule(_SkeletonRule):
    """D-2: Bus factor one risk."""

    def __init__(self) -> None:
        super().__init__(rule_id="D-2", category="D", title="Bus factor 1")


class D3NoSecurityOperationRule(_SkeletonRule):
    """D-3: Missing security operations."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="D-3",
            category="D",
            title="Missing security operations",
        )


class D4PatchDelayRule(_SkeletonRule):
    """D-4: Delayed remediation risk."""

    def __init__(self) -> None:
        super().__init__(rule_id="D-4", category="D", title="Patch delay")


class E1GplAgplLicenseRule(_SkeletonRule):
    """E-1: GPL/AGPL license risk."""

    def __init__(self) -> None:
        super().__init__(rule_id="E-1", category="E", title="GPL/AGPL license risk")


class E2IncompatibleLicenseMixRule(_SkeletonRule):
    """E-2: Incompatible license combination risk."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="E-2",
            category="E",
            title="Incompatible license mix",
        )


class E3UndefinedLicenseRule(_SkeletonRule):
    """E-3: Undefined license risk."""

    def __init__(self) -> None:
        super().__init__(rule_id="E-3", category="E", title="Undefined license")


class F1DebugEnabledRule(_SkeletonRule):
    """F-1: Debug mode enabled."""

    def __init__(self) -> None:
        super().__init__(rule_id="F-1", category="F", title="Debug mode enabled")


class F2HttpOnlyCommunicationRule(_SkeletonRule):
    """F-2: HTTP-only communication."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="F-2",
            category="F",
            title="HTTP-only communication",
        )


class F3AdminEndpointExposedRule(_SkeletonRule):
    """F-3: Potential public exposure of admin endpoint."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="F-3",
            category="F",
            title="Admin endpoint exposure",
        )
