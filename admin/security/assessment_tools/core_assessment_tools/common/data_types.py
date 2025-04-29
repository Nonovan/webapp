"""
Common data types for security assessment tools.

This module defines the core data structures used across security assessment tools
in the Cloud Infrastructure Platform. These types provide standardized representations
for assessment targets, findings, evidence, remediation information, and related metadata.
"""

import datetime
import enum
import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union


class FindingSeverity(enum.Enum):
    """Severity level of a security finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_cvss(cls, score: float) -> 'FindingSeverity':
        """
        Convert a CVSS score to a severity level.

        Args:
            score: CVSS score (0.0-10.0)

        Returns:
            Corresponding FindingSeverity
        """
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0.0:
            return cls.LOW
        else:
            return cls.INFO


class FindingStatus(enum.Enum):
    """Status of a security finding."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    RISK_ACCEPTED = "risk_accepted"
    DUPLICATE = "duplicate"


class RiskLevel(enum.Enum):
    """Risk level for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


@dataclass
class AssessmentTarget:
    """
    Target system or component for security assessment.

    Represents a system, application, or component that will be assessed.
    Contains all information necessary to connect to and identify the target.
    """

    target_id: str
    target_type: str  # e.g., "server", "application", "container", "network"
    name: Optional[str] = None
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None
    uri: Optional[str] = None
    environment: str = "production"
    owner: Optional[str] = None
    criticality: str = "medium"  # low, medium, high, critical
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate and set defaults after initialization."""
        if not self.name:
            self.name = self.target_id

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert target to dictionary.

        Returns:
            Dictionary representation of the target
        """
        result = {
            "target_id": self.target_id,
            "target_type": self.target_type,
            "name": self.name,
            "environment": self.environment,
            "criticality": self.criticality
        }

        # Add optional fields if they exist
        if self.ip_address:
            result["ip_address"] = self.ip_address
        if self.hostname:
            result["hostname"] = self.hostname
        if self.port:
            result["port"] = self.port
        if self.uri:
            result["uri"] = self.uri
        if self.owner:
            result["owner"] = self.owner
        if self.tags:
            result["tags"] = self.tags
        if self.metadata:
            result["metadata"] = self.metadata

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AssessmentTarget':
        """
        Create a target from dictionary.

        Args:
            data: Dictionary with target information

        Returns:
            AssessmentTarget instance
        """
        return cls(
            target_id=data["target_id"],
            target_type=data["target_type"],
            name=data.get("name"),
            ip_address=data.get("ip_address"),
            hostname=data.get("hostname"),
            port=data.get("port"),
            uri=data.get("uri"),
            environment=data.get("environment", "production"),
            owner=data.get("owner"),
            criticality=data.get("criticality", "medium"),
            tags=data.get("tags", {}),
            metadata=data.get("metadata", {})
        )


@dataclass
class Evidence:
    """
    Evidence supporting a security finding.

    Represents proof that supports a finding, such as screenshots,
    log excerpts, or file contents.
    """

    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    evidence_type: str = ""  # e.g., "screenshot", "log", "file", "command_output"
    content: Optional[str] = None
    file_path: Optional[str] = None
    collection_time: datetime.datetime = field(default_factory=datetime.datetime.now)
    collected_by: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert evidence to dictionary.

        Returns:
            Dictionary representation of the evidence
        """
        result = {
            "evidence_id": self.evidence_id,
            "title": self.title,
            "description": self.description,
            "evidence_type": self.evidence_type,
            "collection_time": self.collection_time.isoformat(),
        }

        if self.content:
            result["content"] = self.content
        if self.file_path:
            result["file_path"] = self.file_path
        if self.collected_by:
            result["collected_by"] = self.collected_by
        if self.metadata:
            result["metadata"] = self.metadata

        return result


@dataclass
class EvidenceCollection:
    """
    Collection of evidence for an assessment.

    Manages all evidence gathered during an assessment with chain of custody tracking.
    """

    collection_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    evidence_items: List[Evidence] = field(default_factory=list)
    collection_start: datetime.datetime = field(default_factory=datetime.datetime.now)
    collection_end: Optional[datetime.datetime] = None
    collector: Optional[str] = None
    chain_of_custody: List[Dict[str, Any]] = field(default_factory=list)
    integrity_hash: Optional[str] = None

    def add_evidence(self, evidence: Evidence) -> None:
        """Add evidence item and record in chain of custody."""
        self.evidence_items.append(evidence)
        self.chain_of_custody.append({
            "timestamp": datetime.datetime.now().isoformat(),
            "action": "added",
            "evidence_id": evidence.evidence_id,
            "actor": self.collector
        })
        self._update_integrity_hash()

    def _update_integrity_hash(self) -> None:
        """Update integrity hash for evidence collection."""
        import hashlib
        hash_data = "".join(sorted([ev.evidence_id for ev in self.evidence_items]))
        self.integrity_hash = hashlib.sha256(hash_data.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence collection to dictionary."""
        return {
            "collection_id": self.collection_id,
            "evidence_items": [ev.to_dict() for ev in self.evidence_items],
            "collection_start": self.collection_start.isoformat(),
            "collection_end": self.collection_end.isoformat() if self.collection_end else None,
            "collector": self.collector,
            "chain_of_custody": self.chain_of_custody,
            "integrity_hash": self.integrity_hash
        }


@dataclass
class Remediation:
    """
    Remediation guidance for a security finding.

    Provides information on how to address a security finding, including
    steps, difficulty, and potential impact.
    """

    description: str
    steps: List[str] = field(default_factory=list)
    difficulty: str = "medium"  # easy, medium, hard
    effort_estimate: str = ""  # e.g., "2 hours", "1 day"
    impact: str = "low"  # none, low, medium, high
    references: List[str] = field(default_factory=list)
    code_sample: Optional[str] = None
    verification_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert remediation to dictionary.

        Returns:
            Dictionary representation of the remediation
        """
        result = {
            "description": self.description,
            "steps": self.steps,
            "difficulty": self.difficulty,
            "effort_estimate": self.effort_estimate,
            "impact": self.impact,
            "references": self.references,
            "verification_steps": self.verification_steps
        }

        if self.code_sample:
            result["code_sample"] = self.code_sample

        return result


@dataclass
class RemediationPlan:
    """
    Plan for remediating security findings.

    Tracks remediation activities, assignments, and verification.
    """

    finding_id: str
    plan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    remediation_status: str = "planned"  # planned, in-progress, completed, verified, deferred
    assigned_to: Optional[str] = None
    reviewer: Optional[str] = None
    due_date: Optional[datetime.datetime] = None
    steps: List[Dict[str, Any]] = field(default_factory=list)
    completion_date: Optional[datetime.datetime] = None
    verification_date: Optional[datetime.datetime] = None
    verification_evidence: List[Evidence] = field(default_factory=list)
    notes: List[Dict[str, Any]] = field(default_factory=list)

    def add_note(self, content: str, author: str) -> None:
        """Add a note to the remediation plan."""
        self.notes.append({
            "timestamp": datetime.datetime.now().isoformat(),
            "content": content,
            "author": author
        })

    def update_status(self, status: str, updated_by: str) -> None:
        """Update remediation status."""
        self.remediation_status = status
        self.add_note(f"Status updated to {status}", updated_by)

        if status == "completed":
            self.completion_date = datetime.datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """Convert remediation plan to dictionary."""
        result = {
            "plan_id": self.plan_id,
            "finding_id": self.finding_id,
            "remediation_status": self.remediation_status,
            "steps": self.steps,
            "notes": self.notes
        }

        # Add optional fields
        if self.assigned_to:
            result["assigned_to"] = self.assigned_to
        if self.reviewer:
            result["reviewer"] = self.reviewer
        if self.due_date:
            result["due_date"] = self.due_date.isoformat()
        if self.completion_date:
            result["completion_date"] = self.completion_date.isoformat()
        if self.verification_date:
            result["verification_date"] = self.verification_date.isoformat()
        if self.verification_evidence:
            result["verification_evidence"] = [e.to_dict() for e in self.verification_evidence]

        return result


@dataclass
class CVSS:
    """
    Common Vulnerability Scoring System representation.

    Implements CVSS v3.1 metrics for vulnerability scoring.
    """

    # Base metrics
    attack_vector: str = "N"  # N(etwork), A(djacent), L(ocal), P(hysical)
    attack_complexity: str = "L"  # L(ow), H(igh)
    privileges_required: str = "N"  # N(one), L(ow), H(igh)
    user_interaction: str = "N"  # N(one), R(equired)
    scope: str = "U"  # U(nchanged), C(hanged)
    confidentiality: str = "N"  # N(one), L(ow), H(igh)
    integrity: str = "N"  # N(one), L(ow), H(igh)
    availability: str = "N"  # N(one), L(ow), H(igh)

    # Temporal metrics (optional)
    exploit_code_maturity: Optional[str] = None  # N(ot defined), U(nproven), P(roof-of-concept), F(unctional), H(igh)
    remediation_level: Optional[str] = None  # N(ot defined), O(fficial fix), T(emporary fix), W(orkaround), U(navailable)
    report_confidence: Optional[str] = None  # N(ot defined), U(nknown), R(easonable), C(onfirmed)

    # Environmental metrics (optional)
    confidentiality_requirement: Optional[str] = None  # N(ot defined), L(ow), M(edium), H(igh)
    integrity_requirement: Optional[str] = None  # N(ot defined), L(ow), M(edium), H(igh)
    availability_requirement: Optional[str] = None  # N(ot defined), L(ow), M(edium), H(igh)

    @property
    def vector_string(self) -> str:
        """
        Generate CVSS vector string.

        Returns:
            CVSS v3.1 vector string
        """
        base = f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/PR:{self.privileges_required}/UI:{self.user_interaction}/S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}/A:{self.availability}"

        temporal = []
        if self.exploit_code_maturity:
            temporal.append(f"E:{self.exploit_code_maturity}")
        if self.remediation_level:
            temporal.append(f"RL:{self.remediation_level}")
        if self.report_confidence:
            temporal.append(f"RC:{self.report_confidence}")

        env = []
        if self.confidentiality_requirement:
            env.append(f"CR:{self.confidentiality_requirement}")
        if self.integrity_requirement:
            env.append(f"IR:{self.integrity_requirement}")
        if self.availability_requirement:
            env.append(f"AR:{self.availability_requirement}")

        result = base
        if temporal:
            result += "/" + "/".join(temporal)
        if env:
            result += "/" + "/".join(env)

        return result

    def calculate_score(self) -> float:
        """
        Calculate CVSS base score.

        Returns:
            CVSS score (0.0-10.0)
        """
        # Simplified calculation for demonstration
        # In a real implementation, this would implement the full CVSS v3.1 formula

        # Assign values to metrics
        av_values = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_values = {"L": 0.77, "H": 0.44}
        pr_values = {"N": 0.85, "L": 0.62, "H": 0.27}
        ui_values = {"N": 0.85, "R": 0.62}

        c_i_a_values = {"N": 0, "L": 0.22, "H": 0.56}

        # Calculate impact and exploitability
        impact = 1 - (
            (1 - c_i_a_values[self.confidentiality]) *
            (1 - c_i_a_values[self.integrity]) *
            (1 - c_i_a_values[self.availability])
        )

        exploitability = (
            8.22 * av_values[self.attack_vector] *
            ac_values[self.attack_complexity] *
            pr_values[self.privileges_required] *
            ui_values[self.user_interaction]
        )

        # Handle scope change
        if self.scope == "U":
            base_score = min(impact + exploitability, 10)
        else:
            base_score = min(1.08 * (impact + exploitability), 10)

        # Round to 1 decimal place
        return round(base_score * 10) / 10

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert CVSS to dictionary.

        Returns:
            Dictionary representation of CVSS metrics
        """
        result = {
            "vector_string": self.vector_string,
            "base_score": self.calculate_score(),
            "base_metrics": {
                "attack_vector": self.attack_vector,
                "attack_complexity": self.attack_complexity,
                "privileges_required": self.privileges_required,
                "user_interaction": self.user_interaction,
                "scope": self.scope,
                "confidentiality": self.confidentiality,
                "integrity": self.integrity,
                "availability": self.availability
            }
        }

        # Add temporal metrics if any are defined
        if any(x is not None for x in [self.exploit_code_maturity, self.remediation_level, self.report_confidence]):
            result["temporal_metrics"] = {}
            if self.exploit_code_maturity:
                result["temporal_metrics"]["exploit_code_maturity"] = self.exploit_code_maturity
            if self.remediation_level:
                result["temporal_metrics"]["remediation_level"] = self.remediation_level
            if self.report_confidence:
                result["temporal_metrics"]["report_confidence"] = self.report_confidence

        # Add environmental metrics if any are defined
        if any(x is not None for x in [self.confidentiality_requirement, self.integrity_requirement, self.availability_requirement]):
            result["environmental_metrics"] = {}
            if self.confidentiality_requirement:
                result["environmental_metrics"]["confidentiality_requirement"] = self.confidentiality_requirement
            if self.integrity_requirement:
                result["environmental_metrics"]["integrity_requirement"] = self.integrity_requirement
            if self.availability_requirement:
                result["environmental_metrics"]["availability_requirement"] = self.availability_requirement

        return result


@dataclass
class Finding:
    """
    Security finding identified during assessment.

    Represents a vulnerability, misconfiguration, or security issue
    identified during an assessment.
    """

    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    cvss: Optional[CVSS] = None
    status: FindingStatus = FindingStatus.OPEN
    category: str = ""  # e.g., "authentication", "authorization", "encryption"
    location: str = ""  # Where the finding was identified
    evidence: List[Evidence] = field(default_factory=list)
    remediation: Optional[Remediation] = None
    references: List[str] = field(default_factory=list)  # External references like CVEs, CWEs
    compliance: Dict[str, List[str]] = field(default_factory=dict)  # Maps frameworks to control IDs
    created_at: datetime.datetime = field(default_factory=datetime.datetime.now)
    updated_at: Optional[datetime.datetime] = None
    created_by: Optional[str] = None
    assigned_to: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Initialize default values if needed."""
        if not self.updated_at:
            self.updated_at = self.created_at

    def add_evidence(self, evidence: Evidence) -> None:
        """
        Add evidence to the finding.

        Args:
            evidence: Evidence to add
        """
        self.evidence.append(evidence)
        self.updated_at = datetime.datetime.now()

    def update_status(self, status: FindingStatus) -> None:
        """
        Update the finding status.

        Args:
            status: New status
        """
        self.status = status
        self.updated_at = datetime.datetime.now()

    def set_remediation(self, remediation: Remediation) -> None:
        """
        Set remediation guidance.

        Args:
            remediation: Remediation guidance
        """
        self.remediation = remediation
        self.updated_at = datetime.datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert finding to dictionary.

        Returns:
            Dictionary representation of the finding
        """
        result = {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "category": self.category,
            "location": self.location,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "references": self.references,
            "tags": self.tags
        }

        # Add optional fields
        if self.cvss:
            result["cvss"] = self.cvss.to_dict()

        if self.evidence:
            result["evidence"] = [e.to_dict() for e in self.evidence]

        if self.remediation:
            result["remediation"] = self.remediation.to_dict()

        if self.compliance:
            result["compliance"] = self.compliance

        if self.created_by:
            result["created_by"] = self.created_by

        if self.assigned_to:
            result["assigned_to"] = self.assigned_to

        return result


@dataclass
class AssessmentResult:
    """
    Overall result of a security assessment.

    Contains all findings, metadata, and summary information from an assessment.
    """

    assessment_id: str
    name: str
    target: Union[AssessmentTarget, List[AssessmentTarget]]
    findings: List[Finding] = field(default_factory=list)
    start_time: datetime.datetime = field(default_factory=datetime.datetime.now)
    end_time: Optional[datetime.datetime] = None
    status: str = "completed"
    summary: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Initialize calculated fields."""
        if not self.end_time:
            self.end_time = datetime.datetime.now()

        if not self.summary:
            self.generate_summary()

    def add_finding(self, finding: Finding) -> None:
        """
        Add a finding to the results.

        Args:
            finding: Finding to add
        """
        self.findings.append(finding)
        self.generate_summary()

    def generate_summary(self) -> None:
        """Generate summary information about the findings."""
        severity_counts = {severity.value: 0 for severity in FindingSeverity}
        status_counts = {status.value: 0 for status in FindingStatus}

        for finding in self.findings:
            severity_counts[finding.severity.value] += 1
            status_counts[finding.status.value] += 1

        severity_counts["total"] = len(self.findings)

        categories = {}
        for finding in self.findings:
            categories.setdefault(finding.category, 0)
            categories[finding.category] += 1

        self.summary = {
            "severity_counts": severity_counts,
            "status_counts": status_counts,
            "categories": categories,
            "duration_seconds": (self.end_time - self.start_time).total_seconds(),
            "risk_level": self._calculate_risk_level()
        }

    def _calculate_risk_level(self) -> RiskLevel:
        """
        Calculate overall risk level based on findings.

        Returns:
            Overall risk level
        """
        if not self.findings:
            return RiskLevel.NEGLIGIBLE

        severity_counts = {
            FindingSeverity.CRITICAL: 0,
            FindingSeverity.HIGH: 0,
            FindingSeverity.MEDIUM: 0,
            FindingSeverity.LOW: 0,
            FindingSeverity.INFO: 0
        }

        for finding in self.findings:
            severity_counts[finding.severity] += 1

        # Determine risk level based on severity distribution
        if severity_counts[FindingSeverity.CRITICAL] > 0:
            return RiskLevel.CRITICAL
        elif severity_counts[FindingSeverity.HIGH] > 0:
            return RiskLevel.HIGH
        elif severity_counts[FindingSeverity.MEDIUM] > 0:
            return RiskLevel.MEDIUM
        elif severity_counts[FindingSeverity.LOW] > 0:
            return RiskLevel.LOW
        else:
            return RiskLevel.NEGLIGIBLE

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert results to dictionary.

        Returns:
            Dictionary representation of assessment results
        """
        # Handle both single target and multiple targets
        if isinstance(self.target, list):
            targets = [t.to_dict() for t in self.target]
        else:
            targets = self.target.to_dict()

        return {
            "assessment_id": self.assessment_id,
            "name": self.name,
            "target": targets,
            "findings": [f.to_dict() for f in self.findings],
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "status": self.status,
            "summary": self.summary,
            "errors": self.errors,
            "warnings": self.warnings
        }

    def to_json(self, indent: int = 2) -> str:
        """
        Convert results to JSON string.

        Args:
            indent: JSON indentation level

        Returns:
            JSON string representation
        """
        return json.dumps(self.to_dict(), indent=indent)

    def save_to_file(self, file_path: Union[str, Path], indent: int = 2) -> bool:
        """
        Save results to a JSON file.

        Args:
            file_path: Path where to save the JSON file
            indent: JSON indentation level

        Returns:
            True if successful, False otherwise
        """
        try:
            # Convert string path to Path object for better path handling
            path_obj = Path(file_path) if isinstance(file_path, str) else file_path

            # Create parent directories if they don't exist
            path_obj.parent.mkdir(parents=True, exist_ok=True)

            # Use atomic write pattern by first writing to a temporary file
            temp_file = path_obj.with_suffix('.tmp')
            with open(temp_file, 'w') as f:
                json.dump(self.to_dict(), f, indent=indent)

            # Attempt to set secure permissions (0600 - owner read/write only)
            try:
                import os
                os.chmod(temp_file, 0o600)
            except (ImportError, OSError):
                # Continue even if setting permissions fails
                pass

            # Rename to target file (atomic on most filesystems)
            temp_file.rename(path_obj)

            return True
        except (IOError, OSError, TypeError) as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to save assessment results to {file_path}: {str(e)}")
            return False


@dataclass
class ComplianceMapping:
    """
    Maps findings to specific compliance framework controls.

    Enables detailed mapping of security findings to regulatory requirements.
    """

    framework: str  # e.g., "pci-dss", "nist-csf", "iso27001"
    version: str  # Framework version
    control_mappings: Dict[str, List[str]] = field(default_factory=dict)  # Maps finding IDs to control IDs
    control_descriptions: Dict[str, str] = field(default_factory=dict)  # Describes each control
    compliance_status: Dict[str, str] = field(default_factory=dict)  # Status per control

    def add_finding_mapping(self, finding_id: str, control_ids: List[str]) -> None:
        """Map a finding to compliance controls."""
        self.control_mappings[finding_id] = control_ids

    def set_compliance_status(self, control_id: str, status: str) -> None:
        """Set compliance status for a control."""
        self.compliance_status[control_id] = status

    def to_dict(self) -> Dict[str, Any]:
        """Convert compliance mapping to dictionary."""
        return {
            "framework": self.framework,
            "version": self.version,
            "control_mappings": self.control_mappings,
            "control_descriptions": self.control_descriptions,
            "compliance_status": self.compliance_status
        }


@dataclass
class AssessmentContext:
    """
    Contextual information about an assessment.

    Contains business context, environment details, and assessment parameters.
    """

    environment: str  # e.g., "production", "development", "testing"
    business_criticality: str = "medium"  # low, medium, high, critical
    data_classification: str = "internal"  # public, internal, confidential, restricted
    system_owner: Optional[str] = None
    assessment_requestor: Optional[str] = None
    assessment_profile: Optional[str] = None  # Name of profile used
    authorized_by: Optional[str] = None
    scope_limitations: List[str] = field(default_factory=list)
    assessment_parameters: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert assessment context to dictionary."""
        return {
            "environment": self.environment,
            "business_criticality": self.business_criticality,
            "data_classification": self.data_classification,
            "system_owner": self.system_owner,
            "assessment_requestor": self.assessment_requestor,
            "assessment_profile": self.assessment_profile,
            "authorized_by": self.authorized_by,
            "scope_limitations": self.scope_limitations,
            "assessment_parameters": self.assessment_parameters
        }
