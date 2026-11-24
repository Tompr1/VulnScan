from datetime import datetime, timezone
from sqlalchemy import String, Integer, Text, Boolean, DateTime, ForeignKey, Float, Index, UniqueConstraint, CheckConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.session import Base


def now():
    return datetime.now(timezone.utc)


class Workspace(Base):
    __tablename__ = "workspaces"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)


class User(Base):
    """An account of the MSP. It belongs to no client: the clients it may open,
    and its role on each, come from its access grants (app.access)."""

    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), index=True, unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    # Admin of every client, present and future, without any grant.
    is_global_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    last_login_location: Mapped[str | None] = mapped_column(String(100), nullable=True)


# ── Access control: who may open which client (workspace) ──────────────────

class ClientGroup(Base):
    """A set of clients granted together (e.g. a region, a sector)."""

    __tablename__ = "client_groups"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ClientGroupMember(Base):
    __tablename__ = "client_group_members"
    __table_args__ = (UniqueConstraint("client_group_id", "workspace_id", name="uq_client_group_member"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    client_group_id: Mapped[int] = mapped_column(ForeignKey("client_groups.id", ondelete="CASCADE"), index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)


class UserGroup(Base):
    """A team of users granted together (e.g. level-1 technicians)."""

    __tablename__ = "user_groups"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class UserGroupMember(Base):
    __tablename__ = "user_group_members"
    __table_args__ = (UniqueConstraint("user_group_id", "user_id", name="uq_user_group_member"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_group_id: Mapped[int] = mapped_column(ForeignKey("user_groups.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)


class AccessGrant(Base):
    """A role given to a user or a user group, on a client or a client group.
    Exactly one principal and one scope are set; deleting either deletes the grant."""

    __tablename__ = "access_grants"
    __table_args__ = (
        CheckConstraint("(user_id IS NULL) <> (user_group_id IS NULL)", name="ck_access_grant_one_principal"),
        CheckConstraint("(workspace_id IS NULL) <> (client_group_id IS NULL)", name="ck_access_grant_one_scope"),
        CheckConstraint("role IN ('admin', 'analyst', 'viewer')", name="ck_access_grant_role"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    user_group_id: Mapped[int | None] = mapped_column(
        ForeignKey("user_groups.id", ondelete="CASCADE"), nullable=True, index=True
    )
    workspace_id: Mapped[int | None] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=True, index=True
    )
    client_group_id: Mapped[int | None] = mapped_column(
        ForeignKey("client_groups.id", ondelete="CASCADE"), nullable=True, index=True
    )
    role: Mapped[str] = mapped_column(String(50))  # admin|analyst|viewer
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Credential(Base):
    __tablename__ = "credentials"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(50), default="ssh")
    username: Mapped[str] = mapped_column(String(255))
    secret_enc: Mapped[str] = mapped_column(Text)
    secret_type: Mapped[str] = mapped_column(String(50), default="password")  # password|ssh_key
    passphrase_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class CveDataset(Base):
    """A reference dataset file (NVD, KEV, EPSS…), shared by every client."""

    __tablename__ = "cve_datasets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(50))
    path: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Profile(Base):
    __tablename__ = "profiles"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    plugin_selection_json: Mapped[str] = mapped_column(Text, default="{}")
    options_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    target: Mapped[str] = mapped_column(String(512))
    # Nullable in the database since the startup migration: API, IaC and
    # inventory jobs have no scan profile.
    profile_id: Mapped[int | None] = mapped_column(ForeignKey("profiles.id"), nullable=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(50), default="queued")  # queued|running|done|failed|cancelled
    scan_type: Mapped[str] = mapped_column(String(20), default="internal")  # internal|external
    created_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    # Stamped when a worker picks the job up. The stale-job watchdog measures
    # from here: a job still waiting behind a busy queue has not started
    # spending its budget yet.
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    meta_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), nullable=True, index=True)
    owner: Mapped[str] = mapped_column(String(255), default="")
    default_profile_id: Mapped[int | None] = mapped_column(ForeignKey("profiles.id"), nullable=True)
    default_credential_id: Mapped[int | None] = mapped_column(ForeignKey("credentials.id"), nullable=True)
    tags_json: Mapped[str] = mapped_column(Text, default="[]")
    sla_overrides_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    schedule_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class WorkspaceSetting(Base):
    __tablename__ = "workspace_settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    key: Mapped[str] = mapped_column(String(100), index=True)
    value_json: Mapped[str] = mapped_column(Text, default="{}")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class PlatformSetting(Base):
    """A setting of the whole platform, shared by every client (app.core.platform_settings)."""

    __tablename__ = "platform_settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(100), unique=True)
    value_json: Mapped[str] = mapped_column(Text, default="{}")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ReportTemplate(Base):
    __tablename__ = "report_templates"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    # Sections to include (JSON list of section ids)
    sections_json: Mapped[str] = mapped_column(Text, default='["summary","severity","findings","remediation"]')
    # Severity filter (JSON list, e.g. ["critical","high"])
    severities_json: Mapped[str] = mapped_column(Text, default='["critical","high","medium","low","info"]')
    # Branding & options
    options_json: Mapped[str] = mapped_column(Text, default='{}')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    target: Mapped[str] = mapped_column(String(512))
    plugin_id: Mapped[str] = mapped_column(String(255), index=True)
    title: Mapped[str] = mapped_column(String(1024))
    severity: Mapped[str] = mapped_column(String(50), default="info")
    description: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    references_json: Mapped[str] = mapped_column(Text, default="[]")
    evidence: Mapped[str] = mapped_column(Text, default="")
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)

    cvss_base: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    status: Mapped[str] = mapped_column(String(50), default="open")
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_days: Mapped[int | None] = mapped_column(Integer, nullable=True)

    compliance_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    # Set on inventory audit findings: the device page the alert links to.
    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("inventory_devices.id", ondelete="SET NULL"), nullable=True, index=True
    )


class SuppressedFinding(Base):
    __tablename__ = "suppressed_findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    target: Mapped[str] = mapped_column(String(512))
    profile_id: Mapped[int] = mapped_column(ForeignKey("profiles.id"))
    scan_type: Mapped[str] = mapped_column(String(20), default="internal")
    # Schedule mode: "interval" (recurring) or "custom" (specific datetime)
    schedule_type: Mapped[str] = mapped_column(String(20), default="interval")
    interval_hours: Mapped[int] = mapped_column(Integer, default=24)
    # For custom: specific datetime + optional repeat
    custom_datetime: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    repeat: Mapped[bool] = mapped_column(Boolean, default=True)  # False = run once then disable
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(Integer, index=True)
    actor_email: Mapped[str] = mapped_column(String(255), default="")
    action: Mapped[str] = mapped_column(String(255))
    resource: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Integration(Base):
    __tablename__ = "integrations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    provider: Mapped[str] = mapped_column(String(50))  # slack | email | webhook
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    config_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AiProviderConfig(Base):
    __tablename__ = "ai_provider_configs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    provider_type: Mapped[str] = mapped_column(String(50))       # openai | claude_api | gemini | azure_openai | openai_compat
    name: Mapped[str] = mapped_column(String(100))               # Display name
    model: Mapped[str] = mapped_column(String(100))              # Model ID
    api_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)  # Encrypted API key
    endpoint: Mapped[str | None] = mapped_column(String(500), nullable=True)  # Custom endpoint URL
    extra_json: Mapped[str] = mapped_column(Text, default="{}")  # Provider-specific config
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AiAnalysis(Base):
    __tablename__ = "ai_analyses"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    provider: Mapped[str] = mapped_column(String(50))          # azure_openai | claude_cli | gemini
    mode: Mapped[str] = mapped_column(String(50))              # validate | full | full_exploit
    status: Mapped[str] = mapped_column(String(50), default="queued")  # queued | running | done | failed
    progress_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    token_usage: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    # Set when a worker actually picks the analysis up. The stale-analysis
    # watchdog measures from here, not from created_at — otherwise an analysis
    # still waiting behind a busy queue gets failed before it ever runs.
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ── CVE catalog (global: the same NVD data serves every workspace) ──────────
# Imported page by page from the NVD API (app/cve/nvd_sync.py) and queried by
# product, so the whole history never has to be held in memory.

class CveEntry(Base):
    __tablename__ = "cve_catalog"
    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    references_json: Mapped[str] = mapped_column(Text, default="[]")
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CveCpeMatch(Base):
    __tablename__ = "cve_cpe_matches"
    __table_args__ = (Index("ix_cve_cpe_matches_product", "vendor", "product"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("cve_catalog.cve_id", ondelete="CASCADE"), index=True)
    part: Mapped[str] = mapped_column(String(1))
    vendor: Mapped[str] = mapped_column(String(128))  # canonical vendor (aliases resolved)
    product: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(Text, default="*")
    start_including: Mapped[str | None] = mapped_column(Text, nullable=True)
    start_excluding: Mapped[str | None] = mapped_column(Text, nullable=True)
    end_including: Mapped[str | None] = mapped_column(Text, nullable=True)
    end_excluding: Mapped[str | None] = mapped_column(Text, nullable=True)


class CveSyncState(Base):
    """Progress of a catalog import, so an interrupted run resumes."""

    __tablename__ = "cve_sync_state"
    source: Mapped[str] = mapped_column(String(32), primary_key=True)  # "nvd"
    full_import_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    full_import_next_index: Mapped[int] = mapped_column(Integer, default=0)
    full_import_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    full_import_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Changes up to this instant are in the catalog; the next incremental run starts here.
    synced_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ── Device inventory (fleet managers: Intune, later GLPI / Fleet) ───────────

class InventoryConnection(Base):
    """A fleet manager tenant to collect devices from. The secret is stored
    encrypted (app.core.crypto) and never returned by the API."""

    __tablename__ = "inventory_connections"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    provider: Mapped[str] = mapped_column(String(32), default="intune")
    name: Mapped[str] = mapped_column(String(255))
    tenant_id: Mapped[str] = mapped_column(String(64))
    client_id: Mapped[str] = mapped_column(String(64))
    client_secret_enc: Mapped[str] = mapped_column(Text)
    sync_frequency: Mapped[str] = mapped_column(String(16), default="daily")  # manual | daily | weekly
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    # Set when a sync is queued, so the scheduler does not queue it twice.
    last_sync_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_status: Mapped[str | None] = mapped_column(String(16), nullable=True)  # queued | ok | error
    last_sync_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class InventoryDevice(Base):
    __tablename__ = "inventory_devices"
    __table_args__ = (UniqueConstraint("connection_id", "external_id", name="uq_inventory_device_source_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    connection_id: Mapped[int] = mapped_column(ForeignKey("inventory_connections.id", ondelete="CASCADE"), index=True)
    external_id: Mapped[str] = mapped_column(String(128))
    name: Mapped[str] = mapped_column(String(255))
    platform: Mapped[str] = mapped_column(String(16), index=True)
    os_name: Mapped[str] = mapped_column(String(64), default="")
    os_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    model: Mapped[str | None] = mapped_column(String(255), nullable=True)
    manufacturer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(255), nullable=True)
    user_principal_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ownership: Mapped[str | None] = mapped_column(String(32), nullable=True)
    compliance_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    is_encrypted: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    security_patch_level: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_check_in_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    # Set when the device disappears from the fleet manager; history is kept.
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class InventoryDeviceApp(Base):
    __tablename__ = "inventory_device_apps"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("inventory_devices.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(512))
    version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    publisher: Mapped[str | None] = mapped_column(String(512), nullable=True)


class InventoryDeviceChange(Base):
    """Journal of what changed on a device between two collections."""

    __tablename__ = "inventory_device_changes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("inventory_devices.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    subject: Mapped[str] = mapped_column(String(512))
    before: Mapped[str | None] = mapped_column(String(255), nullable=True)
    after: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class InventoryAuditRun(Base):
    """One audit of a connection's inventory, run by an inventory job whose
    findings hold the issues. The device page shows the latest completed one;
    the alert policy compares two consecutive ones."""

    __tablename__ = "inventory_audit_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    connection_id: Mapped[int] = mapped_column(ForeignKey("inventory_connections.id", ondelete="CASCADE"), index=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True)
    audited_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    devices: Mapped[int] = mapped_column(Integer, default=0)
    issues: Mapped[int] = mapped_column(Integer, default=0)
    # Lifecycle sources that could not be read, rule failures… empty when complete.
    warnings: Mapped[str] = mapped_column(Text, default="")
