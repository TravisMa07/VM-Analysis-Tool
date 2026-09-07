"""Python field names internally; camelCase JSON preserves the original API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class ApiModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, allow_inf_nan=False)


class CvssData(ApiModel):
    version: str | None = None
    vector: str | None = None
    base_score: float | None = Field(default=None, ge=0, le=10)
    base_severity: str | None = None
    exploitability_score: float | None = None
    impact_score: float | None = None


class EpssData(ApiModel):
    cve_id: str
    score: float | None = None
    percentile: float | None = None
    date: str | None = None


class KevData(ApiModel):
    # None means the catalog could not be checked; False means checked, absent.
    listed: bool | None = None
    vendor_project: str | None = None
    product: str | None = None
    vulnerability_name: str | None = None
    date_added: str | None = None
    required_action: str | None = None
    due_date: str | None = None
    notes: str | None = None


class SourceStatus(ApiModel):
    nvd: Literal["ok", "not_found", "error"]
    epss: Literal["ok", "not_found", "error"]
    kev: Literal["ok", "not_listed", "error"]


class CveReference(ApiModel):
    url: str
    source: str | None = None
    tags: list[str] = Field(default_factory=list)


class VendorGuidance(ApiModel):
    cve_id: str
    vendor: str
    product: str
    platform: str
    component: str | None = None
    title: str | None = None
    affected_versions: str | None = None
    fixed_version: str | None = None
    advisory_url: str
    package_url: str | None = None
    remediation: str
    mitigation: str | None = None
    verified_on: str
    confidence: Literal["reviewed", "needs_review"] = "reviewed"
    applicability: Literal["potentially_applicable", "needs_asset_context"] = "needs_asset_context"
    source_type: Literal["vendor_advisory", "patch", "release_notes", "support"] = "vendor_advisory"
    automated: bool = True
    packages: list[str] = Field(default_factory=list)
    update_identifiers: list[str] = Field(default_factory=list)
    commands: list["AdvisoryCommand"] = Field(default_factory=list)
    reboot_required: bool | None = None
    exploitation_status: str | None = None
    extraction_confidence: Literal["high", "medium", "low", "none"] = "none"
    extraction_warnings: list[str] = Field(default_factory=list)
    fetched_at: str | None = None
    expires_at: str | None = None
    stale: bool = False
    advisory_status: Literal["not_available", "discovered", "extracted", "partial", "stale", "error"] = "discovered"
    source_section: str | None = None


class AdvisoryCommand(ApiModel):
    command: str
    platform: str | None = None
    source_url: str
    source_section: str | None = None
    confidence: Literal["high", "medium", "low"] = "medium"
    warning: str = "Vendor-provided command; display only. Review before execution."


class SourceFreshness(ApiModel):
    nvd_last_modified: str | None = None
    epss_date: str | None = None
    kev_date_added: str | None = None
    vendor_verified_on: str | None = None


class AssetContext(ApiModel):
    os: str | None = None
    product: str | None = None
    version: str | None = None


class NvdDetail(ApiModel):
    cve_id: str
    description: str
    published: str | None = None
    last_modified: str | None = None
    cwes: list[str] = Field(default_factory=list)
    references: list[CveReference] = Field(default_factory=list)
    cvss: CvssData = Field(default_factory=CvssData)


class CveDetailResponse(NvdDetail):
    epss: EpssData | None
    kev: KevData
    source_status: SourceStatus
    vendor_guidance: list[VendorGuidance] = Field(default_factory=list)
    vendor_guidance_status: Literal["matched", "not_available", "error"] = "not_available"
    source_freshness: SourceFreshness = Field(default_factory=SourceFreshness)
    asset_context: AssetContext | None = None
    advisory_status: Literal["not_available", "discovered", "extracted", "partial", "stale", "error"] = "not_available"


class SearchResultItem(ApiModel):
    cve_id: str
    title: str
    summary: str
    published: str | None = None
    last_modified: str | None = None
    cvss_base_score: float | None = None
    cvss_severity: str | None = None


class SearchResponse(ApiModel):
    query: str
    mode: Literal["cveId", "keyword"]
    results: list[SearchResultItem]
    total_results: int


class ErrorResponse(ApiModel):
    error: str
