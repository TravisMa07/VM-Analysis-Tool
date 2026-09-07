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
