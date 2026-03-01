export type SearchMode = "cveId" | "keyword";

export type SearchResultItem = {
  cveId: string;
  title: string;
  summary: string;
  published?: string;
  lastModified?: string;
  cvssBaseScore?: number | null;
  cvssSeverity?: string | null;
};

export type SearchResponse = {
  query: string;
  mode: SearchMode;
  results: SearchResultItem[];
  totalResults: number;
};

export type CvssData = {
  version?: string | null;
  vector?: string | null;
  baseScore?: number | null;
  baseSeverity?: string | null;
  exploitabilityScore?: number | null;
  impactScore?: number | null;
};

export type EpssData = {
  cveId: string;
  score?: number | null;
  percentile?: number | null;
  date?: string | null;
};

export type KevData = {
  listed: boolean;
  vendorProject?: string | null;
  product?: string | null;
  vulnerabilityName?: string | null;
  dateAdded?: string | null;
  requiredAction?: string | null;
  dueDate?: string | null;
  notes?: string | null;
};

export type SourceStatus = {
  nvd: "ok" | "not_found" | "error";
  epss: "ok" | "not_found" | "error";
  kev: "ok" | "not_listed" | "error";
};

export type CveReference = {
  url: string;
  source?: string;
};

export type CveDetailResponse = {
  cveId: string;
  description: string;
  published?: string;
  lastModified?: string;
  cwes: string[];
  references: CveReference[];
  cvss: CvssData;
  epss: EpssData | null;
  kev: KevData;
  sourceStatus: SourceStatus;
};

export type NvdDetail = Omit<CveDetailResponse, "epss" | "kev" | "sourceStatus">;

