import { NVD_API_KEY } from "@/lib/config";
import { fetchJson, HttpError } from "@/lib/http";
import {
  CvssData,
  NvdDetail,
  SearchMode,
  SearchResponse,
  SearchResultItem
} from "@/lib/types";
import {
  isLikelyCveIdQuery,
  normalizeCveId,
  truncateText
} from "@/lib/utils";

const NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";

type NvdMetric = {
  cvssData?: {
    version?: string;
    vectorString?: string;
    baseScore?: number;
    baseSeverity?: string;
  };
  exploitabilityScore?: number;
  impactScore?: number;
};

type NvdRecord = {
  cve?: {
    id?: string;
    published?: string;
    lastModified?: string;
    descriptions?: Array<{ lang?: string; value?: string }>;
    metrics?: {
      cvssMetricV31?: NvdMetric[];
      cvssMetricV30?: NvdMetric[];
      cvssMetricV2?: NvdMetric[];
    };
    weaknesses?: Array<{
      description?: Array<{ lang?: string; value?: string }>;
    }>;
    references?: Array<{ url?: string; source?: string }>;
  };
};

type NvdApiResponse = {
  totalResults?: number;
  vulnerabilities?: NvdRecord[];
};

function getHeaders(): HeadersInit | undefined {
  if (!NVD_API_KEY) {
    return undefined;
  }

  return {
    apiKey: NVD_API_KEY
  };
}

function pickEnglishValue(
  values?: Array<{ lang?: string; value?: string }>
): string | null {
  if (!values || values.length === 0) {
    return null;
  }

  const english = values.find((entry) => entry.lang === "en" && entry.value);
  const first = values.find((entry) => entry.value);

  return english?.value?.trim() ?? first?.value?.trim() ?? null;
}

export function mapMetricToCvss(metric?: NvdMetric): CvssData {
  if (!metric) {
    return {
      version: null,
      vector: null,
      baseScore: null,
      baseSeverity: null,
      exploitabilityScore: null,
      impactScore: null
    };
  }

  return {
    version: metric.cvssData?.version ?? null,
    vector: metric.cvssData?.vectorString ?? null,
    baseScore: metric.cvssData?.baseScore ?? null,
    baseSeverity: metric.cvssData?.baseSeverity ?? null,
    exploitabilityScore: metric.exploitabilityScore ?? null,
    impactScore: metric.impactScore ?? null
  };
}

function getPreferredMetric(record?: NvdRecord): NvdMetric | undefined {
  const metrics = record?.cve?.metrics;
  return (
    metrics?.cvssMetricV31?.[0] ??
    metrics?.cvssMetricV30?.[0] ??
    metrics?.cvssMetricV2?.[0]
  );
}

function getDescription(record?: NvdRecord): string {
  return (
    pickEnglishValue(record?.cve?.descriptions) ??
    "No description provided by NVD."
  );
}

function getCwes(record?: NvdRecord): string[] {
  return (
    record?.cve?.weaknesses
      ?.flatMap((weakness) => {
        const value = pickEnglishValue(weakness.description);
        return value ? [value] : [];
      })
      .filter(Boolean) ?? []
  );
}

function buildTitle(description: string): string {
  const firstSentence = description.split(".")[0]?.trim();
  if (firstSentence) {
    return truncateText(firstSentence, 100);
  }

  return truncateText(description, 100);
}

export function mapNvdRecordToSearchResult(record: NvdRecord): SearchResultItem {
  const description = getDescription(record);
  const cvss = mapMetricToCvss(getPreferredMetric(record));

  return {
    cveId: record.cve?.id ?? "Unknown CVE",
    title: buildTitle(description),
    summary: truncateText(description, 220),
    published: record.cve?.published,
    lastModified: record.cve?.lastModified,
    cvssBaseScore: cvss.baseScore ?? null,
    cvssSeverity: cvss.baseSeverity ?? null
  };
}

export function mapNvdRecordToDetail(record: NvdRecord): NvdDetail {
  return {
    cveId: record.cve?.id ?? "Unknown CVE",
    description: getDescription(record),
    published: record.cve?.published,
    lastModified: record.cve?.lastModified,
    cwes: getCwes(record),
    references:
      record.cve?.references
        ?.flatMap((reference) => {
          if (!reference.url) {
            return [];
          }

          return [
            {
              url: reference.url,
              source: reference.source
            }
          ];
        }) ?? [],
    cvss: mapMetricToCvss(getPreferredMetric(record))
  };
}

function buildSearchUrl(query: string, limit: number): { url: URL; mode: SearchMode } {
  const url = new URL(NVD_API_URL);
  const mode: SearchMode = isLikelyCveIdQuery(query) ? "cveId" : "keyword";

  if (mode === "cveId") {
    url.searchParams.set("cveId", normalizeCveId(query));
  } else {
    url.searchParams.set("keywordSearch", query.trim());
    url.searchParams.set("resultsPerPage", `${limit}`);
  }

  return { url, mode };
}

export async function searchNvd(query: string, limit = 10): Promise<SearchResponse> {
  const sanitizedLimit = Math.min(25, Math.max(1, limit));
  const { url, mode } = buildSearchUrl(query, sanitizedLimit);
  let payload: NvdApiResponse;

  try {
    payload = await fetchJson<NvdApiResponse>(url, {
      headers: getHeaders()
    });
  } catch (error) {
    if (error instanceof HttpError && error.status === 404) {
      return {
        query,
        mode,
        results: [],
        totalResults: 0
      };
    }

    throw error;
  }

  const results = (payload.vulnerabilities ?? []).map(mapNvdRecordToSearchResult);

  return {
    query,
    mode,
    results,
    totalResults: payload.totalResults ?? results.length
  };
}

export async function getNvdCve(cveId: string): Promise<NvdDetail | null> {
  const url = new URL(NVD_API_URL);
  url.searchParams.set("cveId", normalizeCveId(cveId));

  try {
    const payload = await fetchJson<NvdApiResponse>(url, {
      headers: getHeaders()
    });
    const record = payload.vulnerabilities?.[0];

    if (!record) {
      return null;
    }

    return mapNvdRecordToDetail(record);
  } catch (error) {
    if (error instanceof HttpError && error.status === 404) {
      return null;
    }

    throw error;
  }
}
