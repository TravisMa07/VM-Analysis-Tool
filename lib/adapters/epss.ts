import { fetchJson } from "@/lib/http";
import { EpssData } from "@/lib/types";
import { normalizeCveId } from "@/lib/utils";

const EPSS_API_URL = "https://api.first.org/data/v1/epss";

type EpssApiResponse = {
  data?: Array<{
    cve?: string;
    epss?: string;
    percentile?: string;
    date?: string;
  }>;
};

function toNumber(value?: string): number | null {
  if (!value) {
    return null;
  }

  const parsed = Number.parseFloat(value);
  return Number.isNaN(parsed) ? null : parsed;
}

export function mapEpssResponse(
  cveId: string,
  payload: EpssApiResponse
): EpssData | null {
  const record = payload.data?.[0];

  if (!record?.cve) {
    return null;
  }

  return {
    cveId: record.cve,
    score: toNumber(record.epss),
    percentile: toNumber(record.percentile),
    date: record.date ?? null
  };
}

export async function getEpss(cveId: string): Promise<EpssData | null> {
  const url = new URL(EPSS_API_URL);
  url.searchParams.set("cve", normalizeCveId(cveId));

  const payload = await fetchJson<EpssApiResponse>(url);
  return mapEpssResponse(cveId, payload);
}

