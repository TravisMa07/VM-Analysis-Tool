import { fetchJson } from "@/lib/http";
import { KevData } from "@/lib/types";
import { normalizeCveId } from "@/lib/utils";

const KEV_API_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

type KevCatalogResponse = {
  vulnerabilities?: Array<{
    cveID?: string;
    vendorProject?: string;
    product?: string;
    vulnerabilityName?: string;
    dateAdded?: string;
    requiredAction?: string;
    dueDate?: string;
    shortDescription?: string;
    notes?: string;
  }>;
};

export function mapKevEntry(
  payload: KevCatalogResponse,
  cveId: string
): KevData {
  const normalizedCveId = normalizeCveId(cveId);
  const record = payload.vulnerabilities?.find(
    (entry) => normalizeCveId(entry.cveID ?? "") === normalizedCveId
  );

  if (!record) {
    return {
      listed: false,
      vendorProject: null,
      product: null,
      vulnerabilityName: null,
      dateAdded: null,
      requiredAction: null,
      dueDate: null,
      notes: null
    };
  }

  return {
    listed: true,
    vendorProject: record.vendorProject ?? null,
    product: record.product ?? null,
    vulnerabilityName: record.vulnerabilityName ?? null,
    dateAdded: record.dateAdded ?? null,
    requiredAction: record.requiredAction ?? null,
    dueDate: record.dueDate ?? null,
    notes: record.notes ?? record.shortDescription ?? null
  };
}

export async function getKev(cveId: string): Promise<KevData> {
  const payload = await fetchJson<KevCatalogResponse>(KEV_API_URL);
  return mapKevEntry(payload, cveId);
}

