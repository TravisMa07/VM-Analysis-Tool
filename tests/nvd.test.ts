import { describe, expect, it } from "vitest";
import {
  mapMetricToCvss,
  mapNvdRecordToDetail,
  mapNvdRecordToSearchResult
} from "@/lib/adapters/nvd";

describe("nvd adapter", () => {
  it("maps search data with preferred fields", () => {
    const result = mapNvdRecordToSearchResult({
      cve: {
        id: "CVE-2024-9999",
        published: "2024-02-01T00:00:00.000",
        descriptions: [
          { lang: "en", value: "Example product remote code execution flaw." }
        ],
        metrics: {
          cvssMetricV31: [
            {
              cvssData: {
                version: "3.1",
                baseScore: 9.8,
                baseSeverity: "CRITICAL",
                vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
              }
            }
          ]
        }
      }
    });

    expect(result.cveId).toBe("CVE-2024-9999");
    expect(result.cvssBaseScore).toBe(9.8);
    expect(result.cvssSeverity).toBe("CRITICAL");
    expect(result.summary).toContain("remote code execution");
  });

  it("maps detail data when optional fields are absent", () => {
    const result = mapNvdRecordToDetail({
      cve: {
        id: "CVE-2023-1111",
        descriptions: [],
        weaknesses: [],
        references: []
      }
    });

    expect(result.description).toBe("No description provided by NVD.");
    expect(result.cwes).toEqual([]);
    expect(result.references).toEqual([]);
    expect(result.cvss.baseScore).toBeNull();
  });

  it("returns empty cvss data when no metric is provided", () => {
    const cvss = mapMetricToCvss(undefined);

    expect(cvss.baseScore).toBeNull();
    expect(cvss.vector).toBeNull();
    expect(cvss.baseSeverity).toBeNull();
  });
});

