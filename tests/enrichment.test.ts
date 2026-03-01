import { describe, expect, it } from "vitest";
import { mapEpssResponse } from "@/lib/adapters/epss";
import { mapKevEntry } from "@/lib/adapters/kev";

describe("enrichment adapters", () => {
  it("maps epss values into numeric fields", () => {
    const result = mapEpssResponse("CVE-2024-0001", {
      data: [
        {
          cve: "CVE-2024-0001",
          epss: "0.8123",
          percentile: "0.9911",
          date: "2026-02-28"
        }
      ]
    });

    expect(result?.score).toBeCloseTo(0.8123);
    expect(result?.percentile).toBeCloseTo(0.9911);
  });

  it("returns null when epss has no match", () => {
    const result = mapEpssResponse("CVE-2024-0001", {
      data: []
    });

    expect(result).toBeNull();
  });

  it("maps kev entries and falls back when not listed", () => {
    const listed = mapKevEntry(
      {
        vulnerabilities: [
          {
            cveID: "CVE-2024-0001",
            vendorProject: "Vendor",
            product: "Product",
            vulnerabilityName: "Actively exploited issue",
            dateAdded: "2026-02-01",
            requiredAction: "Patch immediately",
            dueDate: "2026-03-01",
            shortDescription: "Short description"
          }
        ]
      },
      "CVE-2024-0001"
    );

    const notListed = mapKevEntry(
      {
        vulnerabilities: []
      },
      "CVE-2024-9999"
    );

    expect(listed.listed).toBe(true);
    expect(listed.notes).toBe("Short description");
    expect(notListed.listed).toBe(false);
    expect(notListed.vendorProject).toBeNull();
  });
});

