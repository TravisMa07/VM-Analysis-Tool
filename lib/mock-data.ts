import { CveDetailResponse, SearchResponse } from "@/lib/types";

export const DEMO_SEARCH_RESPONSE: SearchResponse = {
  query: "demo",
  mode: "keyword",
  totalResults: 2,
  results: [
    {
      cveId: "CVE-2024-3400",
      title: "Palo Alto PAN-OS command injection",
      summary:
        "A command injection vulnerability in GlobalProtect gateway and portal features can lead to unauthenticated remote code execution.",
      published: "2024-04-12T00:00:00.000Z",
      lastModified: "2024-05-10T00:00:00.000Z",
      cvssBaseScore: 10,
      cvssSeverity: "CRITICAL"
    },
    {
      cveId: "CVE-2023-4863",
      title: "libwebp heap buffer overflow",
      summary:
        "A crafted WebP image can trigger a heap buffer overflow in libwebp, impacting many downstream browsers and desktop apps.",
      published: "2023-09-12T00:00:00.000Z",
      lastModified: "2023-10-02T00:00:00.000Z",
      cvssBaseScore: 8.8,
      cvssSeverity: "HIGH"
    }
  ]
};

export const DEMO_CVE_ANALYSES: Record<string, CveDetailResponse> = {
  "CVE-2024-3400": {
    cveId: "CVE-2024-3400",
    description:
      "A command injection vulnerability in Palo Alto Networks PAN-OS GlobalProtect gateway and portal may allow an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.",
    published: "2024-04-12T00:00:00.000Z",
    lastModified: "2024-05-10T00:00:00.000Z",
    cwes: ["CWE-77: Command Injection", "CWE-78: OS Command Injection"],
    references: [
      {
        url: "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
        source: "CVE / NVD"
      },
      {
        url: "https://api.first.org/data/v1/epss?cve=CVE-2024-3400",
        source: "EPSS / FIRST"
      },
      {
        url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        source: "KEV / CISA"
      }
    ],
    cvss: {
      version: "3.1",
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      baseScore: 10,
      baseSeverity: "CRITICAL",
      exploitabilityScore: 3.9,
      impactScore: 6
    },
    epss: {
      cveId: "CVE-2024-3400",
      score: 0.945,
      percentile: 0.998,
      date: "2026-02-28"
    },
    kev: {
      listed: true,
      vendorProject: "Palo Alto Networks",
      product: "PAN-OS",
      vulnerabilityName: "PAN-OS GlobalProtect Command Injection",
      dateAdded: "2024-04-12",
      requiredAction:
        "Apply the vendor fix or mitigations immediately and verify device integrity.",
      dueDate: "2024-05-03",
      notes:
        "This issue has been observed in active exploitation against internet-facing firewalls."
    },
    sourceStatus: {
      nvd: "ok",
      epss: "ok",
      kev: "ok"
    }
  },
  "CVE-2023-4863": {
    cveId: "CVE-2023-4863",
    description:
      "A heap buffer overflow in libwebp can be triggered by crafted image data, with broad downstream impact due to widespread library reuse.",
    published: "2023-09-12T00:00:00.000Z",
    lastModified: "2023-10-02T00:00:00.000Z",
    cwes: ["CWE-122: Heap-based Buffer Overflow"],
    references: [
      {
        url: "https://nvd.nist.gov/vuln/detail/CVE-2023-4863",
        source: "CVE / NVD"
      },
      {
        url: "https://api.first.org/data/v1/epss?cve=CVE-2023-4863",
        source: "EPSS / FIRST"
      },
      {
        url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        source: "KEV / CISA"
      }
    ],
    cvss: {
      version: "3.1",
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
      baseScore: 8.8,
      baseSeverity: "HIGH",
      exploitabilityScore: 2.8,
      impactScore: 5.9
    },
    epss: {
      cveId: "CVE-2023-4863",
      score: 0.732,
      percentile: 0.982,
      date: "2026-02-28"
    },
    kev: {
      listed: false,
      vendorProject: null,
      product: null,
      vulnerabilityName: null,
      dateAdded: null,
      requiredAction: null,
      dueDate: null,
      notes: null
    },
    sourceStatus: {
      nvd: "ok",
      epss: "ok",
      kev: "not_listed"
    }
  }
};

export function getDemoCveAnalysis(cveId: string): CveDetailResponse | null {
  return DEMO_CVE_ANALYSES[cveId] ?? null;
}
