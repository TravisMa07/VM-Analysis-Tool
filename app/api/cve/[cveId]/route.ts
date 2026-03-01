import { NextResponse } from "next/server";
import { getCveAnalysis } from "@/lib/services/cve-analysis";
import { isValidCveId, normalizeCveId } from "@/lib/utils";

export const dynamic = "force-dynamic";

type Props = {
  params:
    | {
        cveId: string;
      }
    | Promise<{
        cveId: string;
      }>;
};

export async function GET(_request: Request, { params }: Props) {
  const resolvedParams = await Promise.resolve(params);
  const cveId = normalizeCveId(resolvedParams.cveId);

  if (!isValidCveId(cveId)) {
    return NextResponse.json(
      { error: "The supplied CVE ID is invalid." },
      { status: 400 }
    );
  }

  try {
    const payload = await getCveAnalysis(cveId);

    if (!payload) {
      return NextResponse.json(
        { error: "The requested CVE was not found in NVD." },
        { status: 404 }
      );
    }

    return NextResponse.json(payload);
  } catch (error) {
    const message =
      error instanceof Error
        ? error.message
        : "Unable to load the CVE analysis right now.";

    return NextResponse.json({ error: message }, { status: 502 });
  }
}
