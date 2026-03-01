import { NextRequest, NextResponse } from "next/server";
import { searchNvd } from "@/lib/adapters/nvd";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const query = request.nextUrl.searchParams.get("q")?.trim() ?? "";
  const requestedLimit = Number.parseInt(
    request.nextUrl.searchParams.get("limit") ?? "10",
    10
  );

  if (!query) {
    return NextResponse.json(
      { error: "The q query parameter is required." },
      { status: 400 }
    );
  }

  const limit = Number.isNaN(requestedLimit) ? 10 : requestedLimit;

  try {
    const payload = await searchNvd(query, limit);
    return NextResponse.json(payload);
  } catch (error) {
    const message =
      error instanceof Error
        ? error.message
        : "Unable to search NVD at this time.";

    return NextResponse.json({ error: message }, { status: 502 });
  }
}

