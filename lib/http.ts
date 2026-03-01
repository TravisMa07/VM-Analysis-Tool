import { REQUEST_TIMEOUT_MS } from "@/lib/config";

export class HttpError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "HttpError";
    this.status = status;
  }
}

type FetchJsonOptions = RequestInit & {
  timeoutMs?: number;
};

export async function fetchJson<T>(
  input: string | URL,
  options: FetchJsonOptions = {}
): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    options.timeoutMs ?? REQUEST_TIMEOUT_MS
  );

  try {
    const response = await fetch(input, {
      ...options,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(options.headers ?? {})
      },
      cache: "no-store"
    });

    if (!response.ok) {
      throw new HttpError(
        `Upstream request failed with status ${response.status}`,
        response.status
      );
    }

    return (await response.json()) as T;
  } finally {
    clearTimeout(timeout);
  }
}

