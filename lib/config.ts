const DEFAULT_TIMEOUT_MS = 8_000;

export const REQUEST_TIMEOUT_MS = Number.parseInt(
  process.env.REQUEST_TIMEOUT_MS ?? `${DEFAULT_TIMEOUT_MS}`,
  10
);

export const NVD_API_KEY = process.env.NVD_API_KEY;

