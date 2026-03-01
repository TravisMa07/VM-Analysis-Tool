export const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/i;

export function normalizeCveId(value: string): string {
  return value.trim().toUpperCase();
}

export function isValidCveId(value: string): boolean {
  return CVE_ID_PATTERN.test(normalizeCveId(value));
}

export function isLikelyCveIdQuery(value: string): boolean {
  return isValidCveId(value);
}

export function truncateText(value: string, maxLength: number): string {
  if (value.length <= maxLength) {
    return value;
  }

  return `${value.slice(0, Math.max(0, maxLength - 1)).trimEnd()}…`;
}

export function formatPercent(value?: number | null): string {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return "Not available";
  }

  return `${(value * 100).toFixed(2)}%`;
}

export function formatDate(value?: string | null): string {
  if (!value) {
    return "Not available";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric"
  }).format(date);
}

