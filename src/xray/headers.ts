export interface HeaderEntry {
  name: string;
  value: string;
}

export type V2HeaderMap = Record<string, string | string[]>;

/**
 * Converts raw headers to an array of header entries.
 */
export function toHeaders(v2Headers: unknown): HeaderEntry[] {
  const out: HeaderEntry[] = [];
  if (!v2Headers || typeof v2Headers !== 'object') return out;
  const map = v2Headers as Record<string, unknown>;
  for (const key of Object.keys(map)) {
    const values = map[key];
    if (typeof values === 'string') {
      out.push({ name: key, value: values });
    } else if (Array.isArray(values)) {
      for (const v of values) {
        if (typeof v === 'string') out.push({ name: key, value: v });
      }
    }
  }
  return out;
}

/**
 * Gets a header value by name case-insensitively.
 */
export function getHeaderValue(
  headers: Readonly<Record<string, string | string[]>> | undefined | null,
  name: string
): string {
  if (!headers || typeof headers !== 'object') return '';
  const lower = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() !== lower) continue;
    const value = headers[key];
    if (typeof value === 'string') return value;
    if (Array.isArray(value)) return value[0] ?? '';
  }
  return '';
}

/**
 * Converts an array of header entries to a raw headers map.
 */
export function toV2Headers(headers: HeaderEntry[], arr: boolean = true): V2HeaderMap {
  const out: V2HeaderMap = {};
  for (const { name, value } of headers) {
    if (name == null || name === '' || value == null || value === '') continue;
    if (!(name in out)) {
      out[name] = arr ? [value] : value;
      continue;
    }
    const existing = out[name];
    if (arr && Array.isArray(existing)) {
      existing.push(value);
    } else {
      out[name] = value;
    }
  }
  return out;
}
