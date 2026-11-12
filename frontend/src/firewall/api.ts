export class ApiError extends Error {
  constructor(readonly code: string, readonly status = 0) { super(code); }
}

// Authentication stays in a Secure HttpOnly cookie. CSRF is held only in React memory.
export async function request<T>(path: string, body?: unknown, csrf?: string): Promise<T> {
  return requestAt<T>('/api/v1/', path, body, csrf);
}

export async function configurationRequest<T>(path: string, body?: unknown, csrf?: string, signal?: AbortSignal): Promise<T> {
  return requestAt<T>('/api/v2/', path, body, csrf, signal);
}

async function boundedJSON(response: Response): Promise<unknown> {
  if (!response.body) return null;
  const reader = response.body.getReader(), chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > 1024 * 1024) { await reader.cancel(); return null; }
      chunks.push(next.value);
    }
  } finally { reader.releaseLock(); }
  const data = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { data.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data)) as unknown; } catch { return null; }
}

async function requestAt<T>(prefix: '/api/v1/' | '/api/v2/', path: string, body?: unknown, csrf?: string, signal?: AbortSignal): Promise<T> {
  const controller = new AbortController();
  const abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true });
  if (signal?.aborted) controller.abort();
  const timeout = window.setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetch(`${prefix}${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal,
      headers: { Accept: 'application/json', 'X-ANDEIVA-Client': 'web', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(csrf ? { 'X-CSRF-Token': csrf } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const data: unknown = await boundedJSON(response);
    if (!response.ok) {
      const code = data && typeof data === 'object' && 'code' in data && typeof data.code === 'string' ? data.code : 'ANDEIVA_REQUEST_FAILED';
      throw new ApiError(code, response.status);
    }
    if (data === null) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
    return data as T;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError('ANDEIVA_CONNECTION_UNAVAILABLE');
  } finally { window.clearTimeout(timeout); signal?.removeEventListener('abort', abort); }
}
