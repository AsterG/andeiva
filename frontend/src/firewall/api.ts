export class ApiError extends Error {
  constructor(readonly code: string, readonly status = 0) { super(code); }
}

// Authentication stays in a Secure HttpOnly cookie. CSRF is held only in React memory.
export async function request<T>(path: string, body?: unknown, csrf?: string): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetch(`/api/v1/${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal,
      headers: { Accept: 'application/json', 'X-ANDEIVA-Client': 'web', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(csrf ? { 'X-CSRF-Token': csrf } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const data: unknown = await response.json().catch(() => null);
    if (!response.ok) {
      const code = data && typeof data === 'object' && 'code' in data && typeof data.code === 'string' ? data.code : 'ANDEIVA_REQUEST_FAILED';
      throw new ApiError(code, response.status);
    }
    if (data === null) throw new ApiError('ANDEIVA_RESPONSE_INVALID');
    return data as T;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError('ANDEIVA_CONNECTION_UNAVAILABLE');
  } finally { window.clearTimeout(timeout); }
}
