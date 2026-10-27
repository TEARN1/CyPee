// The dashboard's sign-in token. It lives only for this browser tab and is
// added to every call to this CyPee's own /api/, so the protected panels work.

const KEY = 'cypee_token';

export function getToken(): string | null {
  try {
    return sessionStorage.getItem(KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null): void {
  try {
    if (token) sessionStorage.setItem(KEY, token);
    else sessionStorage.removeItem(KEY);
  } catch {
    // Storage blocked: the user signs in again next time.
  }
}

/** Wraps fetch once, at start-up, so same-origin /api/ calls carry the token. */
export function installAuthFetch(): void {
  const original = window.fetch.bind(window);
  window.fetch = (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const path = url.startsWith(window.location.origin) ? url.slice(window.location.origin.length) : url;
    const token = getToken();
    if (token && path.startsWith('/api/')) {
      const headers = new Headers(init.headers ?? (input instanceof Request ? input.headers : undefined));
      if (!headers.has('Authorization')) headers.set('Authorization', `Bearer ${token}`);
      init = { ...init, headers };
    }
    return original(input, init);
  };
}
