/**
 * Where CyPee may clone code from. A scan's repository address comes from the
 * signed-in user, so without this anyone with an account could make the
 * server fetch from private addresses (the cloud metadata service at
 * 169.254.169.254, or services on the server itself): server-side request
 * forgery. Only https on the public code hosts, plus any listed in
 * CYPEE_ALLOWED_GIT_HOSTS (comma-separated), is accepted.
 */
const DEFAULT_HOSTS = ['github.com', 'gitlab.com', 'bitbucket.org'];

export function allowedGitHosts(env: string | undefined = process.env.CYPEE_ALLOWED_GIT_HOSTS): string[] {
  const extra = (env ?? '')
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter((h) => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(h));
  return [...DEFAULT_HOSTS, ...extra];
}

export function repoUrlAllowed(raw: string, hosts = allowedGitHosts()): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.port) return false;
  const host = url.hostname.toLowerCase();
  return hosts.includes(host);
}

/** git settings for every clone: https only, and no following a redirect to somewhere else. */
export const SAFE_GIT_CONFIG = ['-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always', '-c', 'http.followRedirects=false'];
