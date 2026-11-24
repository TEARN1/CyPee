import { allowedGitHosts, repoUrlAllowed } from './repo-url';

// Pentest: a scan's repository address comes from the user. These are the
// addresses an attacker would give to reach things only the server can see.
describe('repository addresses (server-side request forgery)', () => {
  it('accepts https links on the public code hosts', () => {
    expect(repoUrlAllowed('https://github.com/TEARN1/CyPee')).toBe(true);
    expect(repoUrlAllowed('https://gitlab.com/group/project.git')).toBe(true);
  });

  it.each([
    'http://github.com/a/b', // not https
    'https://169.254.169.254/latest/meta-data/', // cloud metadata
    'https://localhost:3050/api/v1/health',
    'https://127.0.0.1/x',
    'https://[::1]/x',
    'https://10.0.0.5/repo.git', // private network
    'https://github.com.evil.example/a/b', // look-alike host
    'https://evil.example/github.com/a/b',
    'https://user:pass@github.com/a/b', // credentials in the link
    'https://github.com:8443/a/b',
    'file:///etc/passwd',
    'ext::sh -c touch% /tmp/pwned', // git's command transport
    '--upload-pack=touch /tmp/pwned',
    'not a url',
  ])('refuses %s', (url) => {
    expect(repoUrlAllowed(url)).toBe(false);
  });

  it('lets the owner add their own host, but only a real host name', () => {
    expect(allowedGitHosts('git.example.com, bad host, ')).toEqual(['github.com', 'gitlab.com', 'bitbucket.org', 'git.example.com']);
    expect(repoUrlAllowed('https://git.example.com/a/b', allowedGitHosts('git.example.com'))).toBe(true);
  });
});
