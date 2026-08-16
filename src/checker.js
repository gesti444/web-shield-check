import dns from 'node:dns/promises';
import net from 'node:net';

export const HEADER_RULES = [
  ['strict-transport-security', 'HSTS', 'Forces browsers to use HTTPS.'],
  ['content-security-policy', 'Content Security Policy', 'Reduces cross-site scripting risk.'],
  ['x-content-type-options', 'MIME Sniffing Protection', 'Should normally be set to nosniff.'],
  ['referrer-policy', 'Referrer Policy', 'Controls information sent in the Referer header.'],
  ['permissions-policy', 'Permissions Policy', 'Restricts access to browser features.'],
  ['cross-origin-opener-policy', 'Cross-Origin Opener Policy', 'Helps isolate the browsing context.']
];

function isPrivate(address) {
  if (net.isIPv4(address)) {
    const p = address.split('.').map(Number);
    return p[0] === 10 || p[0] === 127 || p[0] === 0 ||
      (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) || (p[0] >= 224);
  }
  const value = address.toLowerCase();
  return value === '::1' || value === '::' || value.startsWith('fc') ||
    value.startsWith('fd') || value.startsWith('fe8') || value.startsWith('fe9') ||
    value.startsWith('fea') || value.startsWith('feb');
}

export async function validateTarget(input, lookup = dns.lookup) {
  const value = /^https?:\/\//i.test(input) ? input : `https://${input}`;
  const url = new URL(value);
  if (!['https:', 'http:'].includes(url.protocol)) throw new Error('Only HTTP and HTTPS URLs are supported.');
  if (url.username || url.password) throw new Error('Credentials in URLs are not allowed.');
  if (url.port && !['80', '443'].includes(url.port)) throw new Error('Only ports 80 and 443 are allowed.');
  const records = await lookup(url.hostname, { all: true, verbatim: true });
  if (!records.length || records.some(({ address }) => isPrivate(address))) {
    throw new Error('Private, local, or unresolved hosts are not allowed.');
  }
  return url;
}

export async function checkSite(input, options = {}) {
  const lookup = options.lookup ?? dns.lookup;
  const request = options.fetch ?? fetch;
  const url = await validateTarget(input, lookup);
  const started = performance.now();
  let current = url;
  let response;
  for (let redirects = 0; redirects <= 5; redirects += 1) {
    response = await request(current, {
      method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(8000),
      headers: { 'user-agent': 'WebShieldCheck/1.0 (+https://github.com/)' }
    });
    if (![301, 302, 303, 307, 308].includes(response.status)) break;
    if (redirects === 5) throw new Error('Too many redirects.');
    const location = response.headers.get('location');
    if (!location) throw new Error('Redirect response has no destination.');
    current = await validateTarget(new URL(location, current).href, lookup);
  }
  const checks = HEADER_RULES.map(([header, name, description]) => ({
    name, description, passed: response.headers.has(header), value: response.headers.get(header)
  }));
  const finalUrl = response.url || current.href;
  const https = new URL(finalUrl).protocol === 'https:';
  const passed = checks.filter(item => item.passed).length + (https ? 1 : 0);
  const total = checks.length + 1;
  return {
    requestedUrl: url.href, finalUrl, status: response.status,
    responseTimeMs: Math.round(performance.now() - started), score: Math.round((passed / total) * 100),
    checks: [{ name: 'HTTPS', description: 'Encrypts traffic between visitors and the website.', passed: https, value: https ? 'Enabled' : null }, ...checks]
  };
}
