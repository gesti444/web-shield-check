import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { checkSite } from './checker.js';

const htmlPath = fileURLToPath(new URL('../public/index.html', import.meta.url));
const port = Number(process.env.PORT || 3000);

createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'");
  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(await readFile(htmlPath));
  }
  if (req.method === 'POST' && req.url === '/api/check') {
    try {
      let body = '';
      for await (const chunk of req) {
        body += chunk;
        if (body.length > 4096) throw new Error('Request too large.');
      }
      const { url } = JSON.parse(body);
      if (typeof url !== 'string' || !url.trim()) throw new Error('Enter a website URL.');
      const result = await checkSite(url.trim());
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(result));
    } catch (error) {
      res.writeHead(400, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ error: error.message || 'Check failed.' }));
    }
  }
  res.writeHead(404).end('Not found');
}).listen(port, () => console.log(`Web Shield Check: http://localhost:${port}`));
