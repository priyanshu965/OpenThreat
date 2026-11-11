// Static server for the browser tests.
//
// Serves the repository root exactly as GitHub Pages would, with one
// difference: data/intel.json comes from fixtures/, because the real feed is
// built by the pipeline and never committed. Every other data/ endpoint that
// is missing answers 404, which is what a fresh deployment looks like and what
// each view is expected to survive.
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..', '..');
const FIXTURES = path.join(__dirname, 'fixtures');
const PORT = Number(process.env.E2E_PORT || 8766);

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.txt': 'text/plain; charset=utf-8',
};

// A page that frames the dashboard, for the clickjacking test. The sandbox
// withholds allow-top-navigation, so the guard cannot escape and has to hide.
const FRAMER = '<!doctype html><title>framer</title>'
  + '<iframe id="victim" src="/" sandbox="allow-scripts allow-same-origin"'
  + ' width="900" height="600"></iframe>';

function resolve(urlPath) {
  if (urlPath === '/data/intel.json') return path.join(FIXTURES, 'intel.json');
  // Absent on purpose, so a head file left by a local pipeline run cannot leak
  // into the tests. The specs that exercise it supply one with page.route().
  if (urlPath === '/data/feed-head.json') return path.join(FIXTURES, 'feed-head.json');
  const clean = path.normalize(decodeURIComponent(urlPath)).replace(/^([/\\])+/, '');
  const file = path.join(ROOT, clean || 'index.html');
  // Never serve outside the repository, whatever the URL says.
  return file.startsWith(ROOT + path.sep) || file === ROOT ? file : null;
}

http.createServer((req, res) => {
  const urlPath = new URL(req.url, 'http://localhost').pathname;
  // An empty page to attach routes on before the dashboard is requested.
  if (urlPath === '/__blank') {
    res.writeHead(200, { 'Content-Type': TYPES['.html'] });
    return res.end('<!doctype html><title>blank</title>');
  }
  if (urlPath === '/__framer') {
    res.writeHead(200, { 'Content-Type': TYPES['.html'] });
    return res.end(FRAMER);
  }
  let file = resolve(urlPath);
  if (file && fs.existsSync(file) && fs.statSync(file).isDirectory()) {
    file = path.join(file, 'index.html');
  }
  if (!file || !fs.existsSync(file)) {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    return res.end('not found');
  }
  res.writeHead(200, {
    'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream',
    'Cache-Control': 'no-store',
  });
  if (req.method === 'HEAD') return res.end();
  fs.createReadStream(file).pipe(res);
}).listen(PORT, '127.0.0.1', () => {
  console.log(`e2e server on http://127.0.0.1:${PORT}`);
});
