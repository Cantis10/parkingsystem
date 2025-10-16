import fs from 'fs';
import path from 'path';

export default function handler(req, res) {
  const htmlPath = path.join(process.cwd(), 'public', 'home.html');
  const cssPath = path.join(process.cwd(), 'public', 'styles.css');

  let html = fs.readFileSync(htmlPath, 'utf8');
  const css = fs.readFileSync(cssPath, 'utf8');

  // Inject CSS into HTML head
  html = html.replace('</head>', `<style>${css}</style></head>`);

  res.setHeader('Content-Type', 'text/html');
  res.status(200).send(html);
}
