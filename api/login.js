import fs from 'fs';
import path from 'path';

export default function handler(req, res) {
  const html = fs.readFileSync(path.join(process.cwd(), 'public/login.html'), 'utf8');
  const css = fs.readFileSync(path.join(process.cwd(), 'public/styles.css'), 'utf8');
  const htmlWithCSS = html.replace('</head>', `<style>${css}</style></head>`);

  res.setHeader('Content-Type', 'text/html');
  res.status(200).send(htmlWithCSS);
}