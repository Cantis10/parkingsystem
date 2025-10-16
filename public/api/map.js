// /api/login.js
import path from 'path';
import fs from 'fs';

export default function handler(req, res) {
  const filePath = path.join(process.cwd(), 'public', 'map.html');
  const html = fs.readFileSync(filePath, 'utf8');
  res.status(200).send(html);
}