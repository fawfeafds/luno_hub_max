import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';
const ALLOWED = ['https://lunomotion.netlify.app', 'https://lunoeditor.netlify.app'];
const hmac = (sec, s, enc = 'hex') => crypto.createHmac('sha256', sec).update(s).digest(enc);
const safeEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

export default async (req) => {
  const origin = req.headers.get('origin');
  const cors = ALLOWED.includes(origin) ? { 'access-control-allow-origin': origin, 'access-control-allow-headers': 'content-type' } : {};
  const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', ...cors } });
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  if (req.method !== 'POST') return J({ error: 'Метод не підтримується' }, 405);
  let b; try { b = await req.json(); } catch { return J({ error: 'Некоректний запит' }, 400); }
  const sec = process.env.SESSION_SECRET;
  if (!sec) return J({ error: 'Сервер ще не налаштований' }, 500);

  if (b.token) { // перевірка вже виданої сесії
    const [p, sig] = String(b.token).split('.');
    if (!p || !sig || !safeEq(sig, hmac(sec, p, 'base64url'))) return J({ error: 'Сесія недійсна' }, 401);
    let pl; try { pl = JSON.parse(Buffer.from(p, 'base64url').toString()); } catch { return J({ error: 'Сесія недійсна' }, 401); }
    if (!pl.exp || pl.exp < Date.now()) return J({ error: 'Сесія закінчилась' }, 401);
    return J({ ok: true, email: pl.e });
  }

  const email = String(b.email || '').trim().toLowerCase(), code = String(b.code || '').trim();
  if (!/^\d{6}$/.test(code)) return J({ error: 'Код має складатися з 6 цифр' }, 400);
  const st = getStore({ name: 'codes', consistency: 'strong' });
  const id = crypto.createHash('sha256').update(email).digest('hex');
  const rec = await st.get(id, { type: 'json' });
  if (!rec || rec.exp < Date.now()) return J({ error: 'Код недійсний або прострочений. Запроси новий' }, 400);
  if (rec.tries >= 5) { await st.delete(id); return J({ error: 'Забагато спроб. Запроси новий код' }, 429); }
  if (!safeEq(hmac(sec, email + ':' + code), rec.h)) { rec.tries++; await st.setJSON(id, rec); return J({ error: 'Невірний код' }, 400); }
  await st.delete(id);
  const p = Buffer.from(JSON.stringify({ e: email, exp: Date.now() + 30 * 86400000 })).toString('base64url');
  return J({ ok: true, email, token: p + '.' + hmac(sec, p, 'base64url') });
};
export const config = { path: '/api/verify-code' };
