import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json' } });

export default async (req) => {
  if (req.method !== 'POST') return J({ error: 'Метод не підтримується' }, 405);
  let b; try { b = await req.json(); } catch { return J({ error: 'Некоректний запит' }, 400); }
  const email = String(b.email || '').trim().toLowerCase();
  if (email.length > 120 || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return J({ error: 'Перевір адресу пошти' }, 400);
  const sec = process.env.SESSION_SECRET, key = process.env.RESEND_API_KEY;
  if (!sec || !key) return J({ error: 'Сервер ще не налаштований (немає ключів)' }, 500);

  const st = getStore({ name: 'codes', consistency: 'strong' });
  const id = crypto.createHash('sha256').update(email).digest('hex');
  const old = await st.get(id, { type: 'json' });
  if (old && Date.now() - old.sent < 60000) return J({ error: 'Зачекай хвилину перед повторною відправкою' }, 429);

  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const h = crypto.createHmac('sha256', sec).update(email + ':' + code).digest('hex');
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + key, 'content-type': 'application/json' },
    body: JSON.stringify({
      from: process.env.MAIL_FROM || 'Luno <onboarding@resend.dev>',
      to: [email],
      subject: 'Твій код входу в Luno: ' + code,
      html: `<div style="font-family:system-ui,sans-serif;font-size:16px"><p>Твій код входу:</p><p style="font-size:32px;font-weight:700;letter-spacing:6px">${code}</p><p style="color:#666">Код діє 10 хвилин. Якщо це був не ти, просто проігноруй лист.</p></div>`
    })
  });
  if (!r.ok) return J({ error: 'Не вдалося надіслати лист. Спробуй пізніше' }, 502);
  await st.setJSON(id, { h, exp: Date.now() + 10 * 60000, tries: 0, sent: Date.now() });
  return J({ ok: true });
};
export const config = { path: '/api/send-code' };
