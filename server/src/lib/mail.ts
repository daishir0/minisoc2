import nodemailer from 'nodemailer';
import { getMail, mailPassword, type MailSettings } from './settings';

// The SMTP user defaults to the address in "From" when left empty (for Gmail they are the same).
export function smtpUser(m: MailSettings): string {
  return m.user || (m.from.match(/[^\s<>]+@[^\s<>]+/)?.[0] ?? '');
}

export async function sendMail(subject: string, text: string, override?: MailSettings): Promise<void> {
  const m = override ?? (await getMail());
  if (!m.enabled && !override) throw new Error('メール通知がオフです');
  const user = smtpUser(m);
  if (!m.host) throw new Error('SMTPサーバーが未入力です');
  if (!user) throw new Error('Gmailアドレス（SMTPユーザー）が未入力です');
  if (!m.to) throw new Error('通知先が未入力です');
  if (!m.passwordEnc) throw new Error('アプリパスワードが未設定です');
  const transport = nodemailer.createTransport({
    host: m.host,
    port: m.port,
    secure: m.secure,
    auth: { user, pass: mailPassword(m) },
  });
  try {
    await transport.sendMail({ from: m.from || user, to: m.to, subject, text });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (/535|Username and Password not accepted|BadCredentials/i.test(msg)) {
      throw new Error(`Gmailにログインできません。Gmailアドレスとアプリパスワード（16文字）を確認してください（${msg.slice(0, 120)}）`);
    }
    throw e;
  }
}
