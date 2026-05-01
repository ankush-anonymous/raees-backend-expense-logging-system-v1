import nodemailer from "nodemailer";

function smtpConfigured() {
  return Boolean(process.env.SMTP_HOST);
}

/** @returns {import("nodemailer").Transporter} */
function createTransportFromEnv() {
  const host = process.env.SMTP_HOST;
  if (!host) {
    throw new Error("SMTP_HOST is not configured.");
  }

  const port = Number(process.env.SMTP_PORT) || 587;
  const secure = process.env.SMTP_SECURE === "true";

  /** @type {import("nodemailer").SMTPTransport.Options} */
  const options = { host, port, secure };

  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  if (user && pass !== undefined && pass !== "") {
    options.auth = { user, pass };
  }

  return nodemailer.createTransport(options);
}

/** @typedef {{ to: string; subject: string; text: string; html?: string }} SendEmailOptions */

/** @param {SendEmailOptions} opts */
export async function sendEmail({ to, subject, text, html }) {
  if (!smtpConfigured()) {
    throw new Error(
      "SMTP is not configured (set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, EMAIL_FROM).",
    );
  }

  const transport = createTransportFromEnv();
  const from = process.env.EMAIL_FROM ?? process.env.SMTP_USER;
  if (!from) {
    throw new Error("EMAIL_FROM or SMTP_USER must be set for the From address.");
  }

  await transport.sendMail({
    from,
    to,
    subject,
    text,
    html: html ?? text,
  });
}

/**
 * @param {string} to
 * @param {string} name
 * @param {string} otp
 */
export async function sendRegistrationOtpEmail(to, name, otp) {
  const subject = "Your verification code";
  const text = `Hi ${name},\n\nYour verification code is: ${otp}\n\nIt expires in a few minutes. If you did not request this, ignore this email.\n`;
  await sendEmail({ to, subject, text });
}
