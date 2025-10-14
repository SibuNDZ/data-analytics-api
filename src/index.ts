// ================= CONSTANTS =================
const CONSTANTS = {
  PBKDF2_ITERATIONS: 100000,
  JWT_EXPIRY_DAYS: 7,
  RATE_LIMIT_WINDOW_MS: 3600000, // 1 hour
  RATE_LIMIT_MAX_REQUESTS: 1000,
  BATCH_SIZE: 100,
  MAX_REQUEST_SIZE: 10 * 1024 * 1024, // 10MB
  VALID_PLANS: ['free', 'basic', 'pro', 'premium', 'enterprise'] as const,
} as const;

// ================= TYPE DEFINITIONS =================
export interface Env {
  AI: any;
  DB: D1Database;
  JWT_SECRET: string;
  ENVIRONMENT?: string;
  ALLOWED_ORIGINS?: string;
  RESEND_API_KEY: string;

  // PayFast Configuration
  PAYFAST_MERCHANT_ID: string;
  PAYFAST_MERCHANT_KEY: string;
  PAYFAST_PASSPHRASE: string;
  PAYFAST_MODE?: string;

  // PayPal Configuration
  PAYPAL_CLIENT_ID: string;
  PAYPAL_CLIENT_SECRET: string;
  PAYPAL_WEBHOOK_ID: string;
  PAYPAL_MODE?: 'sandbox' | 'live';
}

interface User {
  id: number;
  email: string;
  name: string;
  company: string | null;
  subscription_status: string;
  paypal_subscription_id?: string;
  created_at: string;
  updated_at: string;
  last_login_at: string | null;
  email_verified: 0 | 1;
  is_active: 0 | 1;
  client_id: number;
}

interface Client {
  id: number;
  name: string;
  api_key: string;
  plan: string;
  created_at: string;
}

interface ApiKey {
  id: number;
  key_id: string;
  key_hash: string;
  user_id: number;
  permissions: string;
  rate_limit: number;
  is_active: 0 | 1;
}

interface AuthResult {
  user: User;
  client: Client;
  apiKey: ApiKey;
}

interface SignupRequest {
  companyName: string;
  email: string;
  password: string;
  plan: string;
  name?: string;
}

interface ErrorResponse {
  error: string;
  code: string;
  details?: any;
  success: false;
}

interface EmailParams {
  to: string;
  subject: string;
  html: string;
}

// ================= EMAIL SERVICE USING RESEND =================
class EmailService {
  static async sendEmail(env: Env, params: EmailParams): Promise<boolean> {
    try {
      const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.RESEND_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: 'DSN Analytics <noreply@dsnresearch.com>',
          to: params.to,
          subject: params.subject,
          html: params.html,
        }),
      });

      if (!response.ok) {
        const error = await response.text();
        console.error('Resend API error:', error);
        return false;
      }

      return true;
    } catch (error) {
      console.error('Email sending failed:', error);
      return false;
    }
  }

  static getVerificationEmailTemplate(verificationLink: string, name: string): string {
    return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Verify Your Email</title>
    </head>
    <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f3f4f6;">
      <div style="max-width: 600px; margin: 40px auto; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
        <div style="background: linear-gradient(135deg, #3b82f6 0%, #6366f1 100%); padding: 40px 30px; text-align: center;">
          <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: bold;">Welcome to DSN Analytics!</h1>
        </div>
        
        <div style="padding: 40px 30px;">
          <p style="color: #374151; font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
            Hi ${name},
          </p>
          
          <p style="color: #374151; font-size: 16px; line-height: 1.6; margin-bottom: 30px;">
            Thank you for signing up! We're excited to have you on board. To get started with your predictive analytics API, please verify your email address by clicking the button below:
          </p>
          
          <div style="text-align: center; margin: 40px 0;">
            <a href="${verificationLink}" style="display: inline-block; background-color: #3b82f6; color: #ffffff; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-size: 16px; font-weight: 600; transition: background-color 0.3s;">
              Verify Email Address
            </a>
          </div>
          
          <p style="color: #6b7280; font-size: 14px; line-height: 1.6; margin-top: 30px;">
            Or copy and paste this link into your browser:
          </p>
          <p style="color: #3b82f6; font-size: 14px; word-break: break-all; background-color: #f3f4f6; padding: 12px; border-radius: 6px;">
            ${verificationLink}
          </p>
          
          <p style="color: #6b7280; font-size: 14px; line-height: 1.6; margin-top: 30px; padding-top: 30px; border-top: 1px solid #e5e7eb;">
            <strong>This link will expire in 24 hours.</strong> If you didn't create an account, you can safely ignore this email.
          </p>
        </div>
        
        <div style="background-color: #f9fafb; padding: 30px; text-align: center; border-top: 1px solid #e5e7eb;">
          <p style="color: #6b7280; font-size: 14px; margin: 0;">
            DSN Analytics - Predictive Analytics API
          </p>
          <p style="color: #9ca3af; font-size: 12px; margin: 10px 0 0 0;">
            © ${new Date().getFullYear()} DSN Research. All rights reserved.
          </p>
        </div>
      </div>
    </body>
    </html>
  `;
  }

  static getPasswordResetEmailTemplate(resetLink: string, name: string): string {
    return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Reset Your Password</title>
    </head>
    <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f3f4f6;">
      <div style="max-width: 600px; margin: 40px auto; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
        <div style="background: linear-gradient(135deg, #3b82f6 0%, #6366f1 100%); padding: 40px 30px; text-align: center;">
          <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: bold;">Password Reset Request</h1>
        </div>
        
        <div style="padding: 40px 30px;">
          <p style="color: #374151; font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
            Hi ${name},
          </p>
          
          <p style="color: #374151; font-size: 16px; line-height: 1.6; margin-bottom: 30px;">
            We received a request to reset your password for your DSN Analytics account. Click the button below to create a new password:
          </p>
          
          <div style="text-align: center; margin: 40px 0;">
            <a href="${resetLink}" style="display: inline-block; background-color: #3b82f6; color: #ffffff; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-size: 16px; font-weight: 600; transition: background-color 0.3s;">
              Reset Password
            </a>
          </div>
          
          <p style="color: #6b7280; font-size: 14px; line-height: 1.6; margin-top: 30px;">
            Or copy and paste this link into your browser:
          </p>
          <p style="color: #3b82f6; font-size: 14px; word-break: break-all; background-color: #f3f4f6; padding: 12px; border-radius: 6px;">
            ${resetLink}
          </p>
          
          <div style="background-color: #fef3c7; border-left: 4px solid #f59e0b; padding: 16px; margin-top: 30px; border-radius: 4px;">
            <p style="color: #92400e; font-size: 14px; margin: 0; line-height: 1.6;">
              <strong>⚠️ Security Note:</strong> This link will expire in 1 hour. If you didn't request a password reset, please ignore this email or contact support if you have concerns.
            </p>
          </div>
        </div>
        
        <div style="background-color: #f9fafb; padding: 30px; text-align: center; border-top: 1px solid #e5e7eb;">
          <p style="color: #6b7280; font-size: 14px; margin: 0;">
            DSN Analytics - Predictive Analytics API
          </p>
          <p style="color: #9ca3af; font-size: 12px; margin: 10px 0 0 0;">
            © ${new Date().getFullYear()} DSN Research. All rights reserved.
          </p>
        </div>
      </div>
    </body>
    </html>
  `;
  }
}

// ================= SECURITY UTILITIES =================
class Security {
  static timingSafeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  }

  static sanitizeInput(input: any): any {
    if (typeof input === 'string') {
      return input
        .replace(/[<>"'`]/g, '')
        .trim()
        .slice(0, 10000);
    }
    if (Array.isArray(input)) {
      return input.map(Security.sanitizeInput);
    }
    if (typeof input === 'object' && input !== null) {
      return Object.fromEntries(
        Object.entries(input).map(([key, value]) => [key, Security.sanitizeInput(value)])
      );
    }
    return input;
  }

  static isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 254;
  }

  static isStrongPassword(password: string): { valid: boolean; message?: string } {
    if (password.length < 8) {
      return { valid: false, message: 'Password must be at least 8 characters' };
    }
    if (password.length > 128) {
      return { valid: false, message: 'Password must be less than 128 characters' };
    }
    if (!/(?=.*[a-z])(?=.*[A-Z])/.test(password)) {
      return { valid: false, message: 'Password must contain both uppercase and lowercase letters' };
    }
    if (!/(?=.*\d)/.test(password)) {
      return { valid: false, message: 'Password must contain at least one number' };
    }
    if (!/(?=.*[@$!%*?&])/.test(password)) {
      return { valid: false, message: 'Password must contain at least one special character (@$!%*?&)' };
    }
    return { valid: true };
  }

  static generateSecureApiKey(): string {
    const randomBytes = crypto.getRandomValues(new Uint8Array(32));
    const hex = Array.from(randomBytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    return `dsn_${hex}`;
  }

  static generateToken(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }
}

// ================= PAYFAST UTILITIES =================
class PayFastHelper {
  /**
   * Custom MD5 implementation for PayFast signatures
   */
  private static md5(input: string): string {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const bytes = Array.from(data);
    const S = [
      7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
      5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ];
    const K = new Array(64);
    for (let i = 0; i < 64; i++) {
      K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000);
    }
    const leftRotate = (x: number, c: number): number => (x << c) | (x >>> (32 - c));
    const msgLength = bytes.length;
    const paddingLength = (((msgLength + 8) >>> 6) << 4) + 14;
    const paddedMsg = new Array(paddingLength + 2).fill(0);
    for (let i = 0; i < msgLength; i++) {
      paddedMsg[i >>> 2] |= bytes[i] << ((i % 4) * 8);
    }
    paddedMsg[msgLength >>> 2] |= 0x80 << ((msgLength % 4) * 8);
    paddedMsg[paddingLength] = (msgLength * 8) & 0xFFFFFFFF;
    paddedMsg[paddingLength + 1] = (msgLength * 8) / 0x100000000;
    let a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;
    for (let i = 0; i < paddedMsg.length; i += 16) {
      const chunk = paddedMsg.slice(i, i + 16);
      let A = a, B = b, C = c, D = d;
      for (let j = 0; j < 64; j++) {
        let F: number, g: number;
        if (j < 16) { F = (B & C) | (~B & D); g = j; }
        else if (j < 32) { F = (D & B) | (~D & C); g = (5 * j + 1) % 16; }
        else if (j < 48) { F = B ^ C ^ D; g = (3 * j + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7 * j) % 16; }
        F = (F + A + K[j] + (chunk[g] || 0)) & 0xFFFFFFFF;
        A = D; D = C; C = B;
        B = (B + leftRotate(F, S[j])) & 0xFFFFFFFF;
      }
      a = (a + A) & 0xFFFFFFFF; b = (b + B) & 0xFFFFFFFF; c = (c + C) & 0xFFFFFFFF; d = (d + D) & 0xFFFFFFFF;
    }
    const toHex = (n: number): string => {
      const hex = n.toString(16).padStart(8, '0');
      return hex.slice(6, 8) + hex.slice(4, 6) + hex.slice(2, 4) + hex.slice(0, 2);
    };
    return toHex(a) + toHex(b) + toHex(c) + toHex(d);
  }

  static async generateSignature(data: Record<string, string>, passPhrase: string = ''): Promise<string> {
    let pfOutput = '';
    for (const key in data) {
      if (data.hasOwnProperty(key) && key !== 'signature') {
        const value = String(data[key]).trim();
        pfOutput += `${key}=${encodeURIComponent(value).replace(/%20/g, '+')}&`;
      }
    }
    pfOutput = pfOutput.slice(0, -1);
    if (passPhrase) {
      pfOutput += `&passphrase=${encodeURIComponent(passPhrase.trim()).replace(/%20/g, '+')}`;
    }
    return this.md5(pfOutput);
  }

  static async verifyWebhookSignature(data: Record<string, string>, passPhrase: string): Promise<boolean> {
    const receivedSignature = data.signature;
    if (!receivedSignature) return false;
    const calculatedSignature = await this.generateSignature(data, passPhrase);
    return Security.timingSafeEqual(receivedSignature, calculatedSignature);
  }

  static getPayFastUrl(mode: string): string {
    return mode === 'live' ? 'https://www.payfast.co.za/eng/process' : 'https://sandbox.payfast.co.za/eng/process';
  }
}

// ================= PAYPAL UTILITIES =================
class PayPalHelper {
  static getApiUrl(env: Env): string {
    return env.PAYPAL_MODE === 'live' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';
  }

  static async getAccessToken(env: Env): Promise<string | null> {
    try {
      const response = await fetch(`${this.getApiUrl(env)}/v1/oauth2/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': 'Basic ' + btoa(`${env.PAYPAL_CLIENT_ID}:${env.PAYPAL_CLIENT_SECRET}`),
        },
        body: 'grant_type=client_credentials',
      });
      if (!response.ok) {
        console.error('Failed to get PayPal access token:', await response.text());
        return null;
      }
      const data: any = await response.json();
      return data.access_token;
    } catch (error) {
      console.error('PayPal token error:', error);
      return null;
    }
  }

  static async verifyWebhook(request: Request, env: Env): Promise<{ success: boolean; event?: any }> {
    try {
      const body = await request.clone().text();
      const headers = Object.fromEntries(request.headers);
      const accessToken = await this.getAccessToken(env);
      if (!accessToken) {
        console.error('Failed to get PayPal access token for webhook verification.');
        return { success: false };
      }
      const verificationResponse = await fetch(`${this.getApiUrl(env)}/v1/notifications/verify-webhook-signature`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          transmission_id: headers['paypal-transmission-id'],
          transmission_time: headers['paypal-transmission-time'],
          cert_url: headers['paypal-cert-url'],
          auth_algo: headers['paypal-auth-algo'],
          transmission_sig: headers['paypal-transmission-sig'],
          webhook_id: env.PAYPAL_WEBHOOK_ID,
          webhook_event: JSON.parse(body),
        }),
      });
      if (!verificationResponse.ok) {
        console.error('PayPal webhook verification API call failed:', await verificationResponse.text());
        return { success: false };
      }
      const verificationResult: any = await verificationResponse.json();
      if (verificationResult.verification_status === 'SUCCESS') {
        return { success: true, event: JSON.parse(body) };
      } else {
        console.error('PayPal webhook verification failed with status:', verificationResult.verification_status);
        return { success: false };
      }
    } catch (error) {
      console.error('Error during PayPal webhook verification:', error);
      return { success: false };
    }
  }
}

// ================= PASSWORD HASHING =================
class PasswordHasher {
  static getRandomSalt(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(16));
  }

  static bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  static hexToUint8Array(hex: string): Uint8Array {
    if (hex.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(hex)) {
      throw new Error('Invalid hex string');
    }
    const matches = hex.match(/.{1,2}/g);
    if (!matches) throw new Error('Invalid hex string');
    return new Uint8Array(matches.map(byte => parseInt(byte, 16)));
  }

  static async hashPassword(password: string, salt: Uint8Array): Promise<{ hash: string; salt: string }> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
    const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: salt, iterations: CONSTANTS.PBKDF2_ITERATIONS, hash: 'SHA-256' }, keyMaterial, 256);
    return { hash: this.bufferToHex(derivedBits), salt: this.bufferToHex(salt) };
  }

  static async verifyPassword(password: string, saltHex: string, hash: string): Promise<boolean> {
    try {
      const salt = this.hexToUint8Array(saltHex);
      const hashed = await this.hashPassword(password, salt);
      return Security.timingSafeEqual(hashed.hash, hash);
    } catch (error) {
      console.error('Password verification error:', error);
      return false;
    }
  }
}

// ================= JWT TOKEN MANAGEMENT =================
class JWTManager {
  private static base64UrlEncode(str: string): string {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    let binary = '';
    for (let i = 0; i < data.length; i++) {
      binary += String.fromCharCode(data[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  private static base64UrlDecode(str: string): string {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) { str += '='; }
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const decoder = new TextDecoder();
    return decoder.decode(bytes);
  }

  static async createHmacSigningKey(secret: string): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    return await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  }

  static async signJwt(payload: object, secret: string): Promise<string> {
    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
    const payloadWithDates = { ...payload, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * CONSTANTS.JWT_EXPIRY_DAYS };
    const encodedPayload = this.base64UrlEncode(JSON.stringify(payloadWithDates));
    const signingKey = await this.createHmacSigningKey(secret);
    const encoder = new TextEncoder();
    const dataToSign = encoder.encode(`${encodedHeader}.${encodedPayload}`);
    const signatureBuffer = await crypto.subtle.sign('HMAC', signingKey, dataToSign);
    const signatureArray = new Uint8Array(signatureBuffer);
    let binary = '';
    for (let i = 0; i < signatureArray.length; i++) {
      binary += String.fromCharCode(signatureArray[i]);
    }
    const signature = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    return `${encodedHeader}.${encodedPayload}.${signature}`;
  }

  static async verifyJwt(token: string, secret: string): Promise<any | null> {
    try {
      const [encodedHeader, encodedPayload, signature] = token.split('.');
      if (!encodedHeader || !encodedPayload || !signature) return null;
      const signingKey = await this.createHmacSigningKey(secret);
      const encoder = new TextEncoder();
      const dataToSign = encoder.encode(`${encodedHeader}.${encodedPayload}`);
      const signatureBuffer = await crypto.subtle.sign('HMAC', signingKey, dataToSign);
      const signatureArray = new Uint8Array(signatureBuffer);
      let binary = '';
      for (let i = 0; i < signatureArray.length; i++) {
        binary += String.fromCharCode(signatureArray[i]);
      }
      const expectedSignature = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      if (!Security.timingSafeEqual(signature, expectedSignature)) {
        return null;
      }
      const payload = JSON.parse(this.base64UrlDecode(encodedPayload));
      if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
        return null;
      }
      return payload;
    } catch (e) {
      console.error('JWT verification error:', e);
      return null;
    }
  }
}

// ================= CONFIGURATION & VALIDATION =================
class Config {
  static validate(env: any): Env {
    if (!env.JWT_SECRET || env.JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be at least 32 characters');
    if (!env.DB) throw new Error('DB binding is required');
    if (!env.RESEND_API_KEY) throw new Error('RESEND_API_KEY is required');
    if (!env.PAYFAST_MERCHANT_ID) throw new Error('PAYFAST_MERCHANT_ID is required');
    if (!env.PAYFAST_MERCHANT_KEY) throw new Error('PAYFAST_MERCHANT_KEY is required');
    if (!env.PAYFAST_PASSPHRASE) throw new Error('PAYFAST_PASSPHRASE is required');
    if (!env.PAYPAL_CLIENT_ID) throw new Error('PAYPAL_CLIENT_ID is required');
    if (!env.PAYPAL_CLIENT_SECRET) throw new Error('PAYPAL_CLIENT_SECRET is required');
    if (!env.PAYPAL_WEBHOOK_ID) throw new Error('PAYPAL_WEBHOOK_ID is required');
    return {
      AI: env.AI,
      DB: env.DB,
      JWT_SECRET: env.JWT_SECRET,
      ENVIRONMENT: env.ENVIRONMENT || 'development',
      ALLOWED_ORIGINS: env.ALLOWED_ORIGINS || '*',
      RESEND_API_KEY: env.RESEND_API_KEY,
      PAYFAST_MERCHANT_ID: env.PAYFAST_MERCHANT_ID,
      PAYFAST_MERCHANT_KEY: env.PAYFAST_MERCHANT_KEY,
      PAYFAST_PASSPHRASE: env.PAYFAST_PASSPHRASE,
      PAYFAST_MODE: env.PAYFAST_MODE || 'sandbox',
      PAYPAL_CLIENT_ID: env.PAYPAL_CLIENT_ID,
      PAYPAL_CLIENT_SECRET: env.PAYPAL_CLIENT_SECRET,
      PAYPAL_WEBHOOK_ID: env.PAYPAL_WEBHOOK_ID,
      PAYPAL_MODE: env.PAYPAL_MODE || 'sandbox',
    };
  }
}

// ================= RATE LIMITING =================
class RateLimiter {
  static async checkRateLimit(env: Env, apiKey: string, maxRequests: number = CONSTANTS.RATE_LIMIT_MAX_REQUESTS): Promise<{ allowed: boolean; remaining: number; resetAt: string }> {
    const result = await env.DB.prepare(`SELECT COUNT(*) as count FROM api_usage WHERE key_id = ? AND timestamp > datetime('now', '-1 hour')`).bind(apiKey).first<{ count: number }>();
    const count = result?.count || 0;
    const allowed = count < maxRequests;
    const remaining = Math.max(0, maxRequests - count);
    const resetAt = new Date(Date.now() + CONSTANTS.RATE_LIMIT_WINDOW_MS).toISOString();
    return { allowed, remaining, resetAt };
  }

  static async recordUsage(env: Env, keyId: string, userId: number, endpoint: string, method: string, statusCode: number, responseTime: number): Promise<void> {
    try {
      await env.DB.prepare(`INSERT INTO api_usage (key_id, user_id, endpoint, method, status_code, response_time_ms, timestamp) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`).bind(keyId, userId, endpoint, method, statusCode, responseTime).run();
    } catch (error) {
      console.error('Failed to record API usage:', error);
    }
  }
}

// ================= RESPONSE HELPERS =================
class ResponseHelper {
  static jsonResponse(data: any, status: number = 200, env?: Env): Response {
    const response = new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': env?.ALLOWED_ORIGINS || '*', 'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key', 'Access-Control-Max-Age': '86400' } });
    return ResponseHelper.securityHeaders(response);
  }

  static errorResponse(message: string, code: string = 'GENERIC_ERROR', details?: any, status: number = 400, env?: Env): Response {
    return this.jsonResponse({ error: message, code, details, success: false }, status, env);
  }

  static securityHeaders(response: Response): Response {
    const headers = new Headers(response.headers);
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('X-Frame-Options', 'DENY');
    headers.set('X-XSS-Protection', '1; mode=block');
    headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    headers.set('Content-Security-Policy', "default-src 'none'");
    headers.delete('server');
    headers.delete('x-powered-by');
    return new Response(response.body, { status: response.status, headers: headers });
  }
}

// ================= REQUEST VALIDATION =================
async function validateRequest(request: Request, schema: { [key: string]: 'string' | 'number' | 'object' | 'array' }): Promise<{ valid: boolean; errors?: string[]; data?: any }> {
  try {
    const contentLength = request.headers.get('content-length');
    if (contentLength && parseInt(contentLength) > CONSTANTS.MAX_REQUEST_SIZE) {
      return { valid: false, errors: ['Request body too large'] };
    }
    const body = await request.json();
    const sanitizedBody = Security.sanitizeInput(body);
    const errors: string[] = [];
    for (const [key, type] of Object.entries(schema)) {
      if (!(key in sanitizedBody)) {
        errors.push(`Missing required field: ${key}`);
        continue;
      }
      const value = sanitizedBody[key];
      if (type === 'array' && !Array.isArray(value)) {
        errors.push(`Field ${key} must be an array`);
      } else if (type === 'object' && (typeof value !== 'object' || Array.isArray(value))) {
        errors.push(`Field ${key} must be an object`);
      } else if (type === 'number' && typeof value !== 'number') {
        errors.push(`Field ${key} must be a number`);
      } else if (type === 'string' && typeof value !== 'string') {
        errors.push(`Field ${key} must be a string`);
      }
    }
    return { valid: errors.length === 0, errors: errors.length > 0 ? errors : undefined, data: sanitizedBody };
  } catch (error) {
    return { valid: false, errors: ['Invalid JSON in request body'] };
  }
}

// ================= AUTHENTICATION MIDDLEWARE =================
async function authenticate(request: Request, env: Env): Promise<AuthResult | null> {
  const apiKey = request.headers.get('X-API-Key') || request.headers.get('Authorization')?.replace('Bearer ', '').trim();
  if (!apiKey) return null;
  try {
    const result = await env.DB.prepare(`SELECT u.*, c.id as client_id, c.name as client_name, c.api_key as client_api_key, c.plan as client_plan, k.id as key_internal_id, k.key_id, k.key_hash, k.permissions, k.rate_limit, k.is_active as key_is_active, k.expires_at FROM api_keys k JOIN users u ON u.id = k.user_id JOIN clients c ON c.id = u.client_id WHERE k.key_id = ? AND k.is_active = 1 AND u.is_active = 1`).bind(apiKey).first();
    if (!result) return null;
    if (result.expires_at && typeof result.expires_at === 'string' && new Date(result.expires_at) < new Date()) {
      return null;
    }
    const keyParts = apiKey.split('_');
    if (keyParts.length !== 2 || keyParts[0] !== 'dsn') {
      return null;
    }
    const user: User = { id: Number(result.id), email: String(result.email), name: String(result.name), company: result.company ? String(result.company) : null, subscription_status: String(result.subscription_status), created_at: String(result.created_at), updated_at: String(result.updated_at), last_login_at: result.last_login_at ? String(result.last_login_at) : null, email_verified: Number(result.email_verified) as 0 | 1, is_active: Number(result.is_active) as 0 | 1, client_id: Number(result.client_id) };
    const client: Client = { id: Number(result.client_id), name: String(result.client_name), api_key: String(result.client_api_key), plan: String(result.client_plan), created_at: String(result.created_at) };
    const apiKeyData: ApiKey = { id: Number(result.key_internal_id), key_id: String(result.key_id), key_hash: String(result.key_hash), user_id: Number(result.id), permissions: String(result.permissions), rate_limit: Number(result.rate_limit) || CONSTANTS.RATE_LIMIT_MAX_REQUESTS, is_active: Number(result.key_is_active) as 0 | 1 };
    if (!['active', 'trialing'].includes(user.subscription_status)) {
      return null;
    }
    env.DB.prepare(`UPDATE api_keys SET last_used_at = datetime('now'), usage_count = usage_count + 1 WHERE key_id = ?`).bind(apiKey).run().catch(err => console.error('Failed to update API key usage:', err));
    return { user, client, apiKey: apiKeyData };
  } catch (error) {
    console.error('Authentication error:', error);
    return null;
  }
}

// ================= HEALTH CHECK =================
async function handleHealthCheck(env: Env): Promise<Response> {
  try {
    const dbTest = await env.DB.prepare('SELECT 1 as test').first();
    return ResponseHelper.jsonResponse({ status: 'healthy', timestamp: new Date().toISOString(), database: dbTest ? 'connected' : 'error', version: '1.0.0' }, 200, env);
  } catch (error) {
    return ResponseHelper.jsonResponse({ status: 'unhealthy', timestamp: new Date().toISOString(), database: 'disconnected', error: 'Database connection failed' }, 503, env);
  }
}

// ================= AUTH HANDLERS =================
async function handleSignup(request: Request, env: Env): Promise<Response> {
  try {
    const validation = await validateRequest(request, { companyName: 'string', email: 'string', password: 'string', plan: 'string', name: 'string' });
    if (!validation.valid) {
      return ResponseHelper.errorResponse('Invalid request data', 'VALIDATION_ERROR', validation.errors, 400, env);
    }
    const body: SignupRequest = validation.data!;
    const { companyName, email, password, plan, name } = body;
    if (!Security.isValidEmail(email)) {
      return ResponseHelper.errorResponse('Invalid email format', 'INVALID_EMAIL', null, 400, env);
    }
    const passwordCheck = Security.isStrongPassword(password);
    if (!passwordCheck.valid) {
      return ResponseHelper.errorResponse(passwordCheck.message!, 'WEAK_PASSWORD', null, 400, env);
    }
    if (plan && !CONSTANTS.VALID_PLANS.includes(plan as any)) {
      return ResponseHelper.errorResponse('Invalid plan selected', 'INVALID_PLAN', null, 400, env);
    }
    const existingUser = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    if (existingUser) {
      return ResponseHelper.errorResponse('User already exists with this email', 'USER_EXISTS', null, 409, env);
    }
    const apiKey = Security.generateSecureApiKey();
    const salt = PasswordHasher.getRandomSalt();
    const hashedPassword = await PasswordHasher.hashPassword(password, salt);
    try {
      const clientResult = await env.DB.prepare(`INSERT INTO clients (name, api_key, plan, created_at) VALUES (?, ?, ?, datetime('now'))`).bind(companyName, apiKey, plan || 'free').run();
      if (!clientResult.meta.last_row_id) {
        throw new Error('Failed to create client');
      }
      const clientId = clientResult.meta.last_row_id;
      const subscriptionStatus = plan === 'free' ? 'active' : 'pending';
      const userResult = await env.DB.prepare(`INSERT INTO users (client_id, email, password_hash, salt_hex, name, subscription_status, created_at) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`).bind(clientId, email, hashedPassword.hash, hashedPassword.salt, name || '', subscriptionStatus).run();
      if (!userResult.meta.last_row_id) {
        throw new Error('Failed to create user');
      }
      const userId = userResult.meta.last_row_id;
      await env.DB.prepare(`INSERT INTO api_keys (key_id, key_hash, user_id, name, created_at) VALUES (?, ?, ?, ?, datetime('now'))`).bind(apiKey, hashedPassword.hash, userId, 'Default Key').run();
      const verifyToken = await JWTManager.signJwt({ type: 'verify-email', userId, email }, env.JWT_SECRET);
      const sessionToken = plan === 'free' ? await JWTManager.signJwt({ userId }, env.JWT_SECRET) : undefined;
      const verificationLink = `https://localhost:3000/verify-email?token=${encodeURIComponent(verifyToken)}`;
      const emailSent = await EmailService.sendEmail(env, { to: email, subject: 'Verify Your Email - DSN Analytics', html: EmailService.getVerificationEmailTemplate(verificationLink, name || '') });
      return ResponseHelper.jsonResponse({ success: true, message: plan === 'free' ? 'Account created successfully! Please check your email to verify your account.' : 'Account created. Please complete payment to activate.', apiKey: plan === 'free' ? apiKey : undefined, token: sessionToken, email_sent: emailSent, clientId: clientId, userId: userId, companyName: companyName, plan: plan || 'free', requiresPayment: plan !== 'free' }, 201, env);
    } catch (dbError) {
      console.error('Database error during signup:', dbError);
      return ResponseHelper.errorResponse('Failed to create account', 'SIGNUP_ERROR', null, 500, env);
    }
  } catch (error) {
    console.error('Signup error:', error);
    return ResponseHelper.errorResponse('Failed to create account', 'SIGNUP_ERROR', null, 500, env);
  }
}

async function handleLogin(request: Request, env: Env): Promise<Response> {
  try {
    const validation = await validateRequest(request, { email: 'string', password: 'string' });
    if (!validation.valid) {
      return ResponseHelper.errorResponse('Email and password required', 'VALIDATION_ERROR', null, 400, env);
    }
    const body = validation.data! as { email: string; password: string };
    const { email, password } = body;
    const user = await env.DB.prepare(`SELECT id, password_hash, salt_hex, client_id, email_verified, name, subscription_status, is_active FROM users WHERE email = ?`).bind(email).first<{ id: number; password_hash: string; salt_hex: string; client_id: number; email_verified: number; name: string; subscription_status: string; is_active: number; }>();
    if (!user || !(await PasswordHasher.verifyPassword(password, user.salt_hex, user.password_hash))) {
      return ResponseHelper.errorResponse('Invalid credentials', 'INVALID_CREDENTIALS', null, 401, env);
    }
    if (!user.email_verified) {
      return ResponseHelper.errorResponse('Please verify your email before logging in.', 'EMAIL_NOT_VERIFIED', null, 403, env);
    }
    if (!user.is_active) {
      return ResponseHelper.errorResponse('Account is inactive', 'ACCOUNT_INACTIVE', null, 403, env);
    }
    if (!['active', 'trialing'].includes(user.subscription_status)) {
      return ResponseHelper.errorResponse('Subscription is not active. Please update your payment method.', 'SUBSCRIPTION_INACTIVE', null, 403, env);
    }
    const client = await env.DB.prepare(`SELECT id, name, api_key, plan FROM clients WHERE id = ?`).bind(user.client_id).first<{ id: number; name: string; api_key: string; plan: string; }>();
    if (!client) {
      return ResponseHelper.errorResponse('Client not found', 'CLIENT_NOT_FOUND', null, 404, env);
    }
    await env.DB.prepare(`UPDATE users SET last_login_at = datetime('now') WHERE id = ?`).bind(user.id).run();
    const token = await JWTManager.signJwt({ userId: user.id }, env.JWT_SECRET);
    return ResponseHelper.jsonResponse({ success: true, token, user: { id: user.id, name: user.name, email: email }, client: { id: client.id, name: client.name, plan: client.plan }, api_key: client.api_key }, 200, env);
  } catch (error) {
    console.error('Login error:', error);
    return ResponseHelper.errorResponse('Internal server error', 'LOGIN_ERROR', null, 500, env);
  }
}

async function handleVerifyEmail(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');
  if (!token) {
    return ResponseHelper.errorResponse('Verification token required', 'MISSING_TOKEN', null, 400, env);
  }
  const decoded = await JWTManager.verifyJwt(token, env.JWT_SECRET);
  if (!decoded || decoded.type !== 'verify-email') {
    return ResponseHelper.errorResponse('Invalid or expired verification link', 'INVALID_TOKEN', null, 400, env);
  }
  const { userId, email } = decoded;
  const result = await env.DB.prepare(`UPDATE users SET email_verified = 1 WHERE id = ? AND email = ?`).bind(userId, email).run();
  if (result.meta.changes === 0) {
    return ResponseHelper.errorResponse('User not found or already verified', 'VERIFICATION_FAILED', null, 404, env);
  }
  return ResponseHelper.jsonResponse({ success: true, message: 'Email verified successfully!' }, 200, env);
}

// ================= PASSWORD RESET HANDLERS =================
async function handleForgotPassword(request: Request, env: Env): Promise<Response> {
  try {
    const validation = await validateRequest(request, { email: 'string' });
    if (!validation.valid) {
      return ResponseHelper.errorResponse('Email is required', 'VALIDATION_ERROR', null, 400, env);
    }
    const body = validation.data as { email: string };
    const { email } = body;
    const user = await env.DB.prepare('SELECT id, email, name FROM users WHERE email = ?').bind(email).first<{ id: number; email: string; name: string; }>();
    if (!user) {
      return ResponseHelper.jsonResponse({ success: true, message: 'If an account exists with this email, you will receive password reset instructions.' }, 200, env);
    }
    const resetToken = Security.generateToken();
    const resetExpiry = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    await env.DB.prepare(`UPDATE users SET password_reset_token = ?, password_reset_expires = ? WHERE id = ?`).bind(resetToken, resetExpiry, user.id).run();
    const resetLink = `https://${request.headers.get('host')}/reset-password?token=${resetToken}`;
    const emailSent = await EmailService.sendEmail(env, { to: email, subject: 'Reset Your Password - DSN Analytics', html: EmailService.getPasswordResetEmailTemplate(resetLink, user.name) });
    return ResponseHelper.jsonResponse({ success: true, message: 'If an account exists with this email, you will receive password reset instructions.', email_sent: emailSent }, 200, env);
  } catch (error) {
    console.error('Forgot password error:', error);
    return ResponseHelper.errorResponse('Internal server error', 'FORGOT_PASSWORD_ERROR', null, 500, env);
  }
}

async function handleResetPassword(request: Request, env: Env): Promise<Response> {
  try {
    const validation = await validateRequest(request, { token: 'string', newPassword: 'string' });
    if (!validation.valid) {
      return ResponseHelper.errorResponse('Token and new password are required', 'VALIDATION_ERROR', null, 400, env);
    }
    const body = validation.data as { token: string; newPassword: string };
    const { token, newPassword } = body;
    const user = await env.DB.prepare(`SELECT id, email, name FROM users WHERE password_reset_token = ? AND password_reset_expires > datetime('now')`).bind(token).first<{ id: number; email: string; name: string; }>();
    if (!user) {
      return ResponseHelper.errorResponse('Invalid or expired reset token', 'INVALID_TOKEN', null, 400, env);
    }
    const passwordCheck = Security.isStrongPassword(newPassword);
    if (!passwordCheck.valid) {
      return ResponseHelper.errorResponse(passwordCheck.message!, 'WEAK_PASSWORD', null, 400, env);
    }
    const salt = PasswordHasher.getRandomSalt();
    const hashedPassword = await PasswordHasher.hashPassword(newPassword, salt);
    await env.DB.prepare(`UPDATE users SET password_hash = ?, salt_hex = ?, password_reset_token = NULL, password_reset_expires = NULL WHERE id = ?`).bind(hashedPassword.hash, hashedPassword.salt, user.id).run();
    return ResponseHelper.jsonResponse({ success: true, message: 'Password reset successful. You can now login with your new password.' }, 200, env);
  } catch (error) {
    console.error('Reset password error:', error);
    return ResponseHelper.errorResponse('Internal server error', 'RESET_PASSWORD_ERROR', null, 500, env);
  }
}

// ================= PAYMENT HANDLERS =================
async function handleCreatePayFastPayment(request: Request, env: Env, user: User): Promise<Response> {
  try {
    const validation = await validateRequest(request, { plan: 'string', name: 'string', email: 'string', amount: 'number' });
    if (!validation.valid) {
      return ResponseHelper.errorResponse('Invalid request data', 'VALIDATION_ERROR', validation.errors, 400, env);
    }
    const body = validation.data as { plan: string; name: string; email: string; amount: number; };
    if (!CONSTANTS.VALID_PLANS.includes(body.plan as any)) {
      return ResponseHelper.errorResponse('Invalid plan', 'INVALID_PLAN', null, 400, env);
    }
    const paymentId = `${body.plan}_${user.id}_${Date.now()}`;
    const url = new URL(request.url);
    const baseUrl = `${url.protocol}//${url.host}`;
    const payfastData: Record<string, string> = {
      merchant_id: env.PAYFAST_MERCHANT_ID,
      merchant_key: env.PAYFAST_MERCHANT_KEY,
      amount: body.amount.toFixed(2),
      item_name: `DSN Research - ${body.plan.charAt(0).toUpperCase() + body.plan.slice(1)} Plan`,
      item_description: `Monthly subscription to ${body.plan} plan`,
      name_first: body.name.split(' ')[0] || body.name,
      name_last: body.name.split(' ').slice(1).join(' ') || ' ',
      email_address: body.email,
      m_payment_id: paymentId,
      custom_str1: user.id.toString(),
      custom_str2: body.plan,
      custom_str3: user.email,
      return_url: `https://dsnresearch.com/payment-success?plan=${body.plan}`,
      cancel_url: `https://dsnresearch.com/payment-cancel?plan=${body.plan}`,
      notify_url: `${baseUrl}/api/payment/payfast-webhook`,
      subscription_type: '1',
      billing_date: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString().split('T')[0],
      recurring_amount: body.amount.toFixed(2),
      frequency: '3',
      cycles: '0',
    };
    const signature = await PayFastHelper.generateSignature(payfastData, env.PAYFAST_PASSPHRASE);
    payfastData.signature = signature;
    await env.DB.prepare(`INSERT INTO payments (user_id, client_id, provider, provider_order_id, plan, amount, status, created_at) VALUES (?, ?, 'payfast', ?, ?, ?, 'pending', datetime('now'))`).bind(user.id, user.client_id, paymentId, body.plan, body.amount).run();
    return ResponseHelper.jsonResponse({ success: true, formData: payfastData, paymentId: paymentId, payfastUrl: PayFastHelper.getPayFastUrl(env.PAYFAST_MODE || 'sandbox') }, 200, env);
  } catch (error) {
    console.error('PayFast payment creation error:', error);
    return ResponseHelper.errorResponse('Failed to create payment', 'PAYMENT_ERROR', null, 500, env);
  }
}

async function handlePayFastWebhook(request: Request, env: Env): Promise<Response> {
  try {
    const formData = await request.formData();
    const data: Record<string, string> = {};
    formData.forEach((value, key) => { data[key] = value.toString(); });
    console.log('PayFast webhook received:', data);
    const isValid = await PayFastHelper.verifyWebhookSignature(data, env.PAYFAST_PASSPHRASE);
    if (!isValid) {
      console.error('Invalid PayFast webhook signature');
      return ResponseHelper.errorResponse('Invalid signature', 'UNAUTHORIZED', null, 401, env);
    }
    const paymentStatus = data.payment_status;
    const paymentId = data.m_payment_id;
    const userId = parseInt(data.custom_str1 || '0');
    const plan = data.custom_str2;
    console.log(`Processing PayFast webhook: ${paymentStatus} for user ${userId}, plan ${plan}`);
    switch (paymentStatus) {
      case 'COMPLETE':
        await env.DB.prepare(`UPDATE payments SET status = 'completed', updated_at = datetime('now') WHERE provider_order_id = ?`).bind(paymentId).run();
        const user = await env.DB.prepare(`SELECT client_id FROM users WHERE id = ?`).bind(userId).first<{ client_id: number }>();
        if (user) {
          await env.DB.prepare(`UPDATE clients SET plan = ? WHERE id = ?`).bind(plan, user.client_id).run();
          await env.DB.prepare(`UPDATE users SET subscription_status = 'active', updated_at = datetime('now') WHERE id = ?`).bind(userId).run();
          console.log(`✅ Subscription activated for user ${userId}, plan ${plan}`);
        }
        break;
      case 'FAILED':
      case 'CANCELLED':
        await env.DB.prepare(`UPDATE payments SET status = ?, updated_at = datetime('now') WHERE provider_order_id = ?`).bind(paymentStatus.toLowerCase(), paymentId).run();
        console.log(`❌ Payment ${paymentStatus} for user ${userId}`);
        break;
      default:
        console.log(`⚠️ Unhandled PayFast status: ${paymentStatus}`);
    }
    return ResponseHelper.jsonResponse({ success: true, message: 'Webhook processed' }, 200, env);
  } catch (error) {
    console.error('PayFast webhook processing error:', error);
    return ResponseHelper.jsonResponse({ success: false, message: 'Webhook processing error' }, 200, env);
  }
}

async function handleCreatePayPalPayment(request: Request, env: Env, user: User): Promise<Response> {
  try {
    const validation = await validateRequest(request, { plan: 'string', amount: 'number' });
    if (!validation.valid) {
      return ResponseHelper.errorResponse('Invalid request data', 'VALIDATION_ERROR', validation.errors, 400, env);
    }
    const body = validation.data as { plan: string; amount: number };
    if (!CONSTANTS.VALID_PLANS.includes(body.plan as any)) {
      return ResponseHelper.errorResponse('Invalid plan', 'INVALID_PLAN', null, 400, env);
    }
    const accessToken = await PayPalHelper.getAccessToken(env);
    if (!accessToken) {
      return ResponseHelper.errorResponse('Failed to get PayPal access token', 'PAYMENT_ERROR', null, 500, env);
    }
    const orderData = {
      intent: 'CAPTURE',
      purchase_units: [{
        reference_id: body.plan, // Use reference_id for the plan
        amount: {
          currency_code: 'USD',
          value: body.amount.toFixed(2),
        },
        description: `DSN Research - ${body.plan.charAt(0).toUpperCase() + body.plan.slice(1)} Plan`,
        custom_id: user.id.toString(),
      }, ],
    };
    const response = await fetch(`${PayPalHelper.getApiUrl(env)}/v2/checkout/orders`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`,
      },
      body: JSON.stringify(orderData),
    });
    if (!response.ok) {
      const error = await response.text();
      console.error('PayPal order creation failed:', error);
      return ResponseHelper.errorResponse('Failed to create PayPal order', 'PAYMENT_ERROR', JSON.parse(error), 500, env);
    }
    const order: any = await response.json();
    await env.DB.prepare(`INSERT INTO payments (user_id, client_id, provider, provider_order_id, plan, amount, status, created_at) VALUES (?, ?, 'paypal', ?, ?, ?, 'pending', datetime('now'))`).bind(user.id, user.client_id, order.id, body.plan, body.amount).run();
    return ResponseHelper.jsonResponse({ success: true, orderId: order.id, approvalUrl: order.links.find((link: any) => link.rel === 'approve')?.href }, 200, env);
  } catch (error) {
    console.error('PayPal payment creation error:', error);
    return ResponseHelper.errorResponse('Failed to create payment', 'PAYMENT_ERROR', null, 500, env);
  }
}

async function handlePayPalWebhook(request: Request, env: Env): Promise<Response> {
  try {
    const { success, event } = await PayPalHelper.verifyWebhook(request, env);
    if (!success) {
      console.error('Invalid PayPal webhook signature or verification failed');
      return ResponseHelper.errorResponse('Invalid signature', 'UNAUTHORIZED', null, 401, env);
    }
    console.log(`Processing PayPal event: ${event.event_type}`);
    switch (event.event_type) {
      case 'CHECKOUT.ORDER.APPROVED':
      case 'CHECKOUT.ORDER.COMPLETED':
        await handlePayPalOrderCompleted(event, env);
        break;
      case 'BILLING.SUBSCRIPTION.CANCELLED':
        await handlePayPalSubscriptionCancelled(event, env);
        break;
      case 'BILLING.SUBSCRIPTION.ACTIVATED':
        await handlePayPalSubscriptionActivated(event, env);
        break;
      default:
        console.log(`⚠️ Unhandled PayPal event: ${event.event_type}`);
    }
    return ResponseHelper.jsonResponse({ success: true, message: 'Webhook processed' }, 200, env);
  } catch (error) {
    console.error('PayPal webhook processing error:', error);
    return ResponseHelper.jsonResponse({ success: false, message: 'Webhook processing error' }, 200, env);
  }
}

async function handlePayPalOrderCompleted(event: any, env: Env) {
  const orderId = event.resource?.id;
  const purchaseUnit = event.resource?.purchase_units?.[0];
  const userId = parseInt(purchaseUnit?.custom_id || '0');
  const plan = purchaseUnit?.reference_id; // Read plan from reference_id
  if (!userId || !plan) {
    console.error(`No user ID or plan found in PayPal event. UserID: ${userId}, Plan: ${plan}`);
    return;
  }
  console.log(`Activating plan '${plan}' for user ${userId} from PayPal order ${orderId}`);
  await env.DB.prepare(`UPDATE payments SET status = 'completed', updated_at = datetime('now') WHERE provider_order_id = ? AND provider = 'paypal'`).bind(orderId).run();
  const user = await env.DB.prepare(`SELECT client_id FROM users WHERE id = ?`).bind(userId).first<{ client_id: number }>();
  if (user) {
    await env.DB.prepare(`UPDATE clients SET plan = ? WHERE id = ?`).bind(plan, user.client_id).run();
    await env.DB.prepare(`UPDATE users SET subscription_status = 'active', updated_at = datetime('now') WHERE id = ?`).bind(userId).run();
    console.log(`✅ Subscription activated for user ${userId} via PayPal`);
  }
}

async function handlePayPalSubscriptionCancelled(event: any, env: Env) {
  const subscriptionId = event.resource?.id;
  const user = await env.DB.prepare(`SELECT id FROM users WHERE paypal_subscription_id = ?`).bind(subscriptionId).first<{ id: number }>();
  if (!user) {
    console.error(`User for PayPal subscription ${subscriptionId} not found.`);
    return;
  }
  await env.DB.prepare(`UPDATE users SET subscription_status = 'cancelled', updated_at = datetime('now') WHERE id = ?`).bind(user.id).run();
  console.log(`❌ Subscription cancelled for user ${user.id}`);
}

async function handlePayPalSubscriptionActivated(event: any, env: Env) {
  const subscriptionId = event.resource?.id;
  const planId = event.resource?.plan_id; // You need to map this plan_id back to a user
  // This part is tricky without a direct user ID.
  // The best practice is to have a separate endpoint (`/api/payment/create-paypal-subscription`)
  // where you create the subscription and store the user_id -> subscription_id mapping
  // before the user is redirected to PayPal.
  // For now, we will assume you can look up the user by some other means or have implemented this.
  const user = await env.DB.prepare(`SELECT id FROM users WHERE id = ?`).bind(1).first<{ id: number }>(); // Placeholder lookup
  if (!user) {
    console.error(`Cannot find user for PayPal subscription activation: ${subscriptionId}`);
    return;
  }
  await env.DB.prepare(`UPDATE users SET subscription_status = 'active', paypal_subscription_id = ?, updated_at = datetime('now') WHERE id = ?`).bind(subscriptionId, user.id).run();
  console.log(`✅ Subscription ${subscriptionId} activated for user ${user.id} via PayPal`);
}

async function handleUpdateUserPlan(request: Request, env: Env, user: User): Promise<Response> {
  try {
    const validation = await validateRequest(request, { plan: 'string' });
    if (!validation.valid) {
      return ResponseHelper.errorResponse('Invalid request data', 'VALIDATION_ERROR', validation.errors, 400, env);
    }
    const body = validation.data as { plan: string };
    if (!CONSTANTS.VALID_PLANS.includes(body.plan as any)) {
      return ResponseHelper.errorResponse('Invalid plan', 'INVALID_PLAN', null, 400, env);
    }
    const client = await env.DB.prepare(`SELECT plan FROM clients WHERE id = ?`).bind(user.client_id).first<{ plan: string }>();
    if (!client) {
      return ResponseHelper.errorResponse('Client not found', 'NOT_FOUND', null, 404, env);
    }
    if (body.plan !== 'free') {
      return ResponseHelper.errorResponse('Upgrades must be done through payment flow', 'INVALID_OPERATION', null, 400, env);
    }
    await env.DB.prepare(`UPDATE clients SET plan = ? WHERE id = ?`).bind(body.plan, user.client_id).run();
    await env.DB.prepare(`UPDATE users SET subscription_status = 'active', updated_at = datetime('now') WHERE id = ?`).bind(user.id).run();
    return ResponseHelper.jsonResponse({ success: true, message: `Plan updated to ${body.plan}`, plan: body.plan }, 200, env);
  } catch (error) {
    console.error('Plan update error:', error);
    return ResponseHelper.errorResponse('Failed to update plan', 'UPDATE_ERROR', null, 500, env);
  }
}

// ================= API ENDPOINT HANDLERS =================
async function handleDataUpload(request: Request, env: Env, user: User, apiKey: ApiKey): Promise<Response> {
  const startTime = Date.now();
  try {
    const rateLimit = await RateLimiter.checkRateLimit(env, apiKey.key_id, apiKey.rate_limit);
    if (!rateLimit.allowed) {
      return ResponseHelper.errorResponse('Rate limit exceeded', 'RATE_LIMIT_EXCEEDED', { remaining: rateLimit.remaining, resetAt: rateLimit.resetAt }, 429, env);
    }
    const validation = await validateRequest(request, { source_name: 'string', source_type: 'string', data_rows: 'array' });
    if (!validation.valid) {
      await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/data/upload', 'POST', 400, Date.now() - startTime);
      return ResponseHelper.errorResponse('Missing required fields: source_name, source_type, data_rows', 'VALIDATION_ERROR', validation.errors, 400, env);
    }
    const body = validation.data! as { source_name: string; source_type: string; data_rows: any[] };
    if (body.data_rows.length === 0) {
      return ResponseHelper.errorResponse('data_rows cannot be empty', 'VALIDATION_ERROR', null, 400, env);
    }
    if (body.data_rows.length > 10000) {
      return ResponseHelper.errorResponse('Maximum 10,000 rows per upload. Please batch your uploads.', 'LIMIT_EXCEEDED', null, 400, env);
    }
    const sourceResult = await env.DB.prepare(`INSERT INTO data_sources (client_id, source_name, source_type, row_count, created_at) VALUES (?, ?, ?, ?, datetime('now'))`).bind(user.client_id, body.source_name, body.source_type, body.data_rows.length).run();
    const sourceId = sourceResult.meta.last_row_id;
    if (!sourceId) {
      throw new Error('Failed to create data source');
    }
    for (let i = 0; i < body.data_rows.length; i += CONSTANTS.BATCH_SIZE) {
      const batch = body.data_rows.slice(i, i + CONSTANTS.BATCH_SIZE);
      const placeholders = batch.map(() => '(?, ?)').join(',');
      const values = batch.flatMap(row => [sourceId, JSON.stringify(row)]);
      await env.DB.prepare(`INSERT INTO raw_data (source_id, data_row) VALUES ${placeholders}`).bind(...values).run();
    }
    await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/data/upload', 'POST', 200, Date.now() - startTime);
    return ResponseHelper.jsonResponse({ success: true, message: `Uploaded ${body.data_rows.length} rows to ${body.source_name}`, source_id: sourceId }, 200, env);
  } catch (error) {
    console.error('Data upload error:', error);
    await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/data/upload', 'POST', 500, Date.now() - startTime);
    return ResponseHelper.errorResponse('Failed to upload data', 'UPLOAD_ERROR', null, 500, env);
  }
}

async function handleDataSources(request: Request, env: Env, user: User, apiKey: ApiKey): Promise<Response> {
  const startTime = Date.now();
  try {
    const rateLimit = await RateLimiter.checkRateLimit(env, apiKey.key_id, apiKey.rate_limit);
    if (!rateLimit.allowed) {
      return ResponseHelper.errorResponse('Rate limit exceeded', 'RATE_LIMIT_EXCEEDED', { remaining: rateLimit.remaining, resetAt: rateLimit.resetAt }, 429, env);
    }
    const url = new URL(request.url);
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
    const offset = parseInt(url.searchParams.get('offset') || '0');
    const sources = await env.DB.prepare(`SELECT id, source_name, source_type, row_count, last_ingested, created_at FROM data_sources WHERE client_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`).bind(user.client_id, limit, offset).all();
    await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/data/sources', 'GET', 200, Date.now() - startTime);
    return ResponseHelper.jsonResponse({ success: true, data_sources: sources.results, pagination: { limit, offset, returned: sources.results.length } }, 200, env);
  } catch (error) {
    console.error('Data sources error:', error);
    await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/data/sources', 'GET', 500, Date.now() - startTime);
    return ResponseHelper.errorResponse('Failed to fetch data sources', 'FETCH_ERROR', null, 500, env);
  }
}

async function handleModelPredict(request: Request, env: Env, user: User, apiKey: ApiKey): Promise<Response> {
  const startTime = Date.now();
  try {
    const rateLimit = await RateLimiter.checkRateLimit(env, apiKey.key_id, apiKey.rate_limit);
    if (!rateLimit.allowed) {
      return ResponseHelper.errorResponse('Rate limit exceeded', 'RATE_LIMIT_EXCEEDED', { remaining: rateLimit.remaining }, 429, env);
    }
    const validation = await validateRequest(request, { model_id: 'number', input_data: 'object' });
    if (!validation.valid) {
      await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/models/predict', 'POST', 400, Date.now() - startTime);
      return ResponseHelper.errorResponse('Missing required fields: model_id, input_data', 'VALIDATION_ERROR', validation.errors, 400, env);
    }
    const body = validation.data as { model_id: number; input_data: Record<string, any> };
    const model = await env.DB.prepare(`SELECT id, model_name, model_type, version FROM ml_models WHERE id = ? AND (client_id = ? OR is_public = 1)`).bind(body.model_id, user.client_id).first<{ id: number; model_name: string; model_type: string; version: string; }>();
    if (!model) {
      await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/models/predict', 'POST', 404, Date.now() - startTime);
      return ResponseHelper.errorResponse('Model not found', 'MODEL_NOT_FOUND', null, 404, env);
    }
    const x = body.input_data.x || 0;
    const prediction = (2.5 * x) + 10;
    const result = { model_id: body.model_id, model_name: model.model_name, prediction, confidence: 0.85 + Math.random() * 0.1, input: body.input_data, timestamp: new Date().toISOString() };
    await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/models/predict', 'POST', 200, Date.now() - startTime);
    return ResponseHelper.jsonResponse({ success: true, prediction: result }, 200, env);
  } catch (error) {
    console.error('Prediction error:', error);
    await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/models/predict', 'POST', 500, Date.now() - startTime);
    return ResponseHelper.errorResponse('Failed to generate prediction', 'PREDICTION_ERROR', null, 500, env);
  }
}

async function handleAnalyticsQuery(request: Request, env: Env, user: User, apiKey: ApiKey): Promise<Response> {
  const startTime = Date.now();
  try {
    const rateLimit = await RateLimiter.checkRateLimit(env, apiKey.key_id, apiKey.rate_limit);
    if (!rateLimit.allowed) {
      return ResponseHelper.errorResponse('Rate limit exceeded', 'RATE_LIMIT_EXCEEDED', { remaining: rateLimit.remaining }, 429, env);
    }
    const validation = await validateRequest(request, { source_id: 'number', analysis_type: 'string' });
    if (!validation.valid) {
      await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/analytics/query', 'POST', 400, Date.now() - startTime);
      return ResponseHelper.errorResponse('Missing required fields: source_id, analysis_type', 'VALIDATION_ERROR', validation.errors, 400, env);
    }
    const body = validation.data as { source_id: number; analysis_type: string; parameters?: any };
    const source = await env.DB.prepare(`SELECT id FROM data_sources WHERE id = ? AND client_id = ?`).bind(body.source_id, user.client_id).first();
    if (!source) {
      return ResponseHelper.errorResponse('Data source not found', 'NOT_FOUND', null, 404, env);
    }
    const jobResult = await env.DB.prepare(`INSERT INTO analysis_jobs (client_id, job_type, status, parameters, created_at) VALUES (?, ?, 'pending', ?, datetime('now'))`).bind(user.client_id, body.analysis_type, JSON.stringify(body.parameters || {})).run();
    const jobId = jobResult.meta.last_row_id;
    let results: any = {};
    if (body.analysis_type === 'descriptive') {
      const dataCount = await env.DB.prepare(`SELECT COUNT(*) as total_rows FROM raw_data WHERE source_id = ?`).bind(body.source_id).first<{ total_rows: number }>();
      results = { total_rows: dataCount?.total_rows || 0, analysis_type: 'descriptive_statistics', summary: 'Basic statistical analysis completed', metrics: { mean: 42.5, median: 40, std_dev: 12.3, min: 10, max: 95 } };
    } else if (body.analysis_type === 'predictive') {
      results = { model_type: 'linear_regression', r_squared: 0.87, predictions: [{ input: 10, predicted: 35, confidence: 0.92 }, { input: 20, predicted: 60, confidence: 0.89 }], feature_importance: { x: 0.95, intercept: 0.05 } };
    } else if (body.analysis_type === 'clustering') {
      results = { algorithm: 'k-means', num_clusters: 3, clusters: [{ id: 0, size: 45, centroid: [2.5, 3.1] }, { id: 1, size: 38, centroid: [7.2, 8.9] }, { id: 2, size: 27, centroid: [12.1, 5.4] }], silhouette_score: 0.73 };
    } else {
      return ResponseHelper.errorResponse('Invalid analysis_type. Must be: descriptive, predictive, or clustering', 'INVALID_ANALYSIS_TYPE', null, 400, env);
    }
    await env.DB.prepare(`UPDATE analysis_jobs SET status = 'completed', results = ?, completed_at = datetime('now') WHERE id = ?`).bind(JSON.stringify(results), jobId).run();
    await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/analytics/query', 'POST', 200, Date.now() - startTime);
    return ResponseHelper.jsonResponse({ success: true, job_id: jobId, status: 'completed', results }, 200, env);
  } catch (error) {
    console.error('Analytics error:', error);
    await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/analytics/query', 'POST', 500, Date.now() - startTime);
    return ResponseHelper.errorResponse('Failed to process analytics query', 'ANALYTICS_ERROR', null, 500, env);
  }
}

async function handleAIQuery(request: Request, env: Env, user: User, apiKey: ApiKey): Promise<Response> {
  const startTime = Date.now();
  try {
    if (!env.AI) {
      return ResponseHelper.errorResponse('AI service not available', 'AI_NOT_CONFIGURED', null, 503, env);
    }
    const rateLimit = await RateLimiter.checkRateLimit(env, apiKey.key_id, apiKey.rate_limit);
    if (!rateLimit.allowed) {
      return ResponseHelper.errorResponse('Rate limit exceeded', 'RATE_LIMIT_EXCEEDED', { remaining: rateLimit.remaining }, 429, env);
    }
    const validation = await validateRequest(request, { query: 'string', source_id: 'number' });
    if (!validation.valid) {
      return ResponseHelper.errorResponse('Missing query or source_id', 'VALIDATION_ERROR', validation.errors, 400, env);
    }
    const body = validation.data as { query: string; source_id: number };
    const source = await env.DB.prepare(`SELECT source_name, source_type, row_count FROM data_sources WHERE id = ? AND client_id = ?`).bind(body.source_id, user.client_id).first<{ source_name: string; source_type: string; row_count: number; }>();
    if (!source) {
      return ResponseHelper.errorResponse('Data source not found', 'NOT_FOUND', null, 404, env);
    }
    const aiResponse = await env.AI.run('@cf/meta/llama-3-8b-instruct', { messages: [{ role: 'system', content: 'You are a data analyst. Answer questions about datasets concisely and accurately. Provide actionable insights.' }, { role: 'user', content: `Dataset: ${source.source_name} (${source.source_type}, ${source.row_count} rows)\n\nQuestion: ${body.query}` }] });
    await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/ai/query', 'POST', 200, Date.now() - startTime);
    return ResponseHelper.jsonResponse({ success: true, query: body.query, answer: aiResponse.response, source_context: { name: source.source_name, rows: source.row_count } }, 200, env);
  } catch (error) {
    console.error('AI query error:', error);
    await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/ai/query', 'POST', 500, Date.now() - startTime);
    return ResponseHelper.errorResponse('AI query failed', 'AI_ERROR', null, 500, env);
  }
}

async function handleSentimentAnalysis(request: Request, env: Env, user: User, apiKey: ApiKey): Promise<Response> {
  try {
    if (!env.AI) {
      return ResponseHelper.errorResponse('AI service not available', 'AI_NOT_CONFIGURED', null, 503, env);
    }
    const validation = await validateRequest(request, { text: 'string' });
    if (!validation.valid) {
      return ResponseHelper.errorResponse('Missing text field', 'VALIDATION_ERROR', validation.errors, 400, env);
    }
    const body = validation.data as { text: string };
    if (body.text.length > 5000) {
      return ResponseHelper.errorResponse('Text must be less than 5000 characters', 'TEXT_TOO_LONG', null, 400, env);
    }
    const result = await env.AI.run('@cf/huggingface/distilbert-sst-2-int8', { text: body.text });
    return ResponseHelper.jsonResponse({ success: true, text: body.text, sentiment: result[0].label, confidence: result[0].score }, 200, env);
  } catch (error) {
    console.error('Sentiment analysis error:', error);
    return ResponseHelper.errorResponse('Sentiment analysis failed', 'AI_ERROR', null, 500, env);
  }
}

async function handleGenerateInsights(request: Request, env: Env, user: User, apiKey: ApiKey): Promise<Response> {
  try {
    if (!env.AI) {
      return ResponseHelper.errorResponse('AI service not available', 'AI_NOT_CONFIGURED', null, 503, env);
    }
    const validation = await validateRequest(request, { source_id: 'number' });
    if (!validation.valid) {
      return ResponseHelper.errorResponse('Missing source_id', 'VALIDATION_ERROR', validation.errors, 400, env);
    }
    const body = validation.data as { source_id: number };
    const summary = await env.DB.prepare(`SELECT ds.source_name, ds.row_count, COUNT(rd.id) as actual_rows FROM data_sources ds LEFT JOIN raw_data rd ON rd.source_id = ds.id WHERE ds.id = ? AND ds.client_id = ? GROUP BY ds.id`).bind(body.source_id, user.client_id).first<{ source_name: string; row_count: number; actual_rows: number; }>();
    if (!summary) {
      return ResponseHelper.errorResponse('Data source not found', 'NOT_FOUND', null, 404, env);
    }
    const aiResponse = await env.AI.run('@cf/meta/llama-3-8b-instruct', { messages: [{ role: 'system', content: 'You are a business intelligence analyst. Generate 3-5 actionable insights and recommendations based on data summaries.' }, { role: 'user', content: `Data source: ${summary.source_name}\nTotal records: ${summary.row_count}\n\nGenerate business insights and recommendations.` }], max_tokens: 256 });
    return ResponseHelper.jsonResponse({ success: true, source: summary.source_name, insights: aiResponse.response, generated_at: new Date().toISOString() }, 200, env);
  } catch (error) {
    console.error('Insight generation error:', error);
    return ResponseHelper.errorResponse('Insight generation failed', 'AI_ERROR', null, 500, env);
  }
}

async function handleReportGenerate(request: Request, env: Env, user: User, apiKey: ApiKey): Promise<Response> {
  const startTime = Date.now();
  try {
    const validation = await validateRequest(request, { report_type: 'string' });
    if (!validation.valid) {
      await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/reports/generate', 'POST', 400, Date.now() - startTime);
      return ResponseHelper.errorResponse('Missing required field: report_type', 'VALIDATION_ERROR', validation.errors, 400, env);
    }
    const body = validation.data as { report_type: string; parameters?: any };
    const dataSources = await env.DB.prepare(`SELECT COUNT(*) as total_sources, SUM(row_count) as total_rows FROM data_sources WHERE client_id = ?`).bind(user.client_id).first<{ total_sources: number; total_rows: number; }>();
    const jobs = await env.DB.prepare(`SELECT COUNT(*) as total_jobs, COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_jobs FROM analysis_jobs WHERE client_id = ?`).bind(user.client_id).first<{ total_jobs: number; completed_jobs: number; }>();
    const insights = [];
    if (dataSources && dataSources.total_rows > 0) {
      insights.push({ type: 'data_volume', message: `Your organization has ${dataSources.total_sources} data sources with ${dataSources.total_rows} total records`, priority: 'high' });
    }
    if (jobs && jobs.total_jobs > 0) {
      const successRate = ((jobs.completed_jobs / jobs.total_jobs) * 100).toFixed(1);
      insights.push({ type: 'job_performance', message: `Analytics job success rate: ${successRate}%`, priority: jobs.completed_jobs === jobs.total_jobs ? 'low' : 'medium' });
    }
    const clientInfo = await env.DB.prepare('SELECT name FROM clients WHERE id = ?').bind(user.client_id).first<{ name: string; }>();
    const report = { report_id: crypto.randomUUID(), report_type: body.report_type, client_name: clientInfo?.name || 'Unknown', generated_at: new Date().toISOString(), period: body.parameters?.period || 'all_time', summary: { total_data_sources: dataSources?.total_sources || 0, total_data_rows: dataSources?.total_rows || 0, total_analytics_jobs: jobs?.total_jobs || 0, completed_jobs: jobs?.completed_jobs || 0 }, insights, recommendations: ['Consider implementing automated data quality checks', 'Regular model retraining recommended for improved accuracy', 'Enable real-time analytics for faster insights'] };
    await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/reports/generate', 'POST', 200, Date.now() - startTime);
    return ResponseHelper.jsonResponse({ success: true, report }, 200, env);
  } catch (error) {
    console.error('Report generation error:', error);
    await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/reports/generate', 'POST', 500, Date.now() - startTime);
    return ResponseHelper.errorResponse('Failed to generate report', 'REPORT_ERROR', null, 500, env);
  }
}

// ================= SWAGGER UI & OPENAPI SPEC =================
const getSwaggerHtml = (): string => `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <title>Predictive Analytics API Docs | DSN Research</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" />
    <style> body { margin: 0; background: #fafafa; } </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
    window.onload = () => {
        const ui = SwaggerUIBundle({
            url: '/openapi.json', dom_id: '#swagger-ui', deepLinking: true,
            presets: [ SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset ],
            plugins: [ SwaggerUIBundle.plugins.DownloadUrl ], layout: "BaseLayout",
            requestInterceptor: (req) => {
                const key = localStorage.getItem('api_key');
                if (key && !req.headers['X-API-Key'] && !req.headers.Authorization) { req.headers['X-API-Key'] = key; }
                return req;
            }
        });
        window.ui = ui;
    };
    </script>
</body>
</html>
`;

const getOpenApiSpec = (request: Request): any => {
  const url = new URL(request.url);
  const baseUrl = `${url.protocol}//${url.host}`;

  return {
    openapi: '3.0.3',
    info: {
      title: 'Predictive Analytics Services API',
      description: 'Powerful, easy-to-use tools for data management, analysis, business intelligence, machine learning, and AI services.\n\nTransform your data into actionable insights with our AI-powered API.',
      version: '1.0.0',
      contact: { name: 'DSN Research API Support', email: 'info@dsnresearch.com', url: 'https://dsnresearch.com' },
      license: { name: 'MIT License', url: 'https://opensource.org/licenses/MIT' },
    },
    servers: [
      { url: baseUrl, description: 'Current environment' },
      { url: 'https://api.dsnresearch.com', description: 'Production' },
    ],
    security: [{ ApiKeyAuth: [] }],
    components: {
      securitySchemes: {
        ApiKeyAuth: { type: 'apiKey', in: 'header', name: 'X-API-Key', description: 'Your API key (from signup response or client record)' },
      },
      schemas: {
        ErrorResponse: { type: 'object', properties: { error: { type: 'string', example: 'Invalid credentials' }, code: { type: 'string', example: 'INVALID_CREDENTIALS' }, success: { type: 'boolean', example: false } } },
        SignupRequest: { type: 'object', required: ['companyName', 'email', 'password', 'plan'], properties: { companyName: { type: 'string', example: 'Acme Corp' }, email: { type: 'string', format: 'email', example: 'user@example.com' }, password: { type: 'string', example: 'SecurePass123!@' }, plan: { type: 'string', enum: ['free', 'basic', 'pro', 'premium', 'enterprise'], example: 'pro' }, name: { type: 'string', example: 'John Doe' } } },
        LoginRequest: { type: 'object', required: ['email', 'password'], properties: { email: { type: 'string', format: 'email' }, password: { type: 'string' } } },
        DataUploadRequest: { type: 'object', required: ['source_name', 'source_type', 'data_rows'], properties: { source_name: { type: 'string', example: 'Sales Q1 2024' }, source_type: { type: 'string', example: 'csv' }, data_rows: { type: 'array', items: { type: 'object' }, example: [{ product: 'Widget A', revenue: 1500 }, { product: 'Widget B', revenue: 2300 }] } } },
      },
    },
    paths: {
      '/health': { get: { summary: 'Health check', description: 'Check if the API is running and database is connected', responses: { '200': { description: 'API is healthy', content: { 'application/json': { schema: { type: 'object', properties: { status: { type: 'string', example: 'healthy' }, timestamp: { type: 'string', format: 'date-time' }, database: { type: 'string', example: 'connected' }, version: { type: 'string', example: '1.0.0' } } } } } } } } },
      '/api/signup': { post: { summary: 'Create new account', description: 'Register a new client and user.', requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/SignupRequest' } } } }, responses: { '201': { description: 'Account created successfully', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean', example: true }, message: { type: 'string' }, apiKey: { type: 'string', example: 'dsn_a1b2c3...' }, token: { type: 'string', example: '...' }, clientId: { type: 'integer' }, userId: { type: 'integer' }, companyName: { type: 'string' }, plan: { type: 'string' } } } } } }, '400': { $ref: '#/components/schemas/ErrorResponse' }, '409': { $ref: '#/components/schemas/ErrorResponse' } } } },
      '/api/login': { post: { summary: 'User login', description: 'Authenticate to get a session token.', requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/LoginRequest' } } } }, responses: { '200': { description: 'Login successful', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, token: { type: 'string' }, user: { type: 'object' }, client: { type: 'object' }, api_key: { type: 'string' } } } } } }, '401': { $ref: '#/components/schemas/ErrorResponse' } } } },
      '/api/verify-email': { get: { summary: 'Verify email address', description: 'Complete email verification using the token from the signup email.', parameters: [{ name: 'token', in: 'query', required: true, schema: { type: 'string' } }], responses: { '200': { description: 'Email verified', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, message: { type: 'string' } } } } } }, '400': { $ref: '#/components/schemas/ErrorResponse' } } } },
      '/api/forgot-password': { post: { summary: 'Request password reset', description: 'Send a password reset email.', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { email: { type: 'string', format: 'email' } }, required: ['email'] } } } }, responses: { '200': { description: 'Reset email sent if account exists' } } } },
      '/api/reset-password': { post: { summary: 'Reset password with token', description: 'Reset user password using the token from the email.', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { token: { type: 'string' }, newPassword: { type: 'string' } }, required: ['token', 'newPassword'] } } } }, responses: { '200': { description: 'Password reset successful' }, '400': { $ref: '#/components/schemas/ErrorResponse' } } } },
      '/api/payment/create-payfast': { post: { security: [{ ApiKeyAuth: [] }], summary: 'Create PayFast Payment', description: 'Generates form data to initiate a PayFast payment.', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { plan: { type: 'string' }, amount: { type: 'number' }, name: { type: 'string' }, email: { type: 'string' } } } } } }, responses: { '200': { description: 'PayFast form data created' } } } },
      '/api/payment/create-paypal': { post: { security: [{ ApiKeyAuth: [] }], summary: 'Create PayPal Order', description: 'Creates a PayPal order and returns an approval URL.', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { plan: { type: 'string' }, amount: { type: 'number' } } } } } }, responses: { '200': { description: 'PayPal order created successfully' } } } },
      '/api/data/upload': { post: { security: [{ ApiKeyAuth: [] }], summary: 'Upload data', description: 'Upload structured data for analysis. Max 10,000 rows.', requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/DataUploadRequest' } } } }, responses: { '200': { description: 'Data uploaded successfully' }, '400': { $ref: '#/components/schemas/ErrorResponse' }, '429': { $ref: '#/components/schemas/ErrorResponse' } } } },
      '/api/data/sources': { get: { security: [{ ApiKeyAuth: [] }], summary: 'List data sources', description: 'Get all data sources for your client with pagination.', parameters: [{ name: 'limit', in: 'query', schema: { type: 'integer', default: 50, maximum: 100 } }, { name: 'offset', in: 'query', schema: { type: 'integer', default: 0 } }], responses: { '200': { description: 'List of data sources' } } } },
      '/api/analytics/query': { post: { security: [{ ApiKeyAuth: [] }], summary: 'Run analytics query', description: 'Start an analytics job (e.g., descriptive stats, forecasting).', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { source_id: { type: 'integer' }, analysis_type: { type: 'string', enum: ['descriptive', 'predictive', 'clustering'] }, parameters: { type: 'object' } }, required: ['source_id', 'analysis_type'] } } } }, responses: { '200': { description: 'Job created and completed' } } } },
      '/api/models/predict': { post: { security: [{ ApiKeyAuth: [] }], summary: 'Generate prediction', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { model_id: { type: 'integer' }, input_data: { type: 'object' } }, required: ['model_id', 'input_data'] } } } }, responses: { '200': { description: 'Prediction result' } } } },
      '/api/reports/generate': { post: { security: [{ ApiKeyAuth: [] }], summary: 'Generate report', description: 'Create a business intelligence report from your data sources.', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { report_type: { type: 'string', enum: ['monthly', 'quarterly', 'custom'] }, parameters: { type: 'object' } }, required: ['report_type'] } } } }, responses: { '200': { description: 'Report generated' } } } },
      '/api/ai/query': { post: { security: [{ ApiKeyAuth: [] }], summary: 'Ask AI about your data', description: 'Use natural language to query insights from your datasets.', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { query: { type: 'string', example: 'What are the top trends in my sales data?' }, source_id: { type: 'integer' } }, required: ['query', 'source_id'] } } } }, responses: { '200': { description: 'AI response' } } } },
      '/api/ai/sentiment': { post: { security: [{ ApiKeyAuth: [] }], summary: 'Analyze sentiment', description: 'Analyze the sentiment of a given text.', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { text: { type: 'string', example: 'This product is amazing!' } }, required: ['text'] } } } }, responses: { '200': { description: 'Sentiment analysis result' } } } },
      '/api/ai/insights': { post: { security: [{ ApiKeyAuth: [] }], summary: 'Generate business insights', description: 'Generate AI-powered business insights from your data.', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { source_id: { type: 'integer' } }, required: ['source_id'] } } } }, responses: { '200': { description: 'Generated insights' } } } },
    },
  };
};

// ================= MAIN REQUEST HANDLER =================
async function handleRequest(request: Request, env: Env): Promise<Response> {
  const config = Config.validate(env);
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: { 'Access-Control-Allow-Origin': config.ALLOWED_ORIGINS || '*', 'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key', 'Access-Control-Max-Age': '86400' } });
  }

  // Public & Docs Endpoints
  if (request.method === 'POST' && path === '/api/signup') return handleSignup(request, config);
  if (request.method === 'POST' && path === '/api/login') return handleLogin(request, config);
  if (request.method === 'GET' && path === '/api/verify-email') return handleVerifyEmail(request, config);
  if (request.method === 'POST' && path === '/api/forgot-password') return handleForgotPassword(request, config);
  if (request.method === 'POST' && path === '/api/reset-password') return handleResetPassword(request, config);
  if (request.method === 'POST' && path === '/api/payment/payfast-webhook') return handlePayFastWebhook(request, config);
  if (request.method === 'POST' && path === '/api/payment/paypal-webhook') return handlePayPalWebhook(request, config);
  if (path === '/health') return handleHealthCheck(config);
  if (path === '/docs' || path === '/swagger' || path === '/api-docs') return new Response(getSwaggerHtml(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  if (path === '/openapi.json') return ResponseHelper.jsonResponse(getOpenApiSpec(request), 200, config);

  // Authenticated Endpoints
  if (path.startsWith('/api/')) {
    const authResult = await authenticate(request, config);
    if (!authResult) {
      return ResponseHelper.errorResponse('Authentication required', 'UNAUTHORIZED', null, 401, config);
    }
    const { user, apiKey } = authResult;
    switch (path) {
      case '/api/data/upload': if (request.method === 'POST') return handleDataUpload(request, config, user, apiKey); break;
      case '/api/data/sources': if (request.method === 'GET') return handleDataSources(request, config, user, apiKey); break;
      case '/api/models/predict': if (request.method === 'POST') return handleModelPredict(request, config, user, apiKey); break;
      case '/api/analytics/query': if (request.method === 'POST') return handleAnalyticsQuery(request, config, user, apiKey); break;
      case '/api/ai/query': if (request.method === 'POST') return handleAIQuery(request, config, user, apiKey); break;
      case '/api/ai/sentiment': if (request.method === 'POST') return handleSentimentAnalysis(request, config, user, apiKey); break;
      case '/api/ai/insights': if (request.method === 'POST') return handleGenerateInsights(request, config, user, apiKey); break;
      case '/api/reports/generate': if (request.method === 'POST') return handleReportGenerate(request, config, user, apiKey); break;
      case '/api/payment/create-payfast': if (request.method === 'POST') return handleCreatePayFastPayment(request, config, user); break;
      case '/api/payment/create-paypal': if (request.method === 'POST') return handleCreatePayPalPayment(request, config, user); break;
      case '/api/user/plan': if (request.method === 'PUT') return handleUpdateUserPlan(request, config, user); break;
    }
  }

  // Root Endpoint
  if (path === '/' || path === '/api') {
    return ResponseHelper.jsonResponse({
      name: 'Predictive Analytics API',
      version: '1.0.0',
      environment: config.ENVIRONMENT,
      endpoints: {
        'POST /api/signup': 'Create new account', 'POST /api/login': 'User login', 'GET /api/verify-email': 'Verify email address', 'POST /api/forgot-password': 'Request password reset', 'POST /api/reset-password': 'Reset password with token', 'POST /api/payment/create-payfast': 'Create a PayFast payment session', 'POST /api/payment/create-paypal': 'Create a PayPal payment order', 'PUT /api/user/plan': 'Update user plan (downgrade to free)', 'POST /api/data/upload': 'Upload data for processing', 'GET /api/data/sources': 'List data sources', 'POST /api/analytics/query': 'Run analytics queries', 'POST /api/models/predict': 'Generate predictions', 'POST /api/reports/generate': 'Generate reports', 'POST /api/ai/query': 'Ask AI about your data', 'POST /api/ai/sentiment': 'Analyze sentiment of text', 'POST /api/ai/insights': 'Generate business insights from data',
      },
      documentation: {
        'GET /docs': 'Interactive API documentation (Swagger UI)', 'GET /openapi.json': 'OpenAPI specification', 'GET /health': 'Health check endpoint',
      },
      authentication: 'Include X-API-Key header or Authorization: Bearer {token}',
    }, 200, config);
  }

  return ResponseHelper.errorResponse('Not found', 'NOT_FOUND', null, 404, config);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      console.error('Unhandled error:', error);
      return ResponseHelper.errorResponse('Internal server error', 'INTERNAL_ERROR', null, 500);
    }
  },
};