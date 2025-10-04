// src/index.ts

export interface Env {
  DB: D1Database;
  JWT_SECRET: string;
  ENVIRONMENT?: string;
  ALLOWED_ORIGINS?: string;
}

interface User {
  id: number;
  email: string;
  name: string;
  company: string | null;
  subscription_status: string;
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
  is_active: number;
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

// ================= CONFIGURATION & VALIDATION =================
class Config {
  static validate(env: any): Env {
    if (!env.JWT_SECRET || env.JWT_SECRET.length < 32) {
      throw new Error('JWT_SECRET must be at least 32 characters');
    }
    if (!env.DB) {
      throw new Error('DB binding is required');
    }
    
    return {
      DB: env.DB,
      JWT_SECRET: env.JWT_SECRET,
      ENVIRONMENT: env.ENVIRONMENT || 'development',
      ALLOWED_ORIGINS: env.ALLOWED_ORIGINS || '*'
    };
  }
}

// ================= SECURITY UTILITIES =================
class Security {
  // Timing-safe comparison to prevent timing attacks
  static timingSafeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  }

  // Input sanitization
  static sanitizeInput(input: any): any {
    if (typeof input === 'string') {
      // Remove potential XSS vectors
      return input.replace(/[<>"'`]/g, '');
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

  // Validate email format
  static isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  // Validate password strength
  static isStrongPassword(password: string): { valid: boolean; message?: string } {
    if (password.length < 8) {
      return { valid: false, message: 'Password must be at least 8 characters' };
    }
    if (!/(?=.*[a-z])(?=.*[A-Z])/.test(password)) {
      return { valid: false, message: 'Password must contain both uppercase and lowercase letters' };
    }
    if (!/(?=.*\d)/.test(password)) {
      return { valid: false, message: 'Password must contain at least one number' };
    }
    return { valid: true };
  }
}

// ================= PASSWORD HASHING =================
class PasswordHasher {
  // Generate random salt
  static getRandomSalt(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(16));
  }

  // Convert buffer to hex string
  static bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }

  // Hash password with PBKDF2 (more secure than SHA-256 alone)
  static async hashPassword(password: string, salt: Uint8Array): Promise<{hash: string, salt: string}> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveBits']
    );
    
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    );
    
    return {
      hash: this.bufferToHex(derivedBits),
      salt: this.bufferToHex(salt)
    };
  }

  // Verify password
  static async verifyPassword(password: string, saltHex: string, hash: string): Promise<boolean> {
    const salt = new Uint8Array(saltHex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
    const hashed = await this.hashPassword(password, salt);
    return Security.timingSafeEqual(hashed.hash, hash);
  }
}

// ================= JWT TOKEN MANAGEMENT =================
class JWTManager {
  static async createHmacSigningKey(secret: string): Promise<CryptoKey> {
    const keyData = Uint8Array.from(atob(secret), c => c.charCodeAt(0));
    return await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify']
    );
  }

  static async signJwt(payload: object, secret: string): Promise<string> {
    const encoder = new TextEncoder();
    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = btoa(JSON.stringify(header));
    
    const payloadWithDates = {
      ...payload,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7 // 7-day expiry
    };
    
    const encodedPayload = btoa(JSON.stringify(payloadWithDates));
    const signingKey = await this.createHmacSigningKey(secret);
    const dataToSign = encoder.encode(`${encodedHeader}.${encodedPayload}`);
    const signatureBuffer = await crypto.subtle.sign('HMAC', signingKey, dataToSign);
    const signature = PasswordHasher.bufferToHex(signatureBuffer);

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
      const expectedSignature = PasswordHasher.bufferToHex(signatureBuffer);

      return Security.timingSafeEqual(signature, expectedSignature) ? 
             JSON.parse(atob(encodedPayload)) : null;
    } catch (e) {
      return null;
    }
  }
}

// ================= RATE LIMITING =================
class RateLimiter {
  static async checkRateLimit(env: Env, apiKey: string): Promise<{allowed: boolean, remaining: number}> {
    const windowMs = 3600000; // 1 hour
    const maxRequests = 1000; // Default limit
    
    const result = await env.DB.prepare(`
      SELECT COUNT(*) as count FROM api_usage 
      WHERE key_id = ? AND timestamp > datetime('now', '-1 hour')
    `).bind(apiKey).first<{count: number}>();

    const count = result?.count || 0;
    
    return {
      allowed: count < maxRequests,
      remaining: Math.max(0, maxRequests - count)
    };
  }

  static async recordUsage(env: Env, keyId: string, userId: number, endpoint: string, method: string, statusCode: number, responseTime: number): Promise<void> {
    await env.DB.prepare(`
      INSERT INTO api_usage (key_id, user_id, endpoint, method, status_code, response_time_ms, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(keyId, userId, endpoint, method, statusCode, responseTime).run();
  }
}

// ================= RESPONSE HELPERS =================
class ResponseHelper {
  static jsonResponse(data: any, status: number = 200, env?: Env): Response {
    const response = new Response(JSON.stringify(data), {
      status,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': env?.ALLOWED_ORIGINS || '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
      },
    });

    return ResponseHelper.securityHeaders(response);
  }

  static errorResponse(message: string, code: string = 'GENERIC_ERROR', details?: any, status: number = 400, env?: Env): Response {
    return this.jsonResponse({
      error: message,
      code,
      details,
      success: false
    }, status, env);
  }

  static securityHeaders(response: Response): Response {
    const headers = new Headers(response.headers);
    
    // Security headers
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('X-Frame-Options', 'DENY');
    headers.set('X-XSS-Protection', '1; mode=block');
    headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Remove server information
    headers.delete('server');
    headers.delete('x-powered-by');

    return new Response(response.body, {
      status: response.status,
      headers: headers
    });
  }
}

// ================= AUTHENTICATION MIDDLEWARE =================
async function authenticate(request: Request, env: Env): Promise<AuthResult | null> {
  const apiKey = request.headers.get('X-API-Key') || 
                 request.headers.get('Authorization')?.replace('Bearer ', '').trim();

  if (!apiKey) return null;

  try {
    // Find key and join with user and client
    const result = await env.DB.prepare(`
      SELECT 
        u.*,
        c.id as client_id,
        c.name as client_name,
        c.api_key as client_api_key,
        c.plan as client_plan,
        k.id as key_internal_id,
        k.key_id,
        k.key_hash,
        k.permissions,
        k.rate_limit,
        k.is_active as key_is_active,
        k.expires_at
      FROM api_keys k
      JOIN users u ON u.id = k.user_id
      JOIN clients c ON c.id = u.client_id
      WHERE k.key_id = ? AND k.is_active = 1
    `).bind(apiKey).first();

    if (!result) return null;

    // Check if API key is expired
    if (result.expires_at && typeof result.expires_at === 'string' && new Date(result.expires_at) < new Date()) {
      return null;
    }

    const user: User = {
      id: Number(result.id),
      email: String(result.email),
      name: String(result.name),
      company: result.company ? String(result.company) : null,
      subscription_status: String(result.subscription_status),
      created_at: String(result.created_at),
      updated_at: String(result.updated_at),
      last_login_at: result.last_login_at ? String(result.last_login_at) : null,
      email_verified: Number(result.email_verified) as 0 | 1,
      is_active: Number(result.is_active) as 0 | 1,
      client_id: Number(result.client_id)
    };

    const client: Client = {
      id: Number(result.client_id),
      name: String(result.client_name),
      api_key: String(result.client_api_key),
      plan: String(result.client_plan),
      created_at: String(result.created_at)
    };

    const apiKeyData: ApiKey = {
      id: Number(result.key_internal_id),
      key_id: String(result.key_id),
      key_hash: String(result.key_hash),
      user_id: Number(result.id),
      permissions: String(result.permissions),
      rate_limit: Number(result.rate_limit),
      is_active: Number(result.key_is_active) as 0 | 1
    };

    // Update last used
    await env.DB.prepare(`
      UPDATE api_keys 
      SET last_used_at = datetime('now'), usage_count = usage_count + 1 
      WHERE key_id = ?
    `).bind(apiKey).run();

    return { user, client, apiKey: apiKeyData };

  } catch (error) {
    console.error('Authentication error:', error);
    return null;
  }
}

// ================= REQUEST VALIDATION =================
async function validateRequest(request: Request, schema: {[key: string]: 'string' | 'number' | 'object' | 'array'}): Promise<{valid: boolean, errors?: string[], data?: any}> {
  try {
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

    return {
      valid: errors.length === 0,
      errors: errors.length > 0 ? errors : undefined,
      data: sanitizedBody
    };
  } catch (error) {
    return { valid: false, errors: ['Invalid JSON in request body'] };
  }
}

// ================= HEALTH CHECK =================
async function handleHealthCheck(env: Env): Promise<Response> {
  try {
    // Test database connection
    const dbTest = await env.DB.prepare('SELECT 1 as test').first();
    
    return ResponseHelper.jsonResponse({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      database: dbTest ? 'connected' : 'error',
      version: '1.0.0'
    }, 200, env);
  } catch (error) {
    return ResponseHelper.jsonResponse({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      database: 'disconnected',
      error: 'Database connection failed'
    }, 503, env);
  }
}

// ================= AUTH HANDLERS =================
async function handleSignup(request: Request, env: Env): Promise<Response> {
  try {
    const validation = await validateRequest(request, {
      companyName: 'string',
      email: 'string',
      password: 'string',
      plan: 'string',
      name: 'string'
    });

    if (!validation.valid) {
      return ResponseHelper.errorResponse(
        'Invalid request data', 
        'VALIDATION_ERROR', 
        validation.errors, 
        400, 
        env
      );
    }

    const body: SignupRequest = validation.data!;
    const { companyName, email, password, plan, name } = body;

    // Validate email
    if (!Security.isValidEmail(email)) {
      return ResponseHelper.errorResponse('Invalid email format', 'INVALID_EMAIL', null, 400, env);
    }

    // Validate password strength
    const passwordCheck = Security.isStrongPassword(password);
    if (!passwordCheck.valid) {
      return ResponseHelper.errorResponse(passwordCheck.message!, 'WEAK_PASSWORD', null, 400, env);
    }

    const validPlans = ['free', 'basic', 'pro', 'premium', 'enterprise'];
    if (plan && !validPlans.includes(plan)) {
      return ResponseHelper.errorResponse('Invalid plan selected', 'INVALID_PLAN', null, 400, env);
    }

    // Check for existing user
    const existingUser = await env.DB.prepare('SELECT id FROM users WHERE email = ?')
      .bind(email)
      .first();

    if (existingUser) {
      return ResponseHelper.errorResponse('User already exists with this email', 'USER_EXISTS', null, 409, env);
    }

    // Generate API key
    const apiKey = 'dsn_' + crypto.getRandomValues(new Uint8Array(16)).reduce((acc, byte) => 
      acc + byte.toString(36), '') + Date.now().toString(36);

    const salt = PasswordHasher.getRandomSalt();
    const hashedPassword = await PasswordHasher.hashPassword(password, salt);

    // Create client
    const clientResult = await env.DB.prepare(`
      INSERT INTO clients (name, api_key, plan, created_at)
      VALUES (?, ?, ?, datetime('now'))
    `).bind(companyName, apiKey, plan || 'free').run();

    const clientId = clientResult.meta.last_row_id;

    // Create user
    const userResult = await env.DB.prepare(`
      INSERT INTO users (client_id, email, password_hash, salt_hex, name, created_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
    `).bind(clientId, email, hashedPassword.hash, hashedPassword.salt, name || '').run();

    const userId = userResult.meta.last_row_id;

    // Create API key record
    await env.DB.prepare(`
      INSERT INTO api_keys (key_id, key_hash, user_id, name, created_at)
      VALUES (?, ?, ?, ?, datetime('now'))
    `).bind(apiKey, hashedPassword.hash, userId, 'Default Key').run();

    // Generate email verification token
    const verifyToken = await JWTManager.signJwt(
      { type: 'verify-email', userId, email },
      env.JWT_SECRET
    );

    // Generate session token
    const sessionToken = await JWTManager.signJwt({ userId }, env.JWT_SECRET);

    return ResponseHelper.jsonResponse({
      success: true,
      message: 'Account created successfully. Please verify your email.',
      apiKey: apiKey,
      token: sessionToken,
      verifyEmailUrl: `/api/verify-email?token=${encodeURIComponent(verifyToken)}`,
      clientId: clientId,
      userId: userId,
      companyName: companyName,
      plan: plan || 'free'
    }, 201, env);

  } catch (error) {
    console.error('Signup error:', error);
    return ResponseHelper.errorResponse('Failed to create account', 'SIGNUP_ERROR', null, 500, env);
  }
}

async function handleLogin(request: Request, env: Env): Promise<Response> {
  try {
    const validation = await validateRequest(request, {
      email: 'string',
      password: 'string'
    });

    if (!validation.valid) {
      return ResponseHelper.errorResponse('Email and password required', 'VALIDATION_ERROR', null, 400, env);
    }

    const body = validation.data! as { email: string; password: string };
    const { email, password } = body;

    const user = await env.DB.prepare(`
      SELECT id, password_hash, salt_hex, client_id, email_verified, name FROM users WHERE email = ?
    `).bind(email).first<{ 
      id: number; 
      password_hash: string; 
      salt_hex: string; 
      client_id: number; 
      email_verified: number;
      name: string;
    }>();

    if (!user || !(await PasswordHasher.verifyPassword(password, user.salt_hex, user.password_hash))) {
      return ResponseHelper.errorResponse('Invalid credentials', 'INVALID_CREDENTIALS', null, 401, env);
    }

    if (!user.email_verified) {
      return ResponseHelper.errorResponse('Please verify your email before logging in.', 'EMAIL_NOT_VERIFIED', null, 403, env);
    }

    const client = await env.DB.prepare(`
      SELECT id, name, api_key, plan FROM clients WHERE id = ?
    `).bind(user.client_id).first<{ id: number; name: string; api_key: string; plan: string }>();

    if (!client) {
      return ResponseHelper.errorResponse('Client not found', 'CLIENT_NOT_FOUND', null, 404, env);
    }

    // Update last login
    await env.DB.prepare(`UPDATE users SET last_login_at = datetime('now') WHERE id = ?`)
      .bind(user.id).run();

    const token = await JWTManager.signJwt({ userId: user.id }, env.JWT_SECRET);

    return ResponseHelper.jsonResponse({
      success: true,
      token,
      user: {
        id: user.id,
        name: user.name,
        email: email
      },
      client: {
        id: client.id,
        name: client.name,
        plan: client.plan
      },
      api_key: client.api_key
    }, 200, env);
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

  const result = await env.DB.prepare(`
    UPDATE users SET email_verified = 1 WHERE id = ? AND email = ?
  `).bind(userId, email).run();

  if (result.meta.changes === 0) {
    return ResponseHelper.errorResponse('User not found or already verified', 'VERIFICATION_FAILED', null, 404, env);
  }

  return ResponseHelper.jsonResponse({
    success: true,
    message: 'Email verified successfully!'
  }, 200, env);
}

// ================= API ENDPOINT HANDLERS =================
async function handleDataUpload(request: Request, env: Env, user: User, apiKey: ApiKey): Promise<Response> {
  const startTime = Date.now();
  
  try {
    // Check rate limit
    const rateLimit = await RateLimiter.checkRateLimit(env, apiKey.key_id);
    if (!rateLimit.allowed) {
      return ResponseHelper.errorResponse(
        'Rate limit exceeded', 
        'RATE_LIMIT_EXCEEDED', 
        { remaining: rateLimit.remaining }, 
        429, 
        env
      );
    }

    const validation = await validateRequest(request, {
      source_name: 'string',
      source_type: 'string',
      data_rows: 'array'
    });

    if (!validation.valid) {
      await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/data/upload', 'POST', 400, Date.now() - startTime);
      return ResponseHelper.errorResponse(
        'Missing required fields: source_name, source_type, data_rows', 
        'VALIDATION_ERROR', 
        validation.errors, 
        400, 
        env
      );
    }

    const body = validation.data! as { source_name: string; source_type: string; data_rows: any[] };
    const { source_name: sourceName, source_type: sourceType, data_rows: dataRows } = body;

    const sourceResult = await env.DB.prepare(`
      INSERT INTO data_sources (client_id, source_name, source_type, row_count)
      VALUES (?, ?, ?, ?)
    `).bind(user.client_id, sourceName, sourceType, dataRows.length).run();

    const sourceId = sourceResult.meta.last_row_id;

    // Batch insert for performance
    const batchSize = 100;
    for (let i = 0; i < dataRows.length; i += batchSize) {
      const batch = dataRows.slice(i, i + batchSize);
      const placeholders = batch.map(() => '(?, ?)').join(',');
      const values = batch.flatMap(row => [sourceId, JSON.stringify(row)]);
      
      await env.DB.prepare(`
        INSERT INTO raw_data (source_id, data_row) VALUES ${placeholders}
      `).bind(...values).run();
    }

    await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/data/upload', 'POST', 200, Date.now() - startTime);

    return ResponseHelper.jsonResponse({
      success: true,
      message: `Uploaded ${dataRows.length} rows to ${sourceName}`,
      source_id: sourceId
    }, 200, env);

  } catch (error) {
    console.error('Data upload error:', error);
    await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/data/upload', 'POST', 500, Date.now() - startTime);
    return ResponseHelper.errorResponse('Failed to upload data', 'UPLOAD_ERROR', null, 500, env);
  }
}

async function handleDataSources(request: Request, env: Env, user: User, apiKey: ApiKey): Promise<Response> {
  const startTime = Date.now();
  
  try {
    const rateLimit = await RateLimiter.checkRateLimit(env, apiKey.key_id);
    if (!rateLimit.allowed) {
      return ResponseHelper.errorResponse(
        'Rate limit exceeded', 
        'RATE_LIMIT_EXCEEDED', 
        { remaining: rateLimit.remaining }, 
        429, 
        env
      );
    }

    const sources = await env.DB.prepare(`
      SELECT id, source_name, source_type, row_count, last_ingested, created_at
      FROM data_sources 
      WHERE client_id = ?
      ORDER BY created_at DESC
    `).bind(user.client_id).all();

    await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/data/sources', 'GET', 200, Date.now() - startTime);

    return ResponseHelper.jsonResponse({
      success: true,
      data_sources: sources.results
    }, 200, env);

  } catch (error) {
    console.error('Data sources error:', error);
    await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/data/sources', 'GET', 500, Date.now() - startTime);
    return ResponseHelper.errorResponse('Failed to fetch data sources', 'FETCH_ERROR', null, 500, env);
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
  <style>
    html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
    *, *:before, *:after { box-sizing: inherit; }
    body { margin: 0; background: #fafafa; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => {
      const ui = SwaggerUIBundle({
        url: '/openapi.json',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "BaseLayout",  // Changed from "StandaloneLayout"
        requestInterceptor: (req) => {
          const key = localStorage.getItem('api_key');
          if (key && !req.headers['X-API-Key'] && !req.headers.Authorization) {
            req.headers['X-API-Key'] = key;
          }
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
    openapi: "3.0.3",
    info: {
      title: "Predictive Analytics Services API",
      description: "Powerful, easy-to-use tools for data management, analysis, business intelligence, machine learning, and AI services.\n\n" +
                   "Transform your data into actionable insights with our AI-powered API.",
      version: "1.0.0",
      contact: {
        name: "DSN Research API Support",
        email: "info@dsnresearch.co.za",
        url: "https://dsnresearch.com"
      },
      license: {
        name: "MIT License",
        url: "https://opensource.org/licenses/MIT"
      }
    },
    servers: [
      {
        url: baseUrl,
        description: "Current environment"
      },
      {
        url: "https://data-analytics-api.sibusiso-ndzukuma.workers.dev",
        description: "Production"
      }
    ],
    security: [{ ApiKeyAuth: [] }],
    components: {
      securitySchemes: {
        ApiKeyAuth: {
          type: "apiKey",
          in: "header",
          name: "X-API-Key",
          description: "Your API key (from signup response or client record)"
        }
      },
      schemas: {
        ErrorResponse: {
          type: "object",
          properties: {
            error: { type: "string", example: "Invalid credentials" },
            code: { type: "string", example: "INVALID_CREDENTIALS" },
            success: { type: "boolean", example: false }
          }
        },
        SignupRequest: {
          type: "object",
          required: ["companyName", "email", "password", "plan"],
          properties: {
            companyName: { type: "string", example: "Acme Corp" },
            email: { type: "string", format: "email", example: "user@example.com" },
            password: { type: "string", example: "SecurePass123!" },
            plan: { type: "string", enum: ["free", "basic", "pro", "premium", "enterprise"], example: "pro" },
            name: { type: "string", example: "John Doe" }
          }
        },
        LoginRequest: {
          type: "object",
          required: ["email", "password"],
          properties: {
            email: { type: "string", format: "email" },
            password: { type: "string" }
          }
        },
        DataUploadRequest: {
          type: "object",
          required: ["source_name", "source_type", "data_rows"],
          properties: {
            source_name: { type: "string", example: "Sales Q1 2024" },
            source_type: { type: "string", example: "csv" },
            data_rows: {
              type: "array",
              items: { type: "object" },
              example: [{ "product": "Widget A", "revenue": 1500 }, { "product": "Widget B", "revenue": 2300 }]
            }
          }
        }
      }
    },
    paths: {
      "/health": {
        get: {
          summary: "Health check",
          description: "Check if the API is running and database is connected",
          responses: {
            "200": {
              description: "API is healthy",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      status: { type: "string", example: "healthy" },
                      timestamp: { type: "string", format: "date-time" },
                      database: { type: "string", example: "connected" },
                      version: { type: "string", example: "1.0.0" }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "/api/signup": {
        post: {
          summary: "Create new account",
          description: "Register a new client and user. Returns API key and verification URL.",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/SignupRequest" }
              }
            }
          },
          responses: {
            "201": {
              description: "Account created successfully",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      success: { type: "boolean", example: true },
                      message: { type: "string" },
                      apiKey: { type: "string", example: "dsn_a1b2c3..." },
                      token: { type: "string", example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." },
                      verifyEmailUrl: { type: "string" },
                      clientId: { type: "integer" },
                      userId: { type: "integer" },
                      companyName: { type: "string" },
                      plan: { type: "string" }
                    }
                  }
                }
              }
            },
            "400": { $ref: "#/components/schemas/ErrorResponse" },
            "409": { $ref: "#/components/schemas/ErrorResponse" }
          }
        }
      },
      "/api/login": {
        post: {
          summary: "User login",
          description: "Authenticate with email and password to get a session token.",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/LoginRequest" }
              }
            }
          },
          responses: {
            "200": {
              description: "Login successful",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      success: { type: "boolean" },
                      token: { type: "string" },
                      user: { type: "object" },
                      client: { type: "object" },
                      api_key: { type: "string" }
                    }
                  }
                }
              }
            },
            "401": { $ref: "#/components/schemas/ErrorResponse" }
          }
        }
      },
      "/api/verify-email": {
        get: {
          summary: "Verify email address",
          description: "Complete email verification using token from signup email.",
          parameters: [
            {
              name: "token",
              in: "query",
              required: true,
              schema: { type: "string" }
            }
          ],
          responses: {
            "200": {
              description: "Email verified",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      success: { type: "boolean" },
                      message: { type: "string" }
                    }
                  }
                }
              }
            },
            "400": { $ref: "#/components/schemas/ErrorResponse" }
          }
        }
      },
      "/api/data/upload": {
        post: {
          security: [{ ApiKeyAuth: [] }],
          summary: "Upload data for processing",
          description: "Upload structured data (e.g., from CSV/Excel) for analysis.",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/DataUploadRequest" }
              }
            }
          },
          responses: {
            "200": {
              description: "Data uploaded successfully",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      success: { type: "boolean" },
                      message: { type: "string" },
                      source_id: { type: "integer" }
                    }
                  }
                }
              }
            },
            "400": { $ref: "#/components/schemas/ErrorResponse" }
          }
        }
      },
      "/api/data/sources": {
        get: {
          security: [{ ApiKeyAuth: [] }],
          summary: "List data sources",
          description: "Get all data sources for your client.",
          responses: {
            "200": {
              description: "List of data sources",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      success: { type: "boolean" },
                      data_sources: {
                        type: "array",
                        items: {
                          type: "object",
                          properties: {
                            id: { type: "integer" },
                            source_name: { type: "string" },
                            source_type: { type: "string" },
                            row_count: { type: "integer" },
                            last_ingested: { type: "string", format: "date-time" },
                            created_at: { type: "string", format: "date-time" }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "/api/analytics/query": {
        post: {
          security: [{ ApiKeyAuth: [] }],
          summary: "Run analytics query",
          description: "Start an analytics job (e.g., descriptive stats, forecasting).",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    source_id: { type: "integer" },
                    analysis_type: { type: "string", enum: ["descriptive", "predictive", "clustering"] },
                    parameters: { type: "object" }
                  },
                  required: ["source_id", "analysis_type"]
                }
              }
            }
          },
          responses: {
            "200": {
              description: "Job created and completed (for sync jobs)",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      success: { type: "boolean" },
                      job_id: { type: "integer" },
                      status: { type: "string" },
                      results: { type: "object" }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "/api/analytics/jobs/{jobId}": {
        get: {
          security: [{ ApiKeyAuth: [] }],
          summary: "Get analysis job status",
          parameters: [
            {
              name: "jobId",
              in: "path",
              required: true,
              schema: { type: "integer" }
            }
          ],
          responses: {
            "200": {
              description: "Job status and results",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      success: { type: "boolean" },
                      job: { type: "object" }
                    }
                  }
                }
              }
            },
            "404": { $ref: "#/components/schemas/ErrorResponse" }
          }
        }
      },
      "/api/models/list": {
        get: {
          security: [{ ApiKeyAuth: [] }],
          summary: "List available ML models",
          responses: {
            "200": {
              description: "List of models",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      success: { type: "boolean" },
                      models: {
                        type: "array",
                        items: {
                          type: "object",
                          properties: {
                            id: { type: "integer" },
                            model_name: { type: "string" },
                            model_type: { type: "string" },
                            version: { type: "string" },
                            is_active: { type: "boolean" },
                            created_at: { type: "string", format: "date-time" }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "/api/models/predict": {
        post: {
          security: [{ ApiKeyAuth: [] }],
          summary: "Generate prediction",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    model_id: { type: "integer" },
                    input_data: { type: "object" }
                  },
                  required: ["model_id", "input_data"]
                }
              }
            }
          },
          responses: {
            "200": {
              description: "Prediction result",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      success: { type: "boolean" },
                      prediction: { type: "object" }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "/api/reports/generate": {
        post: {
          security: [{ ApiKeyAuth: [] }],
          summary: "Generate automated report",
          description: "Create a business intelligence report from your data sources.",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    report_type: { type: "string", enum: ["monthly", "quarterly", "custom"] },
                    parameters: { type: "object" }
                  },
                  required: ["report_type"]
                }
              }
            }
          },
          responses: {
            "200": {
              description: "Report generated",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      success: { type: "boolean" },
                      report: { type: "object" }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  };
};

async function handleModelPredict(request: Request, env: Env, user: User, apiKey: ApiKey): Promise<Response> {
  const startTime = Date.now();
  
  try {
    const validation = await validateRequest(request, {
      model_id: 'number',
      input_data: 'object'
    });

    if (!validation.valid) {
      await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/models/predict', 'POST', 400, Date.now() - startTime);
      return ResponseHelper.errorResponse(
        'Missing required fields: model_id, input_data',
        'VALIDATION_ERROR',
        validation.errors,
        400,
        env
      );
    }

    const body = validation.data as { model_id: number; input_data: { x: number } };
    const { model_id: modelId, input_data: inputData } = body;

    // Simple linear regression: y = mx + b
    // Using mock coefficients for demo (in production, fetch from ml_models table)
    const slope = 2.5;
    const intercept = 10;
    const prediction = slope * inputData.x + intercept;

    const result = {
      model_id: modelId,
      prediction: prediction,
      confidence: 0.85 + Math.random() * 0.1, // Mock confidence score
      input: inputData,
      timestamp: new Date().toISOString()
    };

    await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/models/predict', 'POST', 200, Date.now() - startTime);

    return ResponseHelper.jsonResponse({
      success: true,
      prediction: result
    }, 200, env);
  } catch (error) {
    console.error('Prediction error:', error);
    await RateLimiter.recordUsage(env, apiKey.key_id, user.id, '/api/models/predict', 'POST', 500, Date.now() - startTime);
    return ResponseHelper.errorResponse('Failed to generate prediction', 'PREDICTION_ERROR', null, 500, env);
  }
}

// ================= MAIN REQUEST HANDLER =================
async function handleRequest(request: Request, env: Env): Promise<Response> {
  const config = Config.validate(env);
  const url = new URL(request.url);
  const path = url.pathname;

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': config.ALLOWED_ORIGINS || '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
      },
    });
  }

  // Public endpoints
  if (path === '/api/signup' && request.method === 'POST') {
    return handleSignup(request, config);
  }

  if (path === '/api/login' && request.method === 'POST') {
    return handleLogin(request, config);
  }

  if (path === '/api/verify-email' && request.method === 'GET') {
    return handleVerifyEmail(request, config);
  }

  if (path === '/health') {
    return handleHealthCheck(config);
  }

  // ✅ SERVE SWAGGER UI
  if (path === '/docs' || path === '/swagger' || path === '/api-docs') {
    return new Response(getSwaggerHtml(), {
      headers: { 
        'Content-Type': 'text/html; charset=utf-8',
        ...ResponseHelper.securityHeaders(new Response()).headers
      },
    });
  }

  // ✅ SERVE OPENAPI SPEC
  if (path === '/openapi.json') {
    return ResponseHelper.jsonResponse(getOpenApiSpec(request), 200, config);
  }

// Authenticated endpoints
if (path.startsWith('/api/') && !['/api/signup', '/api/login', '/api/verify-email'].includes(path)) {
  const authResult = await authenticate(request, config);
  if (!authResult) {
    return ResponseHelper.errorResponse('Authentication required', 'UNAUTHORIZED', null, 401, config);
  }

  const { user, apiKey } = authResult;

  // Route to appropriate handler
  switch (path) {
    case '/api/data/upload':
      if (request.method === 'POST') return handleDataUpload(request, config, user, apiKey);
      break;
    case '/api/data/sources':
      if (request.method === 'GET') return handleDataSources(request, config, user, apiKey);
      break;
    case '/api/models/predict':
      if (request.method === 'POST') return handleModelPredict(request, config, user, apiKey);
      break;
    // Add other handlers here as you implement them
    default:
      if (path.startsWith('/api/analytics/jobs/') && request.method === 'GET') {
        const jobId = path.split('/').pop();
        if (jobId) {
          // return handleJobStatus(request, config, user, apiKey, jobId);
        }
      }
  }

  return ResponseHelper.errorResponse('Endpoint not found', 'NOT_FOUND', null, 404, config);
}

  // Root endpoint
  if (path === '/' || path === '/api') {
    return ResponseHelper.jsonResponse({
      name: 'Predictive Analytics API',
      version: '1.0.0',
      environment: config.ENVIRONMENT,
      endpoints: {
        'POST /api/signup': 'Create new account (public)',
        'POST /api/login': 'User login (public)',
        'GET /api/verify-email': 'Verify email address (public)',
        'POST /api/data/upload': 'Upload data for processing',
        'GET /api/data/sources': 'List data sources',
        'POST /api/analytics/query': 'Run analytics queries',
        'GET /api/analytics/jobs/{id}': 'Check job status',
        'GET /api/models/list': 'List available ML models',
        'POST /api/models/predict': 'Generate predictions',
        'POST /api/reports/generate': 'Generate reports'
      },
      documentation: {
        'GET /docs': 'Interactive API documentation (Swagger UI)',
        'GET /openapi.json': 'OpenAPI specification',
        'GET /health': 'Health check endpoint'
      },
      authentication: 'Include X-API-Key header or Authorization: Bearer {token}'
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