import { createServer } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { randomBytes, createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand, CopyObjectCommand } from '@aws-sdk/client-s3';
import { createPresignedPost } from '@aws-sdk/s3-presigned-post';
import { DynamoDBClient, PutItemCommand, GetItemCommand, DeleteItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { ECSClient, RunTaskCommand } from '@aws-sdk/client-ecs';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { CognitoJwtVerifier } from 'aws-jwt-verify';

const env = process.env;
const region = env.APP_AWS_REGION || env.AWS_REGION || 'ap-northeast-1';
const s3 = new S3Client({ region, maxAttempts: 2 });
const ddb = new DynamoDBClient({ region, maxAttempts: 2 });
const ecs = new ECSClient({ region, maxAttempts: 2 });
const secrets = new SecretsManagerClient({ region, maxAttempts: 2 });
const verifier = env.COGNITO_USER_POOL_ID && env.COGNITO_CLIENT_ID
  ? CognitoJwtVerifier.create({ userPoolId: env.COGNITO_USER_POOL_ID, tokenUse: 'id', clientId: env.COGNITO_CLIENT_ID }) : null;
function htmlAsset(name) {
  const bundled = new URL(`./${name}`, import.meta.url);
  return readFileSync(existsSync(bundled) ? bundled : new URL(`../web/${name}`, import.meta.url));
}
const pages = { '/': htmlAsset('index.html'), '/terms': htmlAsset('terms.html'), '/privacy': htmlAsset('privacy.html') };
const favicon = htmlAsset('favicon.svg');
const legalVersion = '2026-10-24';
const categories = new Set(['sqli', 'xss', 'path_traversal', 'cmdi', 'ssrf', 'xxe', 'ssti']);
const logFormats = new Set(['cloudfront', 'alb', 'combined']);
const maxTrafficLogBytes = 50 << 20;
const maxDailyLogUploads = 50;
const maxBodyBytes = (1 << 21) + 8192;
const maxSnapshotBytes = 1 << 20;
let cachedSecret;
let cachedUntil = 0;

function reply(res, status, body, extra = {}) {
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
  res.writeHead(status, {
    'content-type': typeof body === 'string' ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8',
    'content-length': bytes.length, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff',
    'referrer-policy': 'same-origin', 'x-frame-options': 'DENY', ...extra,
  });
  res.end(bytes);
}
function redirect(res, path, cookie) {
  res.writeHead(302, { location: path, 'cache-control': 'no-store', ...(cookie ? { 'set-cookie': cookie } : {}) });
  res.end();
}
function cookie(req, name) {
  const raw = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
  return raw ? raw.slice(name.length + 1) : '';
}
function safeCookie(name, value, maxAge, httpOnly = true) {
  return `${name}=${value}; Path=/; Max-Age=${maxAge}; Secure; SameSite=Lax${httpOnly ? '; HttpOnly' : ''}`;
}
function error(res, status, message) { reply(res, status, { error: message }); }
function jstDay() { return new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Tokyo', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date()); }
function ttl(seconds) { return Math.floor(Date.now() / 1000) + seconds; }
function b64url(bytes) { return Buffer.from(bytes).toString('base64url'); }
function sha256(text) { return b64url(createHash('sha256').update(text).digest()); }
function attr(value) { return { S: value }; }
function putItem(item, condition) { return ddb.send(new PutItemCommand({ TableName: env.BUDGET_TABLE, Item: item, ...(condition ? { ConditionExpression: condition } : {}) })); }
function getItem(pk) { return ddb.send(new GetItemCommand({ TableName: env.BUDGET_TABLE, Key: { pk: attr(pk) }, ConsistentRead: true })); }
function deleteItem(pk) { return ddb.send(new DeleteItemCommand({ TableName: env.BUDGET_TABLE, Key: { pk: attr(pk) } })); }
function cognitoUrl(path) { return `https://${env.COGNITO_DOMAIN}${path}`; }

async function authenticatedUser(req) {
  const token = cookie(req, 'waf_session');
  if (!token || !verifier) return null;
  try { return await verifier.verify(token); } catch { return null; }
}
async function login(req, res) {
  const state = b64url(randomBytes(24));
  const verifierValue = b64url(randomBytes(32));
  await putItem({ pk: attr(`OAUTH#${state}`), verifier: attr(verifierValue), expires_at: { N: String(ttl(600)) } }, 'attribute_not_exists(pk)');
  const url = new URL(cognitoUrl('/oauth2/authorize'));
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', env.COGNITO_CLIENT_ID);
  url.searchParams.set('redirect_uri', `${env.PUBLIC_ORIGIN}/callback`);
  url.searchParams.set('scope', 'openid email profile');
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('code_challenge', sha256(verifierValue));
  redirect(res, url.toString(), safeCookie('waf_oauth_state', state, 600));
}
async function callback(req, res, url) {
  const state = url.searchParams.get('state') || '';
  const code = url.searchParams.get('code') || '';
  if (!/^[A-Za-z0-9_-]{20,100}$/.test(state) || state !== cookie(req, 'waf_oauth_state') || !code) return error(res, 400, 'Invalid login response');
  const item = (await getItem(`OAUTH#${state}`)).Item;
  if (!item || Number(item.expires_at?.N || 0) < ttl(0)) return error(res, 400, 'Login expired');
  await deleteItem(`OAUTH#${state}`);
  const body = new URLSearchParams({ grant_type: 'authorization_code', client_id: env.COGNITO_CLIENT_ID, code, redirect_uri: `${env.PUBLIC_ORIGIN}/callback`, code_verifier: item.verifier.S });
  const response = await fetch(cognitoUrl('/oauth2/token'), { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body, signal: AbortSignal.timeout(10000) });
  if (!response.ok) return error(res, 401, 'Login failed');
  const tokens = await response.json();
  if (!tokens.id_token) return error(res, 401, 'Login failed');
  await verifier.verify(tokens.id_token);
  redirect(res, '/', [safeCookie('waf_session', tokens.id_token, Math.min(3600, tokens.expires_in || 3600)), safeCookie('waf_oauth_state', '', 0)]);
}
function validLog(format, snapshot) {
  if (!logFormats.has(format) || snapshot.includes('\0')) return false;
  const lines = snapshot.replace(/^\uFEFF/, '').trim().split(/\r?\n/);
  if (lines.length > 20000) return false;
  let fields = [];
  let count = 0;
  for (const line of lines) {
    if (!line) continue;
    if (format === 'cloudfront' && line.startsWith('#')) {
      if (line.startsWith('#Fields:')) fields = line.slice(8).trim().split(/\s+/);
      continue;
    }
    let status;
    if (format === 'cloudfront') {
      const values = line.split('\t');
      if (!fields.length || values.length !== fields.length) return false;
      const row = Object.fromEntries(fields.map((name, i) => [name, values[i]]));
      if (!/^\d{4}-\d\d-\d\d$/.test(row.date || '') || !/^\d\d:\d\d:\d\d$/.test(row.time || '') || Number.isNaN(Date.parse(`${row.date}T${row.time}Z`)) || !isIP(row['c-ip'] || '') || !row['cs-uri-stem']?.startsWith('/')) return false;
      status = row['sc-status'];
    } else if (format === 'alb') {
      const parts = line.match(/(?:"[^"]*"|\S+)/g) || [];
      const client = /^(\[[^\]]+\]|[^: ]+):\d+$/.exec(parts[3] || '');
      if (parts.length < 14 || !/^(http|https|h2|grpcs|ws|wss)$/.test(parts[0]) || !/^\d{4}-\d\d-\d\dT/.test(parts[1]) || Number.isNaN(Date.parse(parts[1])) || !client || !isIP(client[1].replace(/^\[|\]$/g, '')) || !/^"[A-Z]+ \S+ HTTP\/[\d.]+"$/.test(parts[12])) return false;
      status = parts[8];
    } else {
      const match = line.match(/^([^ ]+) [^ ]+ [^ ]+ \[\d\d\/[A-Za-z]{3}\/\d{4}:\d\d:\d\d:\d\d [+-]\d{4}\] "[A-Z]+ [^" ]+ HTTP\/[\d.]+" ([1-5]\d\d) (?:\d+|-) "[^"]*" "[^"]*"(?: .*)?$/);
      if (!match || !isIP(match[1])) return false;
      status = match[2];
    }
    if (!/^[1-5]\d\d$/.test(status)) return false;
    count++;
  }
  return count > 0;
}
function validateInput(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Invalid request');
  if (!['aws_waf', 'modsecurity', 'traffic_log'].includes(body.kind)) throw new Error('Invalid rule kind');
  if (!['ja', 'en'].includes(body.language)) throw new Error('Invalid language');
  if (body.terms_accepted !== true) throw new Error('Terms of Service acceptance is required');
  if (typeof body.snapshot !== 'string' || !body.snapshot.trim() || Buffer.byteLength(body.snapshot, 'utf8') > maxSnapshotBytes) throw new Error('File must be 1 MiB or less');
  if (!Array.isArray(body.attack_categories) || (body.kind === 'traffic_log' ? body.attack_categories.length !== 0 : body.attack_categories.length < 1 || body.attack_categories.length > categories.size || new Set(body.attack_categories).size !== body.attack_categories.length || !body.attack_categories.every(c => categories.has(c)))) throw new Error('Invalid attack categories');
  if (typeof body.turnstile_token !== 'string' || body.turnstile_token.length < 1 || body.turnstile_token.length > 4096) throw new Error('Bot verification is required');
  if (body.kind === 'aws_waf') {
    let parsed;
    try { parsed = JSON.parse(body.snapshot); } catch { throw new Error('AWS WAF snapshot must be JSON'); }
    if (!parsed || typeof parsed !== 'object' || !parsed.WebACL) throw new Error('Expected a GetWebACL JSON response');
  }
  if (body.kind === 'traffic_log') {
    if (!validLog(body.log_format, body.snapshot)) throw new Error('ログフォーマットが違います');
  } else if (body.log_format !== undefined) throw new Error('Log format is only for traffic logs');
  return body;
}
function validateUploadRequest(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Invalid request');
  if (body.kind !== 'traffic_log' || !logFormats.has(body.log_format)) throw new Error('Invalid log format');
  if (!['ja', 'en'].includes(body.language)) throw new Error('Invalid language');
  if (!Number.isSafeInteger(body.size) || body.size < 1 || body.size > maxTrafficLogBytes) throw new Error('Log file must be 50 MiB or less');
  if (body.terms_accepted !== true) throw new Error('Terms of Service acceptance is required');
  if (typeof body.turnstile_token !== 'string' || body.turnstile_token.length < 1 || body.turnstile_token.length > 4096) throw new Error('Bot verification is required');
  return body;
}
async function readJSON(req) {
  const declared = Number(req.headers['content-length'] || 0);
  if (declared > maxBodyBytes) throw new Error('Request too large');
  const chunks = [];
  let size = 0;
  for await (const chunk of req) { size += chunk.length; if (size > maxBodyBytes) throw new Error('Request too large'); chunks.push(chunk); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new Error('Invalid JSON'); }
}
async function turnstileSecret() {
  if (cachedSecret && cachedUntil > Date.now()) return cachedSecret;
  const result = await secrets.send(new GetSecretValueCommand({ SecretId: env.TURNSTILE_SECRET_ARN }));
  cachedSecret = result.SecretString;
  cachedUntil = Date.now() + 300000;
  if (!cachedSecret) throw new Error('Turnstile secret is empty');
  return cachedSecret;
}
async function verifyTurnstile(token) {
  const body = new URLSearchParams({ secret: await turnstileSecret(), response: token });
  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body, signal: AbortSignal.timeout(10000) });
  if (!response.ok) return false;
  const data = await response.json();
  return data.success === true && data.hostname === new URL(env.PUBLIC_ORIGIN).hostname;
}
async function claimDailySubmission(day, userID, id) {
  const claim = `SUBMIT#${day}#${userID}`;
  try {
    await putItem({ pk: attr(claim), job_id: attr(id), expires_at: { N: String(ttl(3 * 86400)) } }, 'attribute_not_exists(pk)');
  } catch (e) {
    if (e.name === 'ConditionalCheckFailedException') return null;
    throw e;
  }
  return claim;
}
async function launchJob(id, key) {
  const result = await ecs.send(new RunTaskCommand({ Cluster: env.ECS_CLUSTER, TaskDefinition: env.WORKER_TASK_DEFINITION, LaunchType: 'FARGATE', Count: 1, StartedBy: id, ClientToken: id, NetworkConfiguration: { awsvpcConfiguration: { subnets: [env.WORKER_SUBNET], securityGroups: [env.WORKER_SECURITY_GROUP], assignPublicIp: 'ENABLED' } }, Overrides: { ContainerOverrides: [{ Name: 'worker', Environment: [{ Name: 'JOB_KEY', Value: key }] }] } }));
  if (result.failures?.length || result.tasks?.length !== 1) throw new Error('Worker did not start');
}
async function initiateLogUpload(req, res, user) {
  if (req.headers.origin !== env.PUBLIC_ORIGIN) return error(res, 403, 'Invalid origin');
  let input;
  try { input = validateUploadRequest(await readJSON(req)); } catch (e) { return error(res, 400, e.message); }
  if (!(await verifyTurnstile(input.turnstile_token))) return error(res, 403, 'Bot verification failed');
  const day = jstDay();
  const id = b64url(randomBytes(18));
  const claim = await claimDailySubmission(day, user.sub, id);
  if (!claim) return error(res, 429, 'Only one evaluation per user per JST day');
  const uploadCountKey = `UPLOAD_COUNT#${day}`;
  try {
    await ddb.send(new UpdateItemCommand({
      TableName: env.BUDGET_TABLE, Key: { pk: attr(uploadCountKey) },
      UpdateExpression: 'SET uploads = if_not_exists(uploads, :zero) + :one, expires_at = :expires',
      ConditionExpression: 'attribute_not_exists(uploads) OR uploads < :limit',
      ExpressionAttributeValues: { ':zero': { N: '0' }, ':one': { N: '1' }, ':limit': { N: String(maxDailyLogUploads) }, ':expires': { N: String(ttl(3 * 86400)) } },
    }));
  } catch (e) {
    await deleteItem(claim);
    if (e.name === 'ConditionalCheckFailedException') return error(res, 429, 'Daily log upload limit reached');
    throw e;
  }
  try {
    const key = `uploads/${id}.log`;
    const post = await createPresignedPost(s3, {
      Bucket: env.JOB_BUCKET, Key: key, Expires: 300,
      Conditions: [['content-length-range', 1, maxTrafficLogBytes + 16384]],
      Fields: { 'Content-Type': 'text/plain', success_action_status: '204' },
    });
    await putItem({
      pk: attr(`UPLOAD#${id}`), user_id: attr(user.sub), log_format: attr(input.log_format),
      language: attr(input.language), declared_bytes: { N: String(input.size) },
      status: attr('issued'), terms_version: attr(legalVersion),
      expires_at: { N: String(ttl(3600)) },
    }, 'attribute_not_exists(pk)');
    reply(res, 200, { upload_id: id, url: post.url, fields: post.fields });
  } catch (e) {
    await deleteItem(claim);
    throw e;
  }
}
async function submitUploadedLog(res, user, uploadID) {
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(uploadID)) return error(res, 400, 'Invalid upload ID');
  const upload = (await getItem(`UPLOAD#${uploadID}`)).Item;
  if (!upload || upload.user_id?.S !== user.sub || upload.status?.S !== 'issued' || Number(upload.expires_at?.N || 0) < ttl(0)) return error(res, 404, 'Upload not found');
  const sourceKey = `uploads/${uploadID}.log`;
  let object;
  try { object = await s3.send(new HeadObjectCommand({ Bucket: env.JOB_BUCKET, Key: sourceKey })); }
  catch (e) { if (e.name === 'NotFound' || e.name === 'NoSuchKey' || e.$metadata?.httpStatusCode === 404) return error(res, 400, 'Upload is incomplete'); throw e; }
  if (!object.ContentLength || object.ContentLength > maxTrafficLogBytes || object.ContentLength !== Number(upload.declared_bytes.N)) return error(res, 400, 'Log file size does not match');
  try {
    await ddb.send(new UpdateItemCommand({
      TableName: env.BUDGET_TABLE, Key: { pk: attr(`UPLOAD#${uploadID}`) },
      UpdateExpression: 'SET #status = :submitted',
      ConditionExpression: '#status = :issued AND user_id = :user',
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: { ':submitted': attr('submitted'), ':issued': attr('issued'), ':user': attr(user.sub) },
    }));
  } catch (e) {
    if (e.name === 'ConditionalCheckFailedException') return error(res, 409, 'Upload already submitted');
    throw e;
  }
  const key = `jobs/${uploadID}.json`;
  const dataKey = `jobs/data/${uploadID}.log`;
  const job = { id: uploadID, user_id: user.sub, kind: 'traffic_log', log_format: upload.log_format.S, language: upload.language.S, snapshot: '', attack_categories: [], log_object_key: dataKey };
  await s3.send(new CopyObjectCommand({ Bucket: env.JOB_BUCKET, Key: dataKey, CopySource: `${env.JOB_BUCKET}/${sourceKey}`, CopySourceIfMatch: object.ETag, ServerSideEncryption: 'AES256' }));
  await s3.send(new PutObjectCommand({ Bucket: env.JOB_BUCKET, Key: key, Body: JSON.stringify(job), ContentType: 'application/json', ServerSideEncryption: 'AES256' }));
  await putItem({ pk: attr(`EVAL#${uploadID}`), user_id: attr(user.sub), created_at: { N: String(ttl(0)) }, terms_version: upload.terms_version, expires_at: { N: String(ttl(3 * 86400)) } }, 'attribute_not_exists(pk)');
  await launchJob(uploadID, key);
  reply(res, 202, { job_id: uploadID, status_url: `/api/evaluations/${uploadID}` });
}
async function submit(req, res, user) {
  if (req.headers.origin !== env.PUBLIC_ORIGIN) return error(res, 403, 'Invalid origin');
  let body;
  try { body = await readJSON(req); } catch (e) { return error(res, 400, e.message); }
  if (body && typeof body.upload_id === 'string') return submitUploadedLog(res, user, body.upload_id);
  let input;
  try { input = validateInput(body); } catch (e) { return error(res, 400, e.message); }
  if (!(await verifyTurnstile(input.turnstile_token))) return error(res, 403, 'Bot verification failed');
  const day = jstDay();
  const id = b64url(randomBytes(18));
  const claim = await claimDailySubmission(day, user.sub, id);
  if (!claim) return error(res, 429, 'Only one evaluation per user per JST day');
  const key = `jobs/${id}.json`;
  const job = { id, user_id: user.sub, kind: input.kind, language: input.language, snapshot: input.snapshot, attack_categories: input.attack_categories };
  if (input.kind === 'traffic_log') job.log_format = input.log_format;
  if (input.kind === 'modsecurity') job.probe_result_key = `probe-results/${id}.json`;
  try {
    await s3.send(new PutObjectCommand({ Bucket: env.JOB_BUCKET, Key: key, Body: JSON.stringify(job), ContentType: 'application/json', ServerSideEncryption: 'AES256' }));
    await putItem({ pk: attr(`EVAL#${id}`), user_id: attr(user.sub), created_at: { N: String(ttl(0)) }, terms_version: attr(legalVersion), expires_at: { N: String(ttl(3 * 86400)) } }, 'attribute_not_exists(pk)');
    await launchJob(id, key);
  } catch (e) {
    await Promise.allSettled([deleteItem(claim), deleteItem(`EVAL#${id}`)]);
    throw e;
  }
  reply(res, 202, { job_id: id, status_url: `/api/evaluations/${id}` });
}
async function status(res, user, id) {
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(id)) return error(res, 400, 'Invalid job ID');
  const record = (await getItem(`EVAL#${id}`)).Item;
  if (!record || record.user_id?.S !== user.sub) return error(res, 404, 'Not found');
  const job = (await getItem(`JOB#${id}`)).Item;
  if (job?.status?.S === 'failed' && job.error_code?.S === 'LOG_FORMAT') return reply(res, 200, { status: 'failed', code: 'LOG_FORMAT', message: 'ログフォーマットが違います' });
  if (job?.status?.S === 'complete' && job.result_key?.S === `results/${id}.json`) {
    const object = await s3.send(new GetObjectCommand({ Bucket: env.RESULT_BUCKET, Key: job.result_key.S }));
    const report = JSON.parse(await object.Body.transformToString());
    return reply(res, 200, { status: 'complete', report });
  }
  if (Number(record.created_at.N) + 15 * 60 < ttl(0)) return reply(res, 200, { status: 'failed', message: 'Evaluation did not complete within 15 minutes' });
  reply(res, 200, { status: 'pending' });
}
async function handler(req, res) {
  try {
    const url = new URL(req.url, env.PUBLIC_ORIGIN || 'http://localhost:3000');
    if (req.method === 'GET' && url.pathname === '/health') return reply(res, 200, { status: 'ok' });
    if (req.method === 'GET' && url.pathname === '/login') return login(req, res);
    if (req.method === 'GET' && url.pathname === '/callback') return callback(req, res, url);
    if (req.method === 'GET' && url.pathname === '/logout') return redirect(res, '/', safeCookie('waf_session', '', 0));
    if (req.method === 'GET' && url.pathname === '/config.js') return reply(res, 200, `window.WAF_CONFIG = ${JSON.stringify({ turnstileSiteKey: env.TURNSTILE_SITE_KEY || '' })};`, { 'content-type': 'application/javascript; charset=utf-8' });
    if (req.method === 'GET' && url.pathname === '/favicon.svg') return reply(res, 200, favicon, { 'content-type': 'image/svg+xml; charset=utf-8', 'cache-control': 'public, max-age=86400' });
    if (req.method === 'GET' && pages[url.pathname]) return reply(res, 200, pages[url.pathname], { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': `default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; connect-src 'self' https://challenges.cloudflare.com https://${env.JOB_BUCKET}.s3.${region}.amazonaws.com; base-uri 'none'; object-src 'none'` });
    if (url.pathname.startsWith('/api/')) {
      const user = await authenticatedUser(req);
      if (url.pathname === '/api/me' && req.method === 'GET') return reply(res, 200, { authenticated: !!user, user: user?.email || null });
      if (!user) return error(res, 401, 'Login required');
      if (url.pathname === '/api/uploads' && req.method === 'POST') return initiateLogUpload(req, res, user);
      if (url.pathname === '/api/evaluations' && req.method === 'POST') return submit(req, res, user);
      const match = /^\/api\/evaluations\/([A-Za-z0-9_-]+)$/.exec(url.pathname);
      if (match && req.method === 'GET') return status(res, user, match[1]);
    }
    error(res, 404, 'Not found');
  } catch (e) {
    console.error('Request failed', { name: e?.name, message: e?.message });
    error(res, 500, 'Internal error');
  }
}
const [host, port] = (env.AWS_LAMBDA_HTTP_ENDPOINT || 'localhost:3000').split(':');
if (env.NODE_ENV !== 'test') createServer(handler).listen(Number(port), host);
export { validateInput, validateUploadRequest, jstDay, handler };
