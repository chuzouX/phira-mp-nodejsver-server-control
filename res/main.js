"use strict";
/* eslint-disable-next-line @typescript-eslint/triple-slash-reference */
/// <reference path="../../../plugin-api.d.ts" />
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = __importDefault(require("crypto"));
const fs_1 = __importDefault(require("fs"));
const os_1 = __importDefault(require("os"));
const path_1 = __importDefault(require("path"));
const readline_1 = __importDefault(require("readline"));
const express_1 = __importDefault(require("express"));
const js_yaml_1 = __importDefault(require("js-yaml"));
const perf_hooks_1 = require("perf_hooks");
const SECRET_PATTERN = /(password|passwd|token|secret|private[_-]?key|api[_-]?key|geetest[_-]?key)/i;
const MASK = '__SERVER_CONTROL_MASKED__';
const TEXT_EXTENSIONS = new Set([
    '.json',
    '.yaml',
    '.yml',
    '.env',
    '.txt',
    '.log',
    '.md',
    '.csv',
    '',
]);
class ServerControlPlugin {
    constructor(api, config) {
        this.api = api;
        this.config = config;
        this.sessions = new Map();
        this.attempts = new Map();
        this.loginQueues = new Map();
        this.logStreams = new Set();
        this.historicalAnalysisCache = new Map();
        this.historicalAnalysisJobs = new Map();
        this.history = [];
        this.eventLoop = (0, perf_hooks_1.monitorEventLoopDelay)({ resolution: 20 });
        this.auditPath = path_1.default.join(process.cwd(), 'logs', 'server-control-audit.log');
        this.gcSinceSample = { count: 0, durationMs: 0 };
        this.previousCpu = process.cpuUsage();
        this.previousSampleAt = process.hrtime.bigint();
        this.previousSystemCpu = this.systemCpuTimes();
        const knownWeak = new Set([
            'a-very-insecure-secret-change-it',
            'change-this-to-a-random-secret',
            'plugin-managed-session-secret',
        ]);
        const rawSecret = process.env.SESSION_SECRET || this.config.sessionSecret;
        if (!rawSecret || rawSecret.length < 16 || knownWeak.has(rawSecret)) {
            this.config = {
                ...this.config,
                sessionSecret: crypto_1.default.randomBytes(32).toString('hex'),
            };
        }
    }
    start() {
        const app = this.api.getExpressApp();
        if (!app)
            throw new Error('server-control requires ENABLE_WEB_SERVER=true');
        this.eventLoop.enable();
        this.gcObserver = new perf_hooks_1.PerformanceObserver((list) => {
            for (const entry of list.getEntries()) {
                this.gcSinceSample.count += 1;
                this.gcSinceSample.durationMs += entry.duration;
            }
        });
        this.gcObserver.observe({ entryTypes: ['gc'] });
        const sampleInterval = Math.max(1000, this.config.sampleIntervalMs ?? 2000);
        this.collectSample();
        this.sampleTimer = setInterval(() => this.collectSample(), sampleInterval);
        this.cleanupTimer = setInterval(() => this.cleanupSessions(), 60000);
        const publicDir = path_1.default.join(__dirname, 'public');
        app.use('/control/assets', express_1.default.static(path_1.default.join(publicDir, 'assets'), { fallthrough: false }));
        app.get('/control', (_req, res) => res.sendFile(path_1.default.join(publicDir, 'index.html')));
        app.get('/control/favicon.ico', (_req, res) => res.status(204).end());
        app.post('/control/api/auth/login', this.login.bind(this));
        app.get('/control/api/auth/session', this.requireAuth.bind(this), (req, res) => {
            const session = this.getSession(req);
            res.json({ authenticated: true, csrf: session.csrf, expiresAt: session.expiresAt });
        });
        app.post('/control/api/auth/logout', this.requireAuth.bind(this), this.requireCsrf.bind(this), (req, res) => {
            const token = req.cookies?.server_control_session;
            if (token)
                this.sessions.delete(token);
            res.clearCookie('server_control_session', { path: '/control' });
            this.audit(req, 'logout');
            res.json({ success: true });
        });
        app.get('/control/api/metrics', this.requireAuth.bind(this), (_req, res) => {
            res.json({ current: this.history[this.history.length - 1], history: this.history });
        });
        app.get('/control/api/users', this.requireAuth.bind(this), (_req, res) => res.json(this.api.getOnlinePlayers()));
        app.get('/control/api/plugins', this.requireAuth.bind(this), (_req, res) => res.json(this.api.listPlugins()));
        app.get('/control/api/logs/stream', this.requireAuth.bind(this), this.streamLogs.bind(this));
        app.get('/control/api/log-history/files', this.requireAuth.bind(this), (_req, res) => res.json(this.listHistoricalLogs()));
        app.get('/control/api/log-history/analyze', this.requireAuth.bind(this), this.analyzeHistoricalLog.bind(this));
        app.get('/control/api/log-history/lines', this.requireAuth.bind(this), this.readHistoricalLogChunk.bind(this));
        app.post('/control/api/command', this.requireAuth.bind(this), this.requireCsrf.bind(this), this.executeCommand.bind(this));
        app.get('/control/api/files', this.requireAuth.bind(this), (_req, res) => res.json(this.listFiles()));
        app.get('/control/api/file', this.requireAuth.bind(this), (req, res) => this.readFile(req, res, false));
        app.post('/control/api/file/reveal', this.requireAuth.bind(this), this.requireCsrf.bind(this), (req, res) => this.readFile(req, res, true));
        app.put('/control/api/file', this.requireAuth.bind(this), this.requireCsrf.bind(this), this.saveFile.bind(this));
        app.post('/control/api/reload/plugin', this.requireAuth.bind(this), this.requireCsrf.bind(this), this.reloadPlugin.bind(this));
        app.post('/control/api/reload/config', this.requireAuth.bind(this), this.requireCsrf.bind(this), (req, res) => {
            const success = this.api.reloadServerConfig();
            this.audit(req, 'reload-server-config', { success });
            res.status(success ? 200 : 501).json({ success });
        });
        this.registerConsoleCommands();
        const DEFAULT_EXAMPLE_HASH = 'scrypt$16384$8$1$3cd90212691f19a12703d4f0a8268825$f0f1a91d4edb8360a18a716686311fc99a74c2d50f691fa7e8e5dcc62a58ac7c';
        const currentHash = this.passwordHash();
        if (!currentHash || currentHash === DEFAULT_EXAMPLE_HASH) {
            this.api.logger.error('[ServerControl] 错误: passwordHash 为空或等于默认示例哈希，/control 登录已被禁用。请运行 npm run server-control:hash 生成新密码。');
        }
        this.api.logger.info('[ServerControl] control panel mounted at /control');
    }
    stop() {
        if (this.sampleTimer)
            clearInterval(this.sampleTimer);
        if (this.cleanupTimer)
            clearInterval(this.cleanupTimer);
        this.gcObserver?.disconnect();
        this.eventLoop.disable();
        this.sessions.clear();
        this.historicalAnalysisCache.clear();
        for (const stream of this.logStreams) {
            clearInterval(stream.pollTimer);
            clearInterval(stream.keepAlive);
            stream.response.end();
        }
        this.logStreams.clear();
    }
    async login(req, res) {
        const ip = req.ip || req.socket.remoteAddress || 'unknown';
        const previous = this.loginQueues.get(ip) ?? Promise.resolve();
        let release;
        const current = new Promise((resolve) => {
            release = resolve;
        });
        const queued = previous.then(() => current);
        this.loginQueues.set(ip, queued);
        await previous;
        try {
            await this.loginAttempt(req, res, ip);
        }
        finally {
            release();
            if (this.loginQueues.get(ip) === queued)
                this.loginQueues.delete(ip);
        }
    }
    async loginAttempt(req, res, ip) {
        const attempt = this.attempts.get(ip) ?? this.newAttemptRecord();
        if (attempt.lockedUntil > Date.now()) {
            this.audit(req, 'login-blocked', { ip, retryAt: attempt.lockedUntil });
            res.status(429).json({ error: 'Login temporarily locked', retryAt: attempt.lockedUntil });
            return;
        }
        if (attempt.lockedUntil) {
            attempt.lockedUntil = 0;
            attempt.count = 0;
        }
        const DEFAULT_EXAMPLE_HASH = 'scrypt$16384$8$1$3cd90212691f19a12703d4f0a8268825$f0f1a91d4edb8360a18a716686311fc99a74c2d50f691fa7e8e5dcc62a58ac7c';
        const currentHash = this.passwordHash();
        if (!currentHash || currentHash === DEFAULT_EXAMPLE_HASH) {
            res.status(503).json({
                error: 'Control password is not configured or using default example hash',
            });
            return;
        }
        const valid = await this.verifyPassword(String(req.body?.password ?? ''), this.passwordHash());
        if (!valid) {
            attempt.count += 1;
            attempt.lastAttemptAt = Date.now();
            if (attempt.count >= (this.config.loginMaxAttempts ?? 5)) {
                attempt.lockedUntil = Date.now() + (this.config.loginLockMinutes ?? 15) * 60000;
                attempt.count = 0;
            }
            this.storeAttemptRecord(ip, attempt);
            this.audit(req, 'login-failed', {
                ip,
                attempts: attempt.count,
                lockedUntil: attempt.lockedUntil || undefined,
            });
            res.status(401).json({ error: 'Invalid credentials' });
            return;
        }
        this.attempts.delete(ip);
        const token = crypto_1.default.randomBytes(32).toString('base64url');
        const record = {
            expiresAt: Date.now() + (this.config.sessionTtlMinutes ?? 480) * 60000,
            csrf: crypto_1.default.randomBytes(24).toString('base64url'),
        };
        this.sessions.set(token, record);
        res.cookie('server_control_session', token, {
            httpOnly: true,
            sameSite: 'strict',
            secure: process.env.NODE_ENV === 'production',
            maxAge: (this.config.sessionTtlMinutes ?? 480) * 60000,
            path: '/control',
        });
        this.audit(req, 'login-success');
        res.json({ success: true, csrf: record.csrf, expiresAt: record.expiresAt });
    }
    streamLogs(_req, res) {
        const limit = Math.min(32, Math.max(1, this.config.maxLogStreams ?? 8));
        if (this.logStreams.size >= limit) {
            res.status(429).json({ error: 'Too many live log streams' });
            return;
        }
        res.status(200).set({
            'Cache-Control': 'no-cache, no-transform',
            Connection: 'keep-alive',
            'Content-Type': 'text/event-stream; charset=utf-8',
            'X-Accel-Buffering': 'no',
        });
        res.flushHeaders();
        const initial = this.readLogTail();
        const state = initial.state;
        this.writeLogEvents(res, initial.lines);
        res.write(': connected\n\n');
        const pollTimer = setInterval(() => {
            try {
                const next = this.readLogDelta(state);
                this.writeLogEvents(res, next);
            }
            catch {
                // The log can rotate while a stream is open. The next poll will recover.
            }
        }, 750);
        const keepAlive = setInterval(() => res.write(': ping\n\n'), 15000);
        const stream = { response: res, pollTimer, keepAlive };
        this.logStreams.add(stream);
        res.on('close', () => {
            clearInterval(pollTimer);
            clearInterval(keepAlive);
            this.logStreams.delete(stream);
        });
    }
    executeCommand(req, res) {
        const input = String(req.body?.input ?? '').trim();
        if (!input.startsWith('/') || input.length > 512) {
            res.status(400).json({ error: 'Commands must start with / and be at most 512 characters' });
            return;
        }
        if (!this.api.executeConsoleCommand) {
            res.status(501).json({ error: 'Console command execution is unavailable' });
            return;
        }
        this.audit(req, 'console-command', { command: input });
        void this.api
            .executeConsoleCommand(input)
            .then(() => res.status(202).json({ accepted: true }))
            .catch((error) => res.status(400).json({ error: error instanceof Error ? error.message : String(error) }));
    }
    listHistoricalLogs() {
        const directory = path_1.default.join(process.cwd(), 'logs');
        if (!fs_1.default.existsSync(directory))
            return [];
        return fs_1.default
            .readdirSync(directory, { withFileTypes: true })
            .filter((entry) => entry.isFile())
            .map((entry) => {
            const kind = this.historicalLogKind(entry.name);
            if (!kind)
                return undefined;
            const stat = fs_1.default.statSync(path_1.default.join(directory, entry.name));
            return { name: entry.name, kind, size: stat.size, modifiedAt: stat.mtimeMs };
        })
            .filter((entry) => Boolean(entry))
            .sort((a, b) => b.modifiedAt - a.modifiedAt);
    }
    historicalLogKind(name) {
        if (/^server-\d{4}-\d{2}-\d{2}\.log$/.test(name))
            return 'game';
        if (name === 'command.log')
            return 'commands';
        if (name === 'server-control-audit.log')
            return 'control';
        if (name === 'ban.log')
            return 'bans';
        return undefined;
    }
    async analyzeHistoricalLog(req, res) {
        const name = String(req.query.name ?? '');
        const file = this.listHistoricalLogs().find((entry) => entry.name === name);
        if (!file) {
            res.status(404).json({ error: 'Historical log not found' });
            return;
        }
        const cached = this.historicalAnalysisCache.get(file.name);
        if (cached?.size === file.size && cached.modifiedAt === file.modifiedAt) {
            res.json(cached.result);
            return;
        }
        const jobKey = `${file.name}:${file.size}:${file.modifiedAt}`;
        let job = this.historicalAnalysisJobs.get(jobKey);
        if (!job) {
            const limit = Math.min(4, Math.max(1, this.config.maxConcurrentLogAnalyses ?? 2));
            if (this.historicalAnalysisJobs.size >= limit) {
                res.status(429).json({ error: 'Too many historical log analyses in progress' });
                return;
            }
            job = this.buildHistoricalAnalysis(file);
            this.historicalAnalysisJobs.set(jobKey, job);
        }
        try {
            const result = await job;
            this.cacheHistoricalAnalysis(file, result);
            res.json(result);
        }
        catch (error) {
            res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
        }
        finally {
            if (this.historicalAnalysisJobs.get(jobKey) === job)
                this.historicalAnalysisJobs.delete(jobKey);
        }
    }
    async buildHistoricalAnalysis(file) {
        const absolute = path_1.default.join(process.cwd(), 'logs', file.name);
        const stat = await fs_1.default.promises.stat(absolute);
        const maxBytes = 32 * 1024 * 1024;
        const start = Math.max(0, stat.size - maxBytes);
        const lines = await this.readHistoricalLines(absolute, start);
        const result = file.kind === 'control'
            ? await this.analyzeControlLog(file.name, lines)
            : file.kind === 'bans'
                ? await this.analyzeBanLog(file.name, lines)
                : await this.analyzeTextLog(file.name, file.kind, lines);
        return {
            ...result,
            file: { ...file, size: stat.size, modifiedAt: stat.mtimeMs },
            truncated: stat.size > maxBytes,
        };
    }
    async readHistoricalLines(absolute, start) {
        let skipPartialFirstLine = false;
        if (start > 0) {
            const handle = await fs_1.default.promises.open(absolute, 'r');
            try {
                const previous = Buffer.alloc(1);
                await handle.read(previous, 0, 1, start - 1);
                skipPartialFirstLine = previous[0] !== 0x0a;
            }
            finally {
                await handle.close();
            }
        }
        const lines = [];
        const input = fs_1.default.createReadStream(absolute, { encoding: 'utf8', start });
        const reader = readline_1.default.createInterface({ input, crlfDelay: Infinity });
        let count = 0;
        for await (const line of reader) {
            if (skipPartialFirstLine) {
                skipPartialFirstLine = false;
                continue;
            }
            if (line)
                lines.push(line);
            count += 1;
            if (count % 2000 === 0)
                await this.yieldToEventLoop();
        }
        return lines;
    }
    cacheHistoricalAnalysis(file, result) {
        if (!this.historicalAnalysisCache.has(file.name) && this.historicalAnalysisCache.size >= 8) {
            const oldest = this.historicalAnalysisCache.keys().next().value;
            if (oldest)
                this.historicalAnalysisCache.delete(oldest);
        }
        this.historicalAnalysisCache.set(file.name, {
            size: file.size,
            modifiedAt: file.modifiedAt,
            result,
        });
    }
    yieldToEventLoop() {
        return new Promise((resolve) => setImmediate(resolve));
    }
    readHistoricalLogChunk(req, res) {
        const name = String(req.query.name ?? '');
        const file = this.listHistoricalLogs().find((entry) => entry.name === name);
        if (!file) {
            res.status(404).json({ error: 'Historical log not found' });
            return;
        }
        const requestedOffset = Number(req.query.offset ?? 0);
        if (!Number.isSafeInteger(requestedOffset) || requestedOffset < 0) {
            res.status(400).json({ error: 'Invalid log offset' });
            return;
        }
        try {
            const absolute = path_1.default.join(process.cwd(), 'logs', file.name);
            const stat = fs_1.default.statSync(absolute);
            const offset = Math.min(requestedOffset, stat.size);
            const maxLength = Math.min(256 * 1024, stat.size - offset);
            if (maxLength <= 0) {
                res.json({ lines: [], offset, nextOffset: offset, hasMore: false, totalBytes: stat.size });
                return;
            }
            const buffer = Buffer.alloc(maxLength);
            const fd = fs_1.default.openSync(absolute, 'r');
            let bytesRead = 0;
            try {
                bytesRead = fs_1.default.readSync(fd, buffer, 0, maxLength, offset);
            }
            finally {
                fs_1.default.closeSync(fd);
            }
            let consumed = bytesRead;
            if (offset + bytesRead < stat.size) {
                const lastNewline = buffer.lastIndexOf(0x0a, bytesRead - 1);
                if (lastNewline >= 0)
                    consumed = lastNewline + 1;
            }
            const text = buffer.subarray(0, consumed).toString('utf8');
            const lines = text.split(/\r?\n/);
            if (lines[lines.length - 1] === '')
                lines.pop();
            const nextOffset = offset + consumed;
            res.json({
                lines,
                offset,
                nextOffset,
                hasMore: nextOffset < stat.size,
                totalBytes: stat.size,
            });
        }
        catch (error) {
            res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
        }
    }
    async analyzeTextLog(name, kind, lines) {
        const levels = {};
        const timeline = {};
        const commands = {};
        const notable = [];
        for (let index = 0; index < lines.length; index += 1) {
            const line = lines[index];
            const level = line.match(/\[(DEBUG|INFO|MARK|WARN|ERROR|BAN|CMD|PLUGIN)\]/)?.[1];
            if (level)
                levels[level] = (levels[level] ?? 0) + 1;
            const timestamp = line.match(/^\[(\d{4}-\d{2}-\d{2} \d{2})/i)?.[1];
            if (timestamp)
                timeline[timestamp] = (timeline[timestamp] ?? 0) + 1;
            if (level === 'WARN' || level === 'ERROR')
                notable.push(line);
            if (kind === 'commands') {
                const command = line.match(/(?:执行指令|Executing command):\s*(\/\S+)/i)?.[1];
                if (command)
                    commands[command] = (commands[command] ?? 0) + 1;
            }
            if (index > 0 && index % 2000 === 0)
                await this.yieldToEventLoop();
        }
        return {
            kind,
            fileName: name,
            totalLines: lines.length,
            levels,
            timeline: Object.entries(timeline).map(([label, count]) => ({ label, count })),
            commands: kind === 'commands' ? commands : undefined,
            notable: notable.slice(-80).reverse(),
            recent: lines.slice(-100).reverse(),
        };
    }
    async analyzeControlLog(name, lines) {
        const actions = {};
        const timeline = {};
        const records = [];
        for (let index = 0; index < lines.length; index += 1) {
            const line = lines[index];
            try {
                const record = JSON.parse(line);
                if (record.action)
                    actions[record.action] = (actions[record.action] ?? 0) + 1;
                if (record.timestamp) {
                    const hour = record.timestamp.slice(0, 13).replace('T', ' ');
                    timeline[hour] = (timeline[hour] ?? 0) + 1;
                }
                records.push(record);
            }
            catch {
                // Ignore an incomplete line written during a process interruption.
            }
            if (index > 0 && index % 2000 === 0)
                await this.yieldToEventLoop();
        }
        return {
            kind: 'control',
            fileName: name,
            totalLines: records.length,
            actions,
            timeline: Object.entries(timeline).map(([label, count]) => ({ label, count })),
            login: {
                success: actions['login-success'] ?? 0,
                failed: actions['login-failed'] ?? 0,
                logout: actions.logout ?? 0,
            },
            records: records.slice(-100).reverse(),
        };
    }
    async analyzeBanLog(name, lines) {
        const timeline = {};
        const targets = {};
        let created = 0;
        let removed = 0;
        let blocked = 0;
        for (let index = 0; index < lines.length; index += 1) {
            const line = lines[index];
            const timestamp = line.match(/^\[(\d{4}-\d{2}-\d{2} \d{2})/)?.[1];
            if (timestamp)
                timeline[timestamp] = (timeline[timestamp] ?? 0) + 1;
            if (/解封/.test(line))
                removed += 1;
            else if (/拦截到.*登录尝试/.test(line))
                blocked += 1;
            else if (/封禁/.test(line))
                created += 1;
            const target = line.match(/用户 ID\s+(\d+)/)?.[1] ??
                line.match(/封禁用户\s*(\d+)/)?.[1] ??
                line.match(/IP\s+([^\s(]+)/)?.[1];
            if (target)
                targets[target] = (targets[target] ?? 0) + 1;
            if (index > 0 && index % 2000 === 0)
                await this.yieldToEventLoop();
        }
        return {
            kind: 'bans',
            fileName: name,
            totalLines: lines.length,
            bans: { created, removed, blocked, uniqueTargets: Object.keys(targets).length },
            targets,
            timeline: Object.entries(timeline).map(([label, count]) => ({ label, count })),
            recent: lines.slice(-100).reverse(),
        };
    }
    currentLogPath() {
        return path_1.default.join(process.cwd(), 'logs', `server-${new Date().toISOString().split('T')[0]}.log`);
    }
    readLogTail() {
        const filePath = this.currentLogPath();
        if (!fs_1.default.existsSync(filePath))
            return { lines: [], state: { filePath, offset: 0 } };
        const stat = fs_1.default.statSync(filePath);
        const content = fs_1.default.readFileSync(filePath, 'utf8').slice(-512 * 1024);
        return {
            lines: content.split(/\r?\n/).filter(Boolean).slice(-300),
            state: { filePath, offset: stat.size },
        };
    }
    readLogDelta(state) {
        const filePath = this.currentLogPath();
        if (!fs_1.default.existsSync(filePath))
            return [];
        const stat = fs_1.default.statSync(filePath);
        if (filePath !== state.filePath || stat.size < state.offset) {
            state.filePath = filePath;
            state.offset = 0;
        }
        if (stat.size === state.offset)
            return [];
        const length = stat.size - state.offset;
        const buffer = Buffer.alloc(length);
        const fd = fs_1.default.openSync(filePath, 'r');
        try {
            fs_1.default.readSync(fd, buffer, 0, length, state.offset);
        }
        finally {
            fs_1.default.closeSync(fd);
        }
        state.offset = stat.size;
        return buffer.toString('utf8').split(/\r?\n/).filter(Boolean);
    }
    writeLogEvents(res, lines) {
        for (const line of lines)
            res.write(`data: ${JSON.stringify({ line })}\n\n`);
    }
    requireAuth(req, res, next) {
        const session = this.getSession(req);
        if (!session) {
            res.status(401).json({ error: 'Unauthorized' });
            return;
        }
        next();
    }
    requireCsrf(req, res, next) {
        const session = this.getSession(req);
        if (!session || req.header('x-csrf-token') !== session.csrf) {
            res.status(403).json({ error: 'Invalid CSRF token' });
            return;
        }
        next();
    }
    getSession(req) {
        const token = req.cookies?.server_control_session;
        const session = token ? this.sessions.get(token) : undefined;
        if (!session || session.expiresAt <= Date.now()) {
            if (token)
                this.sessions.delete(token);
            return undefined;
        }
        return session;
    }
    verifyPassword(password, encoded) {
        const [algorithm, n, r, p, saltHex, keyHex] = encoded.split('$');
        const cost = Number(n);
        const blockSize = Number(r);
        const parallelization = Number(p);
        if (algorithm !== 'scrypt' ||
            !/^[a-f0-9]{32,}$/i.test(saltHex ?? '') ||
            !/^[a-f0-9]{64}$/i.test(keyHex ?? '') ||
            !Number.isInteger(cost) ||
            cost < 2 ||
            cost > 1048576 ||
            (cost & (cost - 1)) !== 0 ||
            !Number.isInteger(blockSize) ||
            blockSize < 1 ||
            blockSize > 32 ||
            !Number.isInteger(parallelization) ||
            parallelization < 1 ||
            parallelization > 16)
            return Promise.resolve(false);
        const expected = Buffer.from(keyHex, 'hex');
        return new Promise((resolve) => {
            try {
                crypto_1.default.scrypt(password, Buffer.from(saltHex, 'hex'), expected.length, { N: cost, r: blockSize, p: parallelization }, (error, key) => {
                    resolve(!error && key.length === expected.length && crypto_1.default.timingSafeEqual(key, expected));
                });
            }
            catch {
                resolve(false);
            }
        });
    }
    passwordHash() {
        return process.env.SERVER_CONTROL_PASSWORD_HASH || this.config.passwordHash || '';
    }
    registerConsoleCommands() {
        if (!this.api.registerCommand)
            return;
        this.api.registerCommand('server-control', (...args) => this.handleConsoleCommand(args), { redactInput: true });
    }
    handleConsoleCommand(args) {
        const subcommand = String(args[0] ?? 'help').toLowerCase();
        switch (subcommand) {
            case 'help':
                this.api.logger.info('[ServerControl] commands: /server-control status | /server-control reload | /server-control hash "<password>"');
                this.api.logger.info('[ServerControl] password changes are manual only: edit config/server-control/config.yaml and restart');
                return;
            case 'status':
                this.api.logger.info(`[ServerControl] login password: ${this.passwordHash() ? 'configured' : 'not configured'}; route: /control`);
                return;
            case 'reload': {
                const newConfig = this.api.readPluginConfig();
                if (!newConfig) {
                    this.api.logger.warn('[ServerControl] reload failed: unable to read config/server-control/config.yaml');
                    return;
                }
                this.config = newConfig;
                if (this.sampleTimer) {
                    clearInterval(this.sampleTimer);
                    const interval = Math.max(1000, this.config.sampleIntervalMs ?? 2000);
                    this.sampleTimer = setInterval(() => this.collectSample(), interval);
                }
                this.api.logger.info('[ServerControl] configuration reloaded');
                return;
            }
            case 'hash': {
                const password = args.slice(1).join(' ');
                if (password.length < 10) {
                    this.api.logger.warn('[ServerControl] usage: /server-control hash "<password at least 10 characters>"');
                    return;
                }
                const salt = crypto_1.default.randomBytes(16);
                const key = crypto_1.default.scryptSync(password, salt, 32, { N: 16384, r: 8, p: 1 });
                const hash = `scrypt$16384$8$1$${salt.toString('hex')}$${key.toString('hex')}`;
                this.api.logger.info(`[ServerControl] generated passwordHash: ${hash}`);
                this.api.logger.info('[ServerControl] copy it to config/server-control/config.yaml manually; no configuration was changed');
                return;
            }
            case 'password':
            case 'set-password':
                this.api.logger.warn('[ServerControl] password changes are disabled from the console; edit config/server-control/config.yaml manually and restart');
                return;
            default:
                this.api.logger.warn(`[ServerControl] unknown command: ${subcommand}; use /server-control help`);
        }
    }
    collectSample() {
        const now = Date.now();
        const currentCpu = process.cpuUsage();
        const nowHr = process.hrtime.bigint();
        const elapsedMicros = Number(nowHr - this.previousSampleAt) / 1000;
        const usedMicros = currentCpu.user + currentCpu.system - this.previousCpu.user - this.previousCpu.system;
        const systemCpu = this.systemCpuPercent();
        const memory = process.memoryUsage();
        const systemTotal = os_1.default.totalmem();
        const systemUsed = systemTotal - os_1.default.freemem();
        const eventLoopMs = Number(this.eventLoop.mean / 1e6) || 0;
        const resource = process.resourceUsage();
        let disk;
        try {
            const stat = fs_1.default.statfsSync(process.cwd());
            disk = { total: stat.blocks * stat.bsize, free: stat.bfree * stat.bsize };
        }
        catch { }
        const sample = {
            timestamp: now,
            uptime: process.uptime(),
            onlinePlayers: this.api.getOnlinePlayers().length,
            roomCount: this.api.getRooms().length,
            cpu: {
                process: elapsedMicros > 0 ? (usedMicros / elapsedMicros) * 100 : 0,
                system: systemCpu,
            },
            memory: {
                rss: memory.rss,
                heapUsed: memory.heapUsed,
                heapTotal: memory.heapTotal,
                external: memory.external,
                systemUsed,
                systemTotal,
            },
            eventLoopMs,
            gc: { ...this.gcSinceSample },
            resource: {
                userCpuSeconds: resource.userCPUTime / 1e6,
                systemCpuSeconds: resource.systemCPUTime / 1e6,
                fsRead: resource.fsRead,
                fsWrite: resource.fsWrite,
            },
            disk,
        };
        this.gcSinceSample = { count: 0, durationMs: 0 };
        this.eventLoop.reset();
        this.previousCpu = currentCpu;
        this.previousSampleAt = nowHr;
        this.history.push(sample);
        const max = Math.max(10, Math.ceil(((this.config.historyMinutes ?? 5) * 60000) /
            Math.max(1000, this.config.sampleIntervalMs ?? 2000)));
        if (this.history.length > max)
            this.history.splice(0, this.history.length - max);
    }
    systemCpuTimes() {
        return os_1.default.cpus().reduce((sum, cpu) => {
            const total = Object.values(cpu.times).reduce((value, time) => value + time, 0);
            return { idle: sum.idle + cpu.times.idle, total: sum.total + total };
        }, { idle: 0, total: 0 });
    }
    systemCpuPercent() {
        const current = this.systemCpuTimes();
        const idle = current.idle - this.previousSystemCpu.idle;
        const total = current.total - this.previousSystemCpu.total;
        this.previousSystemCpu = current;
        return total > 0 ? (1 - idle / total) * 100 : 0;
    }
    listFiles() {
        const files = [];
        const envPath = path_1.default.join(process.cwd(), '.env');
        if (fs_1.default.existsSync(envPath))
            files.push(this.fileInfo(envPath, '.env'));
        for (const rootName of ['config', 'data']) {
            const root = path_1.default.join(process.cwd(), rootName);
            if (!fs_1.default.existsSync(root))
                continue;
            this.walk(root, rootName, files, 0);
        }
        return files;
    }
    walk(directory, relative, output, depth) {
        if (depth > 5)
            return;
        for (const entry of fs_1.default.readdirSync(directory, { withFileTypes: true })) {
            if (entry.isSymbolicLink() || entry.name.endsWith('.bak') || entry.name.includes('.tmp-'))
                continue;
            const absolute = path_1.default.join(directory, entry.name);
            const childRelative = `${relative}/${entry.name}`.replace(/\\/g, '/');
            if (entry.isDirectory())
                this.walk(absolute, childRelative, output, depth + 1);
            else if (TEXT_EXTENSIONS.has(path_1.default.extname(entry.name).toLowerCase()))
                output.push(this.fileInfo(absolute, childRelative));
        }
    }
    fileInfo(absolute, relative) {
        const stat = fs_1.default.statSync(absolute);
        const parts = relative.split('/');
        return {
            path: relative,
            size: stat.size,
            modifiedAt: stat.mtimeMs,
            owner: parts[0] === 'config'
                ? parts[1]
                : parts[0] === 'data'
                    ? parts.length > 2
                        ? parts[1]
                        : 'shared'
                    : 'server',
        };
    }
    readFile(req, res, reveal) {
        try {
            const relative = String(reveal ? req.body?.path : (req.query.path ?? ''));
            const absolute = this.resolveSafePath(relative);
            const stat = fs_1.default.statSync(absolute);
            if (stat.size > (this.config.maxEditableFileBytes ?? 1048576))
                throw new Error('File is too large');
            const content = fs_1.default.readFileSync(absolute, 'utf8');
            if (content.includes('\0'))
                throw new Error('Binary files are not editable');
            const sensitive = this.containsSecrets(content, relative);
            if (reveal)
                this.audit(req, 'reveal-file', { path: relative });
            res.json({
                path: relative,
                content: reveal ? content : this.maskSecrets(content, relative),
                sensitive,
                revealed: reveal,
                format: this.formatFor(relative),
            });
        }
        catch (error) {
            res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
        }
    }
    saveFile(req, res) {
        try {
            const relative = String(req.body?.path ?? '');
            const content = String(req.body?.content ?? '');
            if (Buffer.byteLength(content) > (this.config.maxEditableFileBytes ?? 1048576))
                throw new Error('File is too large');
            if (content.includes(MASK))
                throw new Error('Reveal masked secrets before saving this file');
            const absolute = this.resolveSafePath(relative, true);
            this.validateContent(relative, content);
            fs_1.default.mkdirSync(path_1.default.dirname(absolute), { recursive: true });
            if (fs_1.default.existsSync(absolute))
                fs_1.default.copyFileSync(absolute, `${absolute}.bak`);
            const temporary = `${absolute}.tmp-${process.pid}-${Date.now()}`;
            fs_1.default.writeFileSync(temporary, content, { encoding: 'utf8', mode: 0o600 });
            fs_1.default.renameSync(temporary, absolute);
            const reload = relative === '.env'
                ? { type: 'server-config', target: 'server' }
                : relative.startsWith('config/')
                    ? { type: 'plugin', target: relative.split('/')[1] }
                    : { type: 'plugin', target: this.dataOwner(relative) };
            this.audit(req, 'save-file', { path: relative });
            res.json({ success: true, reload, restartRequired: relative === '.env' });
        }
        catch (error) {
            res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
        }
    }
    async reloadPlugin(req, res) {
        const name = String(req.body?.name ?? '');
        if (!name || name === 'server-control') {
            res.status(400).json({
                error: name === 'server-control'
                    ? 'server-control requires a server restart'
                    : 'Plugin name is required',
            });
            return;
        }
        const success = await this.api.reloadPlugin(name);
        this.audit(req, 'reload-plugin', { name, success });
        res.status(success ? 200 : 404).json({ success });
    }
    resolveSafePath(relative, allowMissing = false) {
        const normalized = relative.replace(/\\/g, '/');
        if (normalized === '.env') {
            const envPath = path_1.default.join(process.cwd(), '.env');
            if (fs_1.default.existsSync(envPath) && fs_1.default.lstatSync(envPath).isSymbolicLink())
                throw new Error('Symbolic link escape rejected');
            return envPath;
        }
        if (!/^(config|data)\/[A-Za-z0-9._/-]+$/.test(normalized) || normalized.includes('..'))
            throw new Error('Path is outside the editable roots');
        const rootName = normalized.split('/')[0];
        const root = path_1.default.resolve(process.cwd(), rootName);
        const target = path_1.default.resolve(process.cwd(), normalized);
        if (target !== root && !target.startsWith(`${root}${path_1.default.sep}`))
            throw new Error('Path is outside the editable roots');
        let parent = allowMissing ? path_1.default.dirname(target) : target;
        while (!fs_1.default.existsSync(parent) && parent !== root)
            parent = path_1.default.dirname(parent);
        if (fs_1.default.existsSync(parent) &&
            fs_1.default.realpathSync(parent) !== root &&
            !fs_1.default.realpathSync(parent).startsWith(`${root}${path_1.default.sep}`))
            throw new Error('Symbolic link escape rejected');
        return target;
    }
    formatFor(relative) {
        const extension = path_1.default.extname(relative).toLowerCase();
        if (extension === '.json')
            return 'json';
        if (extension === '.yaml' || extension === '.yml')
            return 'yaml';
        if (relative === '.env' || extension === '.env')
            return 'env';
        return 'text';
    }
    dataOwner(relative) {
        const segment = relative.split('/')[1];
        if (!segment)
            return null;
        if (relative.split('/').length > 2)
            return segment;
        const name = path_1.default.parse(segment).name;
        return this.api.listPlugins().some((plugin) => plugin.directory === name) ? name : null;
    }
    validateContent(relative, content) {
        const format = this.formatFor(relative);
        if (format === 'json')
            JSON.parse(content);
        if (format === 'yaml')
            js_yaml_1.default.load(content);
        if (format === 'env') {
            for (const line of content.split(/\r?\n/)) {
                if (line.trim() &&
                    !line.trim().startsWith('#') &&
                    !/^[A-Za-z_][A-Za-z0-9_]*\s*=/.test(line))
                    throw new Error(`Invalid env line: ${line}`);
            }
        }
    }
    containsSecrets(content, relative) {
        if (relative === '.env')
            return content.split(/\r?\n/).some((line) => SECRET_PATTERN.test(line.split('=')[0]));
        try {
            return this.hasSecretKey(this.formatFor(relative) === 'json' ? JSON.parse(content) : js_yaml_1.default.load(content));
        }
        catch {
            return content.split(/\r?\n/).some((line) => SECRET_PATTERN.test(line.split(':')[0]));
        }
    }
    maskSecrets(content, relative) {
        if (relative !== '.env') {
            try {
                const format = this.formatFor(relative);
                const masked = this.maskObject(format === 'json' ? JSON.parse(content) : js_yaml_1.default.load(content));
                return format === 'json'
                    ? JSON.stringify(masked, null, 2)
                    : js_yaml_1.default.dump(masked, { lineWidth: 100 });
            }
            catch { }
        }
        const separator = '=';
        return content
            .split(/\r?\n/)
            .map((line) => {
            const index = line.indexOf(separator);
            if (index < 0 || !SECRET_PATTERN.test(line.slice(0, index)))
                return line;
            return `${line.slice(0, index + 1)} ${MASK}`;
        })
            .join('\n');
    }
    hasSecretKey(value) {
        if (!value || typeof value !== 'object')
            return false;
        return Object.entries(value).some(([key, child]) => SECRET_PATTERN.test(key) || this.hasSecretKey(child));
    }
    maskObject(value) {
        if (Array.isArray(value))
            return value.map((item) => this.maskObject(item));
        if (!value || typeof value !== 'object')
            return value;
        return Object.fromEntries(Object.entries(value).map(([key, child]) => [
            key,
            SECRET_PATTERN.test(key) ? MASK : this.maskObject(child),
        ]));
    }
    audit(req, action, details = {}) {
        try {
            fs_1.default.mkdirSync(path_1.default.dirname(this.auditPath), { recursive: true });
            fs_1.default.appendFileSync(this.auditPath, `${JSON.stringify({ timestamp: new Date().toISOString(), ip: req.ip || req.socket.remoteAddress, action, ...details })}\n`);
        }
        catch (error) {
            this.api.logger.error(`[ServerControl] failed to write audit log: ${String(error)}`);
        }
    }
    cleanupSessions() {
        const now = Date.now();
        for (const [token, session] of this.sessions)
            if (session.expiresAt <= now)
                this.sessions.delete(token);
        const retentionMs = Math.max(1, this.config.loginAttemptRetentionMinutes ?? 15) * 60000;
        for (const [ip, attempt] of this.attempts) {
            const lockExpired = attempt.lockedUntil > 0 && attempt.lockedUntil <= now;
            const stale = !attempt.lockedUntil && now - attempt.lastAttemptAt >= retentionMs;
            if (lockExpired || stale)
                this.attempts.delete(ip);
        }
    }
    newAttemptRecord() {
        return { count: 0, lockedUntil: 0, lastAttemptAt: Date.now() };
    }
    storeAttemptRecord(ip, attempt) {
        const maxEntries = Math.min(100000, Math.max(100, this.config.maxLoginAttemptEntries ?? 10000));
        if (!this.attempts.has(ip) && this.attempts.size >= maxEntries) {
            let oldestIp;
            let oldestAt = Number.POSITIVE_INFINITY;
            const now = Date.now();
            for (const [candidateIp, candidate] of this.attempts) {
                if (candidate.lockedUntil > now)
                    continue;
                if (candidate.lastAttemptAt < oldestAt) {
                    oldestIp = candidateIp;
                    oldestAt = candidate.lastAttemptAt;
                }
            }
            if (oldestIp)
                this.attempts.delete(oldestIp);
            else
                return;
        }
        this.attempts.set(ip, attempt);
    }
}
let instance;
const plugin = {
    async init(api) {
        instance = new ServerControlPlugin(api, api.readPluginConfig() ?? {});
        instance.start();
    },
    async destroy() {
        instance?.stop();
        instance = undefined;
    },
};
exports.default = plugin;
