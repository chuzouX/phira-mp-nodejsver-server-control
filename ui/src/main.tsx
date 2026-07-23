/* The editor intentionally accepts arbitrary JSON/YAML shapes at this boundary. */
/* eslint-disable @typescript-eslint/no-explicit-any */
import React, { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Activity,
  ChevronRight,
  Cpu,
  FileCog,
  Gauge,
  History as HistoryIcon,
  KeyRound,
  LogOut,
  MemoryStick,
  PlugZap,
  RefreshCw,
  Save,
  Send,
  Server,
  ShieldCheck,
  Terminal,
  Trash2,
  Users,
  X,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import yaml from 'js-yaml';
import './styles.css';

type FileEntry = { path: string; size: number; modifiedAt: number; owner: string };

async function request(path: string, init: RequestInit = {}) {
  const response = await fetch(`/control/api${path}`, {
    credentials: 'same-origin',
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init.headers || {}) },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function formatBytes(value = 0) {
  if (value < 1024) return `${value} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let n = value / 1024;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i += 1;
  }
  return `${n.toFixed(1)} ${units[i]}`;
}

function formatUptime(seconds = 0) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  return `${days}d ${hours}h ${mins}m`;
}

function MetricTile({ icon: Icon, label, value, detail, tone = 'blue' }: any) {
  return (
    <div className={`metric-tile ${tone}`}>
      <div className="tile-icon">
        <Icon size={18} />
      </div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{detail}</small>
      </div>
    </div>
  );
}

function Login({ onLogin }: { onLogin: (csrf: string) => void }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const result = await request('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ password }),
      });
      onLogin(result.csrf);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="login-shell">
      <div className="login-panel">
        <div className="brand-mark">
          <ShieldCheck size={22} />
        </div>
        <p className="eyebrow">SERVER CONTROL</p>
        <h1>操作控制台</h1>
        <p className="muted">使用独立管理员密码进入本机服务器管理面板。</p>
        <form onSubmit={submit}>
          <label>
            管理员密码
            <input
              name="password"
              autoComplete="current-password"
              autoFocus
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="输入密码"
            />
          </label>
          {error && <div className="error">{error}</div>}
          <button className="primary full" disabled={busy || !password}>
            {busy ? '验证中…' : '登录控制台'}
            <ChevronRight size={17} />
          </button>
        </form>
        <p className="login-foot">
          <LockIcon /> 仅限受信任的运维人员访问
        </p>
      </div>
    </main>
  );
}

function LockIcon() {
  return <KeyRound size={13} />;
}

function App() {
  const [csrf, setCsrf] = useState<string | null>(null);
  const [tab, setTab] = useState('overview');
  const [metrics, setMetrics] = useState<any>();
  const [users, setUsers] = useState<any[]>([]);
  const [plugins, setPlugins] = useState<any[]>([]);
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [selectedFile, setSelectedFile] = useState<any>();
  const [notice, setNotice] = useState('');

  async function load() {
    try {
      const [m, u, p, f] = await Promise.all([
        request('/metrics'),
        request('/users'),
        request('/plugins'),
        request('/files'),
      ]);
      setMetrics(m);
      setUsers(u);
      setPlugins(p);
      setFiles(f);
    } catch (e) {
      if ((e as Error).message === 'Unauthorized') setCsrf(null);
      else setNotice((e as Error).message);
    }
  }
  useEffect(() => {
    request('/auth/session')
      .then((s) => setCsrf(s.csrf))
      .catch(() => undefined);
  }, []);
  useEffect(() => {
    if (!csrf) return;
    load();
    const timer = setInterval(load, 2500);
    return () => clearInterval(timer);
  }, [csrf]);
  const current = metrics?.current || {};
  const history = (metrics?.history || []).map((item: any) => ({
    ...item,
    time: new Date(item.timestamp).toLocaleTimeString([], { minute: '2-digit', second: '2-digit' }),
    rssMb: Math.round(item.memory.rss / 1024 / 1024),
    heapMb: Math.round(item.memory.heapUsed / 1024 / 1024),
  }));
  const nav = [
    { id: 'overview', label: '概览', icon: Gauge },
    { id: 'users', label: '在线用户', icon: Users },
    { id: 'plugins', label: '插件', icon: PlugZap },
    { id: 'logs', label: '实时日志', icon: Terminal },
    { id: 'history', label: '历史分析', icon: HistoryIcon },
    { id: 'files', label: '配置与数据', icon: FileCog },
  ];
  if (!csrf) return <Login onLogin={setCsrf} />;
  async function logout() {
    await request('/auth/logout', { method: 'POST', headers: { 'X-CSRF-Token': csrf! } });
    setCsrf(null);
  }
  async function reloadPlugin(name: string) {
    if (!confirm(`确认重载插件 ${name}？`)) return;
    try {
      await request('/reload/plugin', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf! },
        body: JSON.stringify({ name }),
      });
      setNotice(`已请求重载 ${name}`);
      load();
    } catch (e) {
      setNotice((e as Error).message);
    }
  }
  async function openFile(entry: FileEntry, reveal = false) {
    try {
      const data = await request(
        reveal ? '/file/reveal' : `/file?path=${encodeURIComponent(entry.path)}`,
        {
          method: reveal ? 'POST' : 'GET',
          headers: reveal ? { 'X-CSRF-Token': csrf! } : undefined,
          body: reveal ? JSON.stringify({ path: entry.path }) : undefined,
        },
      );
      setSelectedFile({ ...entry, ...data });
    } catch (e) {
      setNotice((e as Error).message);
    }
  }
  async function saveFile() {
    if (!selectedFile) return;
    try {
      const result = await request('/file', {
        method: 'PUT',
        headers: { 'X-CSRF-Token': csrf! },
        body: JSON.stringify({ path: selectedFile.path, content: selectedFile.content }),
      });
      setNotice(`已保存 ${selectedFile.path}`);
      const target = result.reload?.target;
      if (
        result.reload?.type === 'server-config' &&
        confirm('文件已保存。现在重新加载可热更新的服务器配置？其余项目仍需重启。')
      ) {
        await request('/reload/config', { method: 'POST', headers: { 'X-CSRF-Token': csrf! } });
        setNotice('服务器配置已重新加载；监听端口等结构性设置仍需重启');
      } else if (
        result.reload?.type === 'plugin' &&
        target &&
        target !== 'server-control' &&
        confirm(`文件已保存。现在重载插件 ${target}？`)
      ) {
        await request('/reload/plugin', {
          method: 'POST',
          headers: { 'X-CSRF-Token': csrf! },
          body: JSON.stringify({ name: target }),
        });
        setNotice(`已重载插件 ${target}`);
      } else if (target === 'server-control') {
        setNotice('已保存 server-control 配置；请重启服务器使其生效');
      }
    } catch (e) {
      setNotice((e as Error).message);
    }
  }
  return (
    <div className="app-shell">
      <aside>
        <div className="side-brand">
          <div className="brand-mark">
            <Server size={18} />
          </div>
          <div>
            <strong>Server Control</strong>
            <span>operations console</span>
          </div>
        </div>
        <nav>
          {nav.map(({ id, label, icon: Icon }) => (
            <button className={tab === id ? 'active' : ''} onClick={() => setTab(id)} key={id}>
              <Icon size={17} />
              {label}
            </button>
          ))}
        </nav>
        <div className="side-footer">
          <span className="status-dot" />
          服务在线
          <button className="ghost" onClick={logout}>
            <LogOut size={15} />
            退出
          </button>
        </div>
      </aside>
      <main className="content">
        <header>
          <div>
            <p className="eyebrow">OPERATIONS / {tab.toUpperCase()}</p>
            <h1>{nav.find((n) => n.id === tab)?.label}</h1>
          </div>
          <div className="header-actions">
            <span className="live">
              <span className="status-dot" />
              LIVE
            </span>
            <button className="icon-button" title="刷新" onClick={load}>
              <RefreshCw size={17} />
            </button>
          </div>
        </header>
        {notice && (
          <div className="notice" onClick={() => setNotice('')}>
            {notice}
            <X size={15} />
          </div>
        )}
        {tab === 'overview' && <Overview current={current} history={history} />}
        {tab === 'users' && <UsersView users={users} />}
        {tab === 'plugins' && <PluginsView plugins={plugins} reloadPlugin={reloadPlugin} />}
        {tab === 'logs' && <LogsView csrf={csrf} setNotice={setNotice} />}
        {tab === 'history' && <HistoricalLogsView setNotice={setNotice} />}
        {tab === 'files' && (
          <FilesView
            files={files}
            selectedFile={selectedFile}
            setSelectedFile={setSelectedFile}
            openFile={openFile}
            saveFile={saveFile}
          />
        )}
      </main>
    </div>
  );
}

function HistoricalLogsView({ setNotice }: { setNotice: (message: string) => void }) {
  const [files, setFiles] = useState<any[]>([]);
  const [kind, setKind] = useState<'game' | 'commands' | 'control' | 'bans'>('game');
  const [selected, setSelected] = useState('');
  const [analysis, setAnalysis] = useState<any>();
  const [loading, setLoading] = useState(false);
  const [loadedLines, setLoadedLines] = useState<string[]>([]);
  const [nextOffset, setNextOffset] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [loadingLines, setLoadingLines] = useState(false);

  useEffect(() => {
    request('/log-history/files')
      .then((items) => {
        setFiles(items);
        const first = items.find((item: any) => item.kind === kind);
        if (first) setSelected(first.name);
      })
      .catch((error) => setNotice((error as Error).message));
  }, []);

  useEffect(() => {
    const first = files.find((item) => item.kind === kind);
    if (first) setSelected(first.name);
    else {
      setSelected('');
      setAnalysis(undefined);
    }
  }, [kind, files]);

  useEffect(() => {
    if (!selected) return;
    setLoading(true);
    request(`/log-history/analyze?name=${encodeURIComponent(selected)}`)
      .then(setAnalysis)
      .catch((error) => setNotice((error as Error).message))
      .finally(() => setLoading(false));
  }, [selected, setNotice]);

  useEffect(() => {
    if (!selected) return;
    let cancelled = false;
    setLoadedLines([]);
    setNextOffset(0);
    setHasMore(false);
    setLoadingLines(true);
    request(`/log-history/lines?name=${encodeURIComponent(selected)}&offset=0`)
      .then((result) => {
        if (cancelled) return;
        setLoadedLines(result.lines || []);
        setNextOffset(result.nextOffset || 0);
        setHasMore(Boolean(result.hasMore));
      })
      .catch((error) => {
        if (!cancelled) setNotice((error as Error).message);
      })
      .finally(() => {
        if (!cancelled) setLoadingLines(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selected, setNotice]);

  async function loadMoreLines() {
    if (!selected || !hasMore || loadingLines) return;
    setLoadingLines(true);
    try {
      const result = await request(
        `/log-history/lines?name=${encodeURIComponent(selected)}&offset=${nextOffset}`,
      );
      setLoadedLines((current) => [...current, ...(result.lines || [])]);
      setNextOffset(result.nextOffset || nextOffset);
      setHasMore(Boolean(result.hasMore));
    } catch (error) {
      setNotice((error as Error).message);
    } finally {
      setLoadingLines(false);
    }
  }

  const visibleFiles = files.filter((file) => file.kind === kind);
  return (
    <section className="history-layout">
      <div className="panel history-files">
        <div className="panel-heading">
          <div>
            <span className="eyebrow">ARCHIVE INDEX</span>
            <h2>历史日志</h2>
          </div>
        </div>
        <div className="history-kinds">
          <button className={kind === 'game' ? 'active' : ''} onClick={() => setKind('game')}>
            游戏日志
          </button>
          <button
            className={kind === 'commands' ? 'active' : ''}
            onClick={() => setKind('commands')}
          >
            命令行日志
          </button>
          <button className={kind === 'control' ? 'active' : ''} onClick={() => setKind('control')}>
            Control 登录
          </button>
          <button className={kind === 'bans' ? 'active' : ''} onClick={() => setKind('bans')}>
            封禁日志
          </button>
        </div>
        <div className="history-file-list">
          {visibleFiles.map((file) => (
            <button
              className={`history-file ${selected === file.name ? 'selected' : ''}`}
              key={file.name}
              onClick={() => setSelected(file.name)}
            >
              <strong>{file.name}</strong>
              <small>
                {formatBytes(file.size)} · {new Date(file.modifiedAt).toLocaleString()}
              </small>
            </button>
          ))}
          {visibleFiles.length === 0 && <div className="empty">暂无该类日志</div>}
        </div>
      </div>
      <div className="panel history-report">
        <div className="panel-heading">
          <div>
            <span className="eyebrow">ANALYSIS REPORT</span>
            <h2>{selected || '选择日志文件'}</h2>
          </div>
          {loading && <span className="table-note">分析中...</span>}
        </div>
        {analysis ? (
          <HistoricalReport
            analysis={analysis}
            lines={loadedLines}
            hasMore={hasMore}
            loadingLines={loadingLines}
            loadMore={loadMoreLines}
          />
        ) : (
          <div className="empty">选择左侧日志开始分析</div>
        )}
      </div>
    </section>
  );
}

function HistoricalReport({
  analysis,
  lines,
  hasMore,
  loadingLines,
  loadMore,
}: {
  analysis: any;
  lines: string[];
  hasMore: boolean;
  loadingLines: boolean;
  loadMore: () => void;
}) {
  const [levelFilter, setLevelFilter] = useState('ALL');
  const levelEntries = Object.entries(analysis.levels || analysis.actions || {}) as Array<
    [string, number]
  >;
  const commandEntries = Object.entries(analysis.commands || {}) as Array<[string, number]>;
  const targetEntries = Object.entries(analysis.targets || {}) as Array<[string, number]>;
  const filteredLines = filterLogLines(lines, levelFilter);
  return (
    <div className="history-report-body">
      <div className="history-metrics">
        <div>
          <span>记录总数</span>
          <strong>{analysis.totalLines}</strong>
        </div>
        {analysis.login ? (
          <>
            <div>
              <span>登录成功</span>
              <strong className="good">{analysis.login.success}</strong>
            </div>
            <div>
              <span>登录失败</span>
              <strong className="bad">{analysis.login.failed}</strong>
            </div>
            <div>
              <span>退出登录</span>
              <strong>{analysis.login.logout}</strong>
            </div>
          </>
        ) : analysis.bans ? (
          <>
            <div>
              <span>新增封禁</span>
              <strong className="bad">{analysis.bans.created}</strong>
            </div>
            <div>
              <span>解除封禁</span>
              <strong className="good">{analysis.bans.removed}</strong>
            </div>
            <div>
              <span>登录拦截</span>
              <strong>{analysis.bans.blocked}</strong>
            </div>
          </>
        ) : (
          levelEntries.slice(0, 3).map(([label, count]) => (
            <div key={label}>
              <span>{label}</span>
              <strong>{count}</strong>
            </div>
          ))
        )}
      </div>
      {commandEntries.length > 0 && (
        <div className="history-section">
          <div className="history-section-title">命令使用排行</div>
          <div className="rank-list">
            {commandEntries
              .sort((a, b) => b[1] - a[1])
              .slice(0, 12)
              .map(([command, count]) => (
                <div key={command}>
                  <span className="mono">{command}</span>
                  <strong>{count}</strong>
                </div>
              ))}
          </div>
        </div>
      )}
      {targetEntries.length > 0 && (
        <div className="history-section">
          <div className="history-section-title">封禁目标排行</div>
          <div className="rank-list">
            {targetEntries
              .sort((a, b) => b[1] - a[1])
              .slice(0, 12)
              .map(([target, count]) => (
                <div key={target}>
                  <span className="mono">{target}</span>
                  <strong>{count}</strong>
                </div>
              ))}
          </div>
        </div>
      )}
      {analysis.login && (
        <div className="history-section">
          <div className="history-section-title">Control 登录记录</div>
          <div className="audit-list">
            {(analysis.records || []).map((record: any, index: number) => (
              <div key={`${record.timestamp}-${index}`}>
                <span
                  className={`badge ${record.action === 'login-success' ? 'green' : record.action === 'login-failed' ? 'red' : 'gray'}`}
                >
                  {record.action}
                </span>
                <span>{record.timestamp || '-'}</span>
                <span className="mono">{record.ip || '-'}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      <div className="history-section">
        <div className="history-section-title history-lines-heading">
          <span>日志内容</span>
          {analysis.kind !== 'control' && (
            <div className="history-level-filter">
              {['ALL', 'DEBUG', 'INFO', 'MARK', 'WARN', 'ERROR', 'BAN', 'CMD', 'PLUGIN'].map(
                (level) => (
                  <button
                    className={levelFilter === level ? 'active' : ''}
                    key={level}
                    onClick={() => setLevelFilter(level)}
                    type="button"
                  >
                    {level === 'ALL' ? '全部' : level}
                  </button>
                ),
              )}
            </div>
          )}
        </div>
        <div className="history-lines">
          {filteredLines.map((line: string, index: number) => (
            <div key={`${index}-${line}`} className={logTone(line)}>
              {line}
            </div>
          ))}
          {filteredLines.length === 0 && <div className="empty">暂无匹配记录</div>}
        </div>
        <div className="history-load-more">
          <span>
            已加载 {lines.length} 行{hasMore ? '' : ' · 已加载全部'}
          </span>
          {hasMore && (
            <button
              className="small-button"
              disabled={loadingLines}
              onClick={loadMore}
              type="button"
            >
              {loadingLines ? '加载中...' : '加载更多'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function LogsView({ csrf, setNotice }: { csrf: string; setNotice: (message: string) => void }) {
  const [lines, setLines] = useState<string[]>([]);
  const [levelFilter, setLevelFilter] = useState('ALL');
  const [command, setCommand] = useState('');
  const [busy, setBusy] = useState(false);
  const [connected, setConnected] = useState(false);
  const viewportRef = useRef<HTMLDivElement>(null);
  const followRef = useRef(true);

  useEffect(() => {
    const source = new EventSource('/control/api/logs/stream');
    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false);
    source.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data) as { line?: string };
        if (payload.line) setLines((current) => [...current, payload.line!].slice(-1000));
      } catch {
        // Ignore malformed stream frames and keep the connection alive.
      }
    };
    return () => source.close();
  }, []);

  useEffect(() => {
    const viewport = viewportRef.current;
    if (viewport && followRef.current) viewport.scrollTop = viewport.scrollHeight;
  }, [lines]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    const input = command.trim();
    if (!input.startsWith('/')) {
      setNotice('指令必须以 / 开头');
      return;
    }
    setBusy(true);
    try {
      await request('/command', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        body: JSON.stringify({ input }),
      });
      setCommand('');
      followRef.current = true;
    } catch (error) {
      setNotice((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const visibleLines = filterLogLines(lines, levelFilter);

  return (
    <section className="panel terminal-panel">
      <div className="panel-heading">
        <div>
          <span className="eyebrow">SERVER OUTPUT</span>
          <h2>实时日志</h2>
        </div>
        <div className="terminal-actions">
          <span className={connected ? 'stream-status connected' : 'stream-status'}>
            <span className="status-dot" />
            {connected ? '实时连接' : '正在重连'}
          </span>
          <button className="icon-button" title="清空当前视图" onClick={() => setLines([])}>
            <Trash2 size={16} />
          </button>
        </div>
      </div>
      <div className="log-filters" role="toolbar" aria-label="日志等级筛选">
        {['ALL', 'DEBUG', 'INFO', 'MARK', 'WARN', 'ERROR', 'BAN', 'CMD', 'PLUGIN'].map((level) => (
          <button
            className={levelFilter === level ? 'active' : ''}
            key={level}
            onClick={() => setLevelFilter(level)}
            type="button"
          >
            {level === 'ALL' ? '全部' : level}
          </button>
        ))}
      </div>
      <div
        className="log-viewport"
        ref={viewportRef}
        role="log"
        onScroll={(event) => {
          const target = event.currentTarget;
          followRef.current = target.scrollHeight - target.scrollTop - target.clientHeight < 48;
        }}
      >
        {visibleLines.length === 0 ? (
          <div className="log-empty">等待服务器日志...</div>
        ) : (
          visibleLines.map((line, index) => (
            <div className={`log-line ${logTone(line)}`} key={`${index}-${line.slice(0, 24)}`}>
              {line}
            </div>
          ))
        )}
      </div>
      <form className="command-bar" onSubmit={submit}>
        <span className="command-prompt">&gt;</span>
        <input
          aria-label="服务器指令"
          autoComplete="off"
          maxLength={512}
          placeholder="/status"
          spellCheck={false}
          value={command}
          onChange={(event) => setCommand(event.target.value)}
        />
        <button
          className="command-submit"
          disabled={busy || !command.trim().startsWith('/')}
          title="执行指令"
          type="submit"
        >
          <Send size={16} />
        </button>
      </form>
    </section>
  );
}

function logTone(line: string): string {
  const level = logLevel(line);
  return level ? `log-${level.toLowerCase()}` : '';
}

function logLevel(line: string): string {
  return line.match(/\[(DEBUG|INFO|MARK|WARN|ERROR|BAN|CMD|PLUGIN)\]/)?.[1] ?? '';
}

function filterLogLines(lines: string[], levelFilter: string): string[] {
  if (levelFilter === 'ALL') return lines;
  let inheritedLevel = '';
  return lines.filter((line) => {
    const explicitLevel = logLevel(line);
    if (explicitLevel) inheritedLevel = explicitLevel;
    return inheritedLevel === levelFilter;
  });
}

function Overview({ current, history }: any) {
  const memoryPercent = current.memory?.systemTotal
    ? (current.memory.systemUsed / current.memory.systemTotal) * 100
    : 0;
  return (
    <section className="page-grid">
      <div className="metrics-row">
        <MetricTile
          icon={Users}
          label="在线用户"
          value={current.onlinePlayers ?? '—'}
          detail={`${current.roomCount ?? 0} 个活跃房间`}
          tone="green"
        />
        <MetricTile
          icon={Cpu}
          label="进程 CPU"
          value={current.cpu ? `${current.cpu.process.toFixed(1)}%` : '—'}
          detail={`主机 ${current.cpu?.system?.toFixed(1) ?? '—'}%`}
        />
        <MetricTile
          icon={MemoryStick}
          label="内存 RSS"
          value={formatBytes(current.memory?.rss)}
          detail={`堆 ${formatBytes(current.memory?.heapUsed)}`}
          tone="amber"
        />
        <MetricTile
          icon={Activity}
          label="事件循环"
          value={current.eventLoopMs ? `${current.eventLoopMs.toFixed(1)} ms` : '—'}
          detail={`GC ${current.gc?.count ?? 0} 次`}
          tone="purple"
        />
      </div>
      <div className="panel chart-panel">
        <div className="panel-heading">
          <div>
            <span className="eyebrow">RESOURCE WINDOW</span>
            <h2>资源利用率</h2>
          </div>
          <div className="legend">
            <span>
              <i className="blue-dot" />
              RSS
            </span>
            <span>
              <i className="purple-dot" />
              Heap
            </span>
          </div>
        </div>
        <ResponsiveContainer width="100%" height={260}>
          <AreaChart data={history}>
            <defs>
              <linearGradient id="rss" x1="0" x2="0" y1="0" y2="1">
                <stop offset="5%" stopColor="#5b8cff" stopOpacity={0.28} />
                <stop offset="95%" stopColor="#5b8cff" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="heap" x1="0" x2="0" y1="0" y2="1">
                <stop offset="5%" stopColor="#9d7bff" stopOpacity={0.22} />
                <stop offset="95%" stopColor="#9d7bff" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="#283142" strokeDasharray="3 3" vertical={false} />
            <XAxis
              dataKey="time"
              tick={{ fill: '#76829a', fontSize: 11 }}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              tick={{ fill: '#76829a', fontSize: 11 }}
              tickLine={false}
              axisLine={false}
              unit=" MB"
              width={50}
            />
            <Tooltip
              contentStyle={{ background: '#171d29', border: '1px solid #303b50', borderRadius: 6 }}
            />
            <Area
              type="monotone"
              dataKey="rssMb"
              name="RSS"
              stroke="#5b8cff"
              fill="url(#rss)"
              strokeWidth={2}
            />
            <Area
              type="monotone"
              dataKey="heapMb"
              name="Heap"
              stroke="#9d7bff"
              fill="url(#heap)"
              strokeWidth={2}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <div className="two-col">
        <div className="panel">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">RUNTIME</span>
              <h2>运行资源</h2>
            </div>
          </div>
          <div className="stat-list">
            <div>
              <span>运行时间</span>
              <strong>{formatUptime(current.uptime)}</strong>
            </div>
            <div>
              <span>系统内存</span>
              <strong>{memoryPercent.toFixed(1)}%</strong>
            </div>
            <div>
              <span>文件读取 / 写入</span>
              <strong>
                {current.resource?.fsRead ?? 0} / {current.resource?.fsWrite ?? 0}
              </strong>
            </div>
            <div>
              <span>磁盘空间</span>
              <strong>
                {current.disk
                  ? `${formatBytes(current.disk.total - current.disk.free)} / ${formatBytes(current.disk.total)}`
                  : '不可用'}
              </strong>
            </div>
          </div>
        </div>
        <div className="panel gc-panel">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">GARBAGE COLLECTION</span>
              <h2>GC 采样</h2>
            </div>
          </div>
          <div className="gc-value">
            <strong>
              {current.gc?.durationMs?.toFixed(1) ?? '0.0'}
              <small> ms</small>
            </strong>
            <span>最近采样暂停时间</span>
          </div>
          <div className="progress">
            <span style={{ width: `${Math.min(100, (current.gc?.durationMs || 0) * 4)}%` }} />
          </div>
          <p className="muted">
            当前采样 {current.gc?.count ?? 0} 次回收，事件循环平均延迟{' '}
            {current.eventLoopMs?.toFixed(1) ?? '0.0'} ms。
          </p>
        </div>
      </div>
    </section>
  );
}

function UsersView({ users }: { users: any[] }) {
  return (
    <section className="panel table-panel">
      <div className="panel-heading">
        <div>
          <span className="eyebrow">CONNECTED SESSIONS</span>
          <h2>
            在线用户 <em>{users.length}</em>
          </h2>
        </div>
        <span className="table-note">实时采样</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>用户</th>
              <th>ID</th>
              <th>房间</th>
              <th>IP 地址</th>
              <th>权限</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={`${user.id}-${user.connectionId}`}>
                <td>
                  <strong>{user.name}</strong>
                </td>
                <td className="mono">{user.id}</td>
                <td>{user.roomName || '大厅'}</td>
                <td className="mono">{user.ip}</td>
                <td>
                  {user.isOwner ? (
                    <span className="badge purple">Owner</span>
                  ) : user.isAdmin ? (
                    <span className="badge blue">Admin</span>
                  ) : (
                    <span className="muted">User</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {users.length === 0 && <div className="empty">当前没有在线用户</div>}
      </div>
    </section>
  );
}

function PluginsView({ plugins, reloadPlugin }: any) {
  return (
    <section className="panel table-panel">
      <div className="panel-heading">
        <div>
          <span className="eyebrow">RUNTIME MODULES</span>
          <h2>
            插件列表 <em>{plugins.length}</em>
          </h2>
        </div>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>插件</th>
              <th>版本</th>
              <th>状态</th>
              <th>UUID</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {plugins.map((plugin: any) => (
              <tr key={plugin.directory}>
                <td>
                  <strong>{plugin.metadata?.name || plugin.directory}</strong>
                  <small>{plugin.directory}</small>
                </td>
                <td>{plugin.metadata?.version || '—'}</td>
                <td>
                  {plugin.loaded ? (
                    <span className="badge green">已加载</span>
                  ) : plugin.enabled ? (
                    <span className="badge amber">未加载</span>
                  ) : (
                    <span className="badge gray">已禁用</span>
                  )}
                </td>
                <td className="mono dim">{plugin.metadata?.uuid || '—'}</td>
                <td className="align-right">
                  {plugin.loaded && plugin.directory !== 'server-control' && (
                    <button className="small-button" onClick={() => reloadPlugin(plugin.directory)}>
                      <RefreshCw size={14} />
                      重载
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function FilesView({ files, selectedFile, setSelectedFile, openFile, saveFile }: any) {
  const [mode, setMode] = useState<'visual' | 'source'>('visual');
  useEffect(() => setMode('visual'), [selectedFile?.path]);
  const supportsVisual = selectedFile && ['json', 'yaml', 'env'].includes(selectedFile.format);
  return (
    <section className="file-layout">
      <div className="panel file-list">
        <div className="panel-heading">
          <div>
            <span className="eyebrow">SAFE FILE ROOTS</span>
            <h2>配置与数据</h2>
          </div>
        </div>
        {files.map((file: FileEntry) => (
          <button
            className={`file-row ${selectedFile?.path === file.path ? 'selected' : ''}`}
            key={file.path}
            onClick={() => openFile(file)}
          >
            <FileCog size={15} />
            <span>
              <strong>{file.path}</strong>
              <small>
                {file.owner} · {formatBytes(file.size)}
              </small>
            </span>
            <ChevronRight size={15} />
          </button>
        ))}
      </div>
      <div className="panel editor-panel">
        {selectedFile ? (
          <>
            <div className="panel-heading">
              <div>
                <span className="eyebrow">{selectedFile.format?.toUpperCase()}</span>
                <h2>{selectedFile.path}</h2>
              </div>
              <div className="editor-actions">
                {supportsVisual && (
                  <div className="segmented">
                    <button
                      className={mode === 'visual' ? 'active' : ''}
                      onClick={() => setMode('visual')}
                    >
                      字段
                    </button>
                    <button
                      className={mode === 'source' ? 'active' : ''}
                      onClick={() => setMode('source')}
                    >
                      源码
                    </button>
                  </div>
                )}
                {selectedFile.sensitive && !selectedFile.revealed && (
                  <button className="small-button" onClick={() => openFile(selectedFile, true)}>
                    <KeyRound size={14} />
                    查看敏感值
                  </button>
                )}
                <button className="primary small-button" onClick={saveFile}>
                  <Save size={14} />
                  保存
                </button>
              </div>
            </div>
            {mode === 'visual' && supportsVisual ? (
              <StructuredEditor
                file={selectedFile}
                onChange={(content: string) => setSelectedFile({ ...selectedFile, content })}
              />
            ) : (
              <textarea
                className="editor"
                value={selectedFile.content}
                onChange={(e) => setSelectedFile({ ...selectedFile, content: e.target.value })}
                spellCheck={false}
              />
            )}
          </>
        ) : (
          <div className="empty editor-empty">
            <FileCog size={26} />
            <p>选择左侧文件开始查看或编辑</p>
          </div>
        )}
      </div>
    </section>
  );
}

function StructuredEditor({ file, onChange }: any) {
  try {
    if (file.format === 'env') {
      const rows = file.content
        .split(/\r?\n/)
        .map((line: string, index: number) => ({
          line,
          index,
          match: line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$/),
        }))
        .filter((row: any) => row.match);
      const update = (index: number, value: string) => {
        const lines = file.content.split(/\r?\n/);
        const key = lines[index].split('=')[0];
        lines[index] = `${key}=${value}`;
        onChange(lines.join('\n'));
      };
      return (
        <div className="structured-editor">
          {rows.map((row: any) => (
            <label className="field-row" key={`${row.match[1]}-${row.index}`}>
              <span>
                {row.match[1]}
                {/(password|token|secret|key)/i.test(row.match[1]) && <KeyRound size={12} />}
              </span>
              <input
                value={row.match[2].trim()}
                onChange={(event) => update(row.index, event.target.value)}
              />
            </label>
          ))}
        </div>
      );
    }
    const parsed: any =
      file.format === 'json' ? JSON.parse(file.content || '{}') : yaml.load(file.content) || {};
    const rows = flattenValues(parsed);
    const update = (parts: Array<string | number>, value: any) => {
      const clone = structuredClone(parsed);
      let cursor = clone;
      for (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];
      cursor[parts[parts.length - 1]] = value;
      onChange(
        file.format === 'json'
          ? JSON.stringify(clone, null, 2)
          : yaml.dump(clone, { lineWidth: 100 }),
      );
    };
    return (
      <div className="structured-editor">
        {rows.map((row) => (
          <label className="field-row" key={row.path.join('.')}>
            <span>{row.path.join('.')}</span>
            {typeof row.value === 'boolean' ? (
              <input
                type="checkbox"
                checked={row.value}
                onChange={(event) => update(row.path, event.target.checked)}
              />
            ) : (
              <input
                type={typeof row.value === 'number' ? 'number' : 'text'}
                value={String(row.value ?? '')}
                onChange={(event) =>
                  update(
                    row.path,
                    typeof row.value === 'number' ? Number(event.target.value) : event.target.value,
                  )
                }
              />
            )}
          </label>
        ))}
      </div>
    );
  } catch (error) {
    return (
      <div className="empty editor-empty">
        <p>无法解析为结构化数据，请切换到源码模式修正格式。</p>
        <small>{(error as Error).message}</small>
      </div>
    );
  }
}

function flattenValues(
  value: any,
  path: Array<string | number> = [],
): Array<{ path: Array<string | number>; value: any }> {
  if (value === null || typeof value !== 'object') return [{ path, value }];
  return Object.entries(value).flatMap(([key, child]) =>
    flattenValues(child, [...path, Array.isArray(value) ? Number(key) : key]),
  );
}

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
