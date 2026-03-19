/**
 * smart-security-client.js
 * ─────────────────────────────────────────────────────────────
 * JavaScript / TypeScript API client for Smart Security Analyzer.
 * Drop this into your React / Vue / vanilla JS frontend to
 * communicate with the Python backend.
 *
 * Usage:
 *   import SecurityClient from './smart-security-client.js';
 *   const api = new SecurityClient('http://localhost:8000');
 *   const { scan_id } = await api.scan.vulnerability('192.168.1.1', { autoRemediate: true });
 *   const result = await api.scan.poll(scan_id);
 */

export class SecurityClient {
  constructor(baseUrl = 'http://localhost:8000') {
    this.base = baseUrl.replace(/\/$/, '');
    this.scan       = new ScanAPI(this);
    this.osint      = new OsintAPI(this);
    this.shadowIt   = new ShadowItAPI(this);
    this.remediation = new RemediationAPI(this);
    this.reports    = new ReportsAPI(this);
    this.schedule   = new ScheduleAPI(this);
  }

  async _request(method, path, body = null) {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json' },
    };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(`${this.base}${path}`, opts);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    return res.json();
  }

  get = (path)       => this._request('GET', path);
  post = (path, body) => this._request('POST', path, body);
  del  = (path)       => this._request('DELETE', path);

  /** Poll a scan until it reaches a terminal status. */
  async pollUntilDone(getResultFn, { intervalMs = 3000, timeoutMs = 600_000, onProgress } = {}) {
    const start = Date.now();
    while (true) {
      const result = await getResultFn();
      if (['completed', 'failed'].includes(result.status)) return result;
      if (Date.now() - start > timeoutMs) throw new Error('Polling timed out');
      if (onProgress) onProgress(result);
      await new Promise(r => setTimeout(r, intervalMs));
    }
  }

  async health() { return this.get('/health'); }
  async stats()  { return this.get('/api/stats'); }
}


// ── Network Scanning ─────────────────────────────────────────────────────────

class ScanAPI {
  constructor(client) { this.c = client; }

  /**
   * @param {string} target – IP, CIDR, or domain
   * @param {Object} opts
   * @param {string} [opts.ports='1-1000']
   * @param {string} [opts.scriptGroup='vuln_basic']
   * @param {boolean} [opts.autoRemediate=false]
   * @param {Object} [opts.deploymentContext]
   * @returns {Promise<{scan_id, status, message}>}
   */
  async discovery(target, opts = {}) {
    return this.c.post('/api/scan/discovery', { target, ...this._opts(opts) });
  }

  async basic(target, opts = {}) {
    return this.c.post('/api/scan/basic', { target, ...this._opts(opts) });
  }

  async vulnerability(target, opts = {}) {
    return this.c.post('/api/scan/vulnerability', { target, ...this._opts(opts) });
  }

  async web(target, opts = {}) {
    return this.c.post('/api/scan/web', { target, ...this._opts(opts) });
  }

  async full(target, opts = {}) {
    return this.c.post('/api/scan/full', { target, ...this._opts(opts) });
  }

  async local(autoRemediate = false) {
    return this.c.post(`/api/scan/local?auto_remediate=${autoRemediate}`);
  }

  async getResult(scanId) {
    return this.c.get(`/api/scan/${scanId}`);
  }

  async list(limit = 20, offset = 0) {
    return this.c.get(`/api/scans?limit=${limit}&offset=${offset}`);
  }

  /**
   * Start a scan and wait until it completes.
   * @param {string} type – discovery | basic | vulnerability | web | full
   * @param {string} target
   * @param {Object} opts
   * @param {Function} [opts.onProgress] – called with partial results while scanning
   * @returns {Promise<ScanResult>}
   */
  async runAndWait(type, target, opts = {}) {
    const { onProgress, ...scanOpts } = opts;
    const { scan_id } = await this[type](target, scanOpts);
    return this.c.pollUntilDone(
      () => this.getResult(scan_id),
      { onProgress }
    );
  }

  _opts(opts) {
    return {
      ports: opts.ports || '1-1000',
      script_group: opts.scriptGroup || 'vuln_basic',
      auto_remediate: opts.autoRemediate || false,
      deployment_context: opts.deploymentContext || null,
    };
  }
}


// ── OSINT ────────────────────────────────────────────────────────────────────

class OsintAPI {
  constructor(client) { this.c = client; }

  async full(domain)       { return this.c.post('/api/osint/full',       { domain }); }
  async subdomains(domain) { return this.c.post('/api/osint/subdomains', { domain }); }
  async dns(domain)        { return this.c.post('/api/osint/dns',        { domain }); }
  async whois(domain)      { return this.c.post('/api/osint/whois',      { domain }); }
  async cert(domain)       { return this.c.post('/api/osint/cert',       { domain }); }

  async getResult(scanId)  { return this.c.get(`/api/osint/${scanId}`); }

  async runAndWait(domain, { onProgress } = {}) {
    const { scan_id } = await this.full(domain);
    return this.c.pollUntilDone(() => this.getResult(scan_id), { onProgress });
  }
}


// ── Shadow IT ─────────────────────────────────────────────────────────────────

class ShadowItAPI {
  constructor(client) { this.c = client; }

  async discover(domain)  { return this.c.post('/api/shadow-it/discover', { domain }); }
  async getResult(scanId) { return this.c.get(`/api/shadow-it/${scanId}`); }

  async runAndWait(domain, { onProgress } = {}) {
    const { scan_id } = await this.discover(domain);
    return this.c.pollUntilDone(() => this.getResult(scan_id), { onProgress });
  }
}


// ── Remediation ───────────────────────────────────────────────────────────────

class RemediationAPI {
  constructor(client) { this.c = client; }

  /**
   * Generate a playbook for a single vulnerability.
   * @param {Object} vuln – {ip, port, service, cves, cvss_score, description, os, ...}
   */
  async generate(vuln) {
    return this.c.post('/api/remediation/generate', vuln);
  }

  /**
   * Generate playbooks for all vulns in a scan.
   * @param {string} scanId
   * @param {string} target
   * @param {Array}  vulnerabilities
   * @param {Object} [deploymentContext]
   */
  async generateBatch(scanId, target, vulnerabilities, deploymentContext = null) {
    return this.c.post('/api/remediation/generate-batch', {
      scan_id: scanId, target, vulnerabilities, deployment_context: deploymentContext
    });
  }

  async getPlaybook(playbookId)    { return this.c.get(`/api/remediation/${playbookId}`); }
  async getForScan(scanId)         { return this.c.get(`/api/remediation/scan/${scanId}`); }
  async downloadScript(playbookId) { return `${this.c.base}/api/remediation/${playbookId}/download`; }
  async downloadRollback(id)       { return `${this.c.base}/api/remediation/${id}/rollback`; }
}


// ── Reports ───────────────────────────────────────────────────────────────────

class ReportsAPI {
  constructor(client) { this.c = client; }

  async generate(scanId)    { return this.c.post(`/api/reports/generate/${scanId}`); }
  htmlUrl(scanId)           { return `${this.c.base}/api/reports/${scanId}/html`; }
  jsonUrl(scanId)           { return `${this.c.base}/api/reports/${scanId}/json`; }
  txtUrl(scanId)            { return `${this.c.base}/api/reports/${scanId}/txt`; }

  /** Analyse and enrich vulnerabilities with NVD CVE data. */
  async analyzeVulns(scanId, enrichCves = true) {
    return this.c.post(`/api/vulns/analyze/${scanId}?enrich_cves=${enrichCves}`);
  }
}


// ── Scheduling ─────────────────────────────────────────────────────────────────

class ScheduleAPI {
  constructor(client) { this.c = client; }

  async add(jobName, target, scanType, intervalHours = 24, autoRemediate = false) {
    return this.c.post('/api/schedule/add', {
      job_name: jobName, target, scan_type: scanType,
      interval_hours: intervalHours, auto_remediate: autoRemediate
    });
  }

  async list()           { return this.c.get('/api/schedule'); }
  async remove(jobId)    { return this.c.del(`/api/schedule/${jobId}`); }
}


// ── Usage examples ─────────────────────────────────────────────────────────────

/**
 * Example 1: Full vulnerability scan with auto-remediation
 *
 *   const api = new SecurityClient();
 *   const result = await api.scan.runAndWait('vulnerability', '192.168.1.1', {
 *     autoRemediate: true,
 *     deploymentContext: { type: 'ubuntu-server', extra: 'Ubuntu 22.04, nginx 1.24' },
 *     onProgress: (r) => console.log('Scanning...', r.status),
 *   });
 *   console.log('Hosts:', result.summary.hosts_up);
 *   console.log('Vulns:', result.summary.total_vulnerabilities);
 *
 * Example 2: OSINT + Shadow IT + generate report
 *
 *   const [osint, shadow] = await Promise.all([
 *     api.osint.runAndWait('example.com'),
 *     api.shadowIt.runAndWait('example.com'),
 *   ]);
 *   const report = await api.reports.generate(scanId);
 *   window.open(api.reports.htmlUrl(scanId), '_blank');
 *
 * Example 3: Schedule nightly scans
 *
 *   await api.schedule.add('Nightly Vuln Scan', '10.0.0.0/24', 'vulnerability', 24, true);
 *   const jobs = await api.schedule.list();
 */

export default SecurityClient;
