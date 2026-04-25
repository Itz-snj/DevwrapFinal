/**
 * Project Phoenix — IP Intelligence Enricher
 * 
 * Enriches attacker profiles with geolocation data from ip-api.com.
 * Features:
 *   - In-memory cache to avoid redundant API calls
 *   - Rate limiting (45 req/min for free tier)
 *   - Graceful fallback if API is unreachable
 *   - Skips private/reserved IP ranges
 */

/**
 * Check if an IP is private (RFC 1918) or reserved.
 */
function isPrivateIp(ip) {
  if (!ip) return true;
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return true;

  // 10.0.0.0/8
  if (parts[0] === 10) return true;
  // 172.16.0.0/12
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  // 192.168.0.0/16
  if (parts[0] === 192 && parts[1] === 168) return true;
  // 127.0.0.0/8 (loopback)
  if (parts[0] === 127) return true;
  // 0.0.0.0
  if (parts.every(p => p === 0)) return true;

  return false;
}

export class IpEnricher {
  constructor(options = {}) {
    /** @type {Map<string, Object>} IP → geo data cache */
    this.cache = new Map();
    /** @type {string} API base URL */
    this.apiUrl = options.apiUrl || 'http://ip-api.com/json';
    /** @type {number} Rate limit (requests per minute) */
    this.rateLimit = options.rateLimit || 45;
    /** @type {number} Request count in current window */
    this.requestCount = 0;
    /** @type {number} Window start timestamp */
    this.windowStart = Date.now();
    /** @type {number} Request timeout in ms */
    this.timeout = options.timeout || 5000;
  }

  /**
   * Enrich a single IP with geolocation data.
   * @param {string} ip
   * @returns {Promise<Object>} Geo data object
   */
  async enrich(ip) {
    // Return cached if available
    if (this.cache.has(ip)) {
      return { ...this.cache.get(ip), cached: true };
    }

    // Skip private IPs
    if (isPrivateIp(ip)) {
      const privateData = {
        ip,
        geo: { country: 'Private Network', city: 'N/A', lat: 0, lon: 0 },
        isp: 'Private/Reserved',
        org: 'Internal Network',
        as: 'N/A',
        isPrivate: true,
        cached: false
      };
      this.cache.set(ip, privateData);
      return privateData;
    }

    // Rate limit check
    if (!this._checkRateLimit()) {
      return this._fallbackData(ip, 'Rate limit exceeded');
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeout);

      const response = await fetch(`${this.apiUrl}/${ip}?fields=status,message,country,city,lat,lon,isp,org,as`, {
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (!response.ok) {
        return this._fallbackData(ip, `HTTP ${response.status}`);
      }

      const data = await response.json();
      this.requestCount++;

      if (data.status === 'fail') {
        return this._fallbackData(ip, data.message || 'API returned failure');
      }

      const enriched = {
        ip,
        geo: {
          country: data.country || 'Unknown',
          city: data.city || 'Unknown',
          lat: data.lat || 0,
          lon: data.lon || 0
        },
        isp: data.isp || 'Unknown',
        org: data.org || 'Unknown',
        as: data.as || 'Unknown',
        isPrivate: false,
        cached: false
      };

      this.cache.set(ip, enriched);
      return enriched;
    } catch (err) {
      return this._fallbackData(ip, err.message);
    }
  }

  /**
   * Enrich multiple IPs in batch with rate limiting.
   * @param {string[]} ips - Array of IP addresses.
   * @returns {Promise<Map<string, Object>>}
   */
  async enrichBatch(ips) {
    const uniqueIps = [...new Set(ips)];
    const results = new Map();

    for (const ip of uniqueIps) {
      const data = await this.enrich(ip);
      results.set(ip, data);

      // Small delay between requests to respect rate limits
      if (!data.cached && !data.isPrivate) {
        await new Promise(r => setTimeout(r, 100));
      }
    }

    return results;
  }

  /**
   * Enrich attacker profiles in-place.
   * @param {AttackerProfile[]} attackers
   * @returns {Promise<AttackerProfile[]>}
   */
  async enrichAttackers(attackers) {
    for (const attacker of attackers) {
      const geoData = await this.enrich(attacker.ip);
      attacker.geo = geoData.geo;
      // Attach full enrichment data to metadata-like fields
      attacker.isp = geoData.isp;
      attacker.org = geoData.org;
      attacker.as = geoData.as;
      attacker.isPrivateIp = geoData.isPrivate;
    }
    return attackers;
  }

  /**
   * Check if we're within rate limits.
   * Resets the counter every 60 seconds.
   */
  _checkRateLimit() {
    const now = Date.now();
    if (now - this.windowStart > 60000) {
      this.requestCount = 0;
      this.windowStart = now;
    }
    return this.requestCount < this.rateLimit;
  }

  /**
   * Return fallback data when API is unavailable.
   */
  _fallbackData(ip, reason) {
    const fallback = {
      ip,
      geo: { country: 'Unavailable', city: 'Unavailable', lat: 0, lon: 0 },
      isp: 'Unavailable',
      org: 'Unavailable',
      as: 'Unavailable',
      isPrivate: false,
      cached: false,
      enrichmentError: reason
    };
    // Cache fallback too (avoid repeated failed requests)
    this.cache.set(ip, fallback);
    return fallback;
  }

  /**
   * Get cache statistics.
   */
  getCacheStats() {
    return {
      cached: this.cache.size,
      requestsThisMinute: this.requestCount,
      rateLimit: this.rateLimit
    };
  }

  /**
   * Clear the cache.
   */
  clearCache() {
    this.cache.clear();
    this.requestCount = 0;
  }
}
