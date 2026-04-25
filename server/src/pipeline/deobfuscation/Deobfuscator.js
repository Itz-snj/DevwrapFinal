/**
 * Project Phoenix — Deobfuscation Layer
 * 
 * Preprocesses raw log entries to decode obfuscated payloads before
 * regex-based detection. This ensures encoded attack patterns
 * (e.g., %2e%2e%2f → ../../) are caught by the Regex Vault.
 * 
 * Pipeline: Raw → URL decode → Base64 decode → Unicode normalize → Clean
 */

/**
 * Decode URL-encoded strings (%XX → character).
 * Handles double-encoding (e.g., %252e → %2e → .).
 * @param {string} input
 * @returns {string}
 */
function urlDecode(input) {
  if (!input || typeof input !== 'string') return input;
  
  let decoded = input;
  let prev = '';

  // Iteratively decode until stable (handles double/triple encoding)
  let maxIterations = 3;
  while (decoded !== prev && maxIterations-- > 0) {
    prev = decoded;
    try {
      decoded = decodeURIComponent(decoded);
    } catch {
      // If decodeURIComponent fails (malformed), try manual replacement
      decoded = decoded.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => {
        return String.fromCharCode(parseInt(hex, 16));
      });
      break;
    }
  }

  return decoded;
}

/**
 * Detect and decode Base64-encoded segments within a string.
 * Only decodes segments that look like Base64 (min 8 chars, valid charset).
 * @param {string} input
 * @returns {string}
 */
function base64Decode(input) {
  if (!input || typeof input !== 'string') return input;

  // Match potential Base64 strings (min 8 chars, valid Base64 charset, optional padding)
  const base64Regex = /(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])/g;

  return input.replace(base64Regex, (match) => {
    try {
      const decoded = Buffer.from(match, 'base64').toString('utf-8');
      // Only accept if the decoded result is mostly printable ASCII
      const printableRatio = (decoded.match(/[\x20-\x7E]/g) || []).length / decoded.length;
      if (printableRatio > 0.8 && decoded.length > 2) {
        return decoded;
      }
    } catch {
      // Not valid Base64, return original
    }
    return match;
  });
}

/**
 * Normalize Unicode escape sequences (\uXXXX, \xXX).
 * @param {string} input
 * @returns {string}
 */
function unicodeNormalize(input) {
  if (!input || typeof input !== 'string') return input;

  // Decode \uXXXX sequences
  let result = input.replace(/\\u([0-9A-Fa-f]{4})/g, (_, code) => {
    return String.fromCharCode(parseInt(code, 16));
  });

  // Decode \xXX sequences
  result = result.replace(/\\x([0-9A-Fa-f]{2})/g, (_, code) => {
    return String.fromCharCode(parseInt(code, 16));
  });

  return result;
}

/**
 * Normalize HTML entities (&#xXX;, &#DDD;, &amp;, &lt;, etc).
 * @param {string} input
 * @returns {string}
 */
function htmlEntityDecode(input) {
  if (!input || typeof input !== 'string') return input;

  const entityMap = {
    '&amp;': '&',
    '&lt;': '<',
    '&gt;': '>',
    '&quot;': '"',
    '&#39;': "'",
    '&apos;': "'"
  };

  let result = input;

  // Named entities
  for (const [entity, char] of Object.entries(entityMap)) {
    result = result.replaceAll(entity, char);
  }

  // Hex numeric entities: &#xXX;
  result = result.replace(/&#x([0-9A-Fa-f]+);/g, (_, hex) => {
    return String.fromCharCode(parseInt(hex, 16));
  });

  // Decimal numeric entities: &#DDD;
  result = result.replace(/&#(\d+);/g, (_, dec) => {
    return String.fromCharCode(parseInt(dec, 10));
  });

  return result;
}

/**
 * Deobfuscator — Runs the full deobfuscation pipeline on a string.
 * 
 * Order matters: URL decode first (most common encoding in logs),
 * then Base64, then Unicode escapes, then HTML entities.
 */
export class Deobfuscator {
  constructor() {
    /** @type {Array<{name: string, fn: function}>} Transform chain */
    this.transforms = [
      { name: 'urlDecode', fn: urlDecode },
      { name: 'base64Decode', fn: base64Decode },
      { name: 'unicodeNormalize', fn: unicodeNormalize },
      { name: 'htmlEntityDecode', fn: htmlEntityDecode }
    ];
  }

  /**
   * Run all transforms on a raw log line.
   * @param {string} rawLine - The raw log line to deobfuscate.
   * @returns {string} The deobfuscated log line.
   */
  deobfuscate(rawLine) {
    if (!rawLine || typeof rawLine !== 'string') return rawLine;

    let result = rawLine;
    for (const { fn } of this.transforms) {
      result = fn(result);
    }
    return result;
  }

  /**
   * Deobfuscate a specific field value (e.g., endpoint, query).
   * @param {string} value
   * @returns {string}
   */
  deobfuscateField(value) {
    return this.deobfuscate(value);
  }

  /**
   * Add a custom transform to the pipeline.
   * @param {string} name - Name for debugging/logging.
   * @param {function} fn - Transform function (string → string).
   * @param {number} [position] - Position to insert (default: end of chain).
   */
  addTransform(name, fn, position) {
    const transform = { name, fn };
    if (position !== undefined) {
      this.transforms.splice(position, 0, transform);
    } else {
      this.transforms.push(transform);
    }
  }
}

// Export individual transforms for testing
export { urlDecode, base64Decode, unicodeNormalize, htmlEntityDecode };
