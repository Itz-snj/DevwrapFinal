/**
 * Project Phoenix — Parser Factory
 * 
 * Auto-detects log format from the first few lines and returns
 * the appropriate parser. Falls back to best-guess if ambiguous.
 * 
 * Supported formats:
 *   - Nginx access logs (combined format)
 *   - Linux auth.log (syslog format)
 *   - JSON application logs (newline-delimited JSON)
 */

import { NginxParser } from './NginxParser.js';
import { AuthLogParser } from './AuthLogParser.js';
import { JsonLogParser } from './JsonLogParser.js';

/**
 * Number of lines to sample for format detection.
 */
const SAMPLE_SIZE = 10;

/**
 * Minimum confidence threshold (%) to accept a format.
 */
const CONFIDENCE_THRESHOLD = 50;

export class ParserFactory {
  constructor() {
    /** @type {Map<string, {parserClass: any, detect: function}>} */
    this.registry = new Map([
      ['nginx', { ParserClass: NginxParser, detect: NginxParser.detect }],
      ['auth', { ParserClass: AuthLogParser, detect: AuthLogParser.detect }],
      ['json', { ParserClass: JsonLogParser, detect: JsonLogParser.detect }]
    ]);
  }

  /**
   * Detect the log format and return the appropriate parser.
   * @param {string} content - Full file content.
   * @returns {{ parser: NginxParser|AuthLogParser|JsonLogParser, format: string, confidence: number }}
   */
  detect(content) {
    const allNonEmpty = content.split('\n').filter(l => l.trim());
    const smallSample = allNonEmpty.slice(0, SAMPLE_SIZE);
    // For JSON detection, we need more lines since objects can be multi-line
    const largeSample = allNonEmpty.slice(0, 50);
    
    if (smallSample.length === 0) {
      throw new Error('Empty log file — no lines to analyze');
    }

    let bestMatch = { format: null, confidence: 0, ParserClass: null };

    for (const [format, { ParserClass, detect }] of this.registry) {
      // Give JSON parser the larger sample so multi-line objects are visible
      const sample = format === 'json' ? largeSample : smallSample;
      const confidence = detect(sample);
      if (confidence > bestMatch.confidence) {
        bestMatch = { format, confidence, ParserClass };
      }
    }

    if (!bestMatch.format || bestMatch.confidence < CONFIDENCE_THRESHOLD) {
      throw new Error(
        `Could not auto-detect log format. Best guess: ${bestMatch.format || 'none'} ` +
        `(confidence: ${bestMatch.confidence}%). ` +
        `Minimum required: ${CONFIDENCE_THRESHOLD}%. ` +
        `Supported formats: ${[...this.registry.keys()].join(', ')}`
      );
    }

    return {
      parser: new bestMatch.ParserClass(),
      format: bestMatch.format,
      confidence: bestMatch.confidence
    };
  }

  /**
   * Detect format and parse the file in one call.
   * @param {string} content - Full file content.
   * @param {string} sourceFile - Filename for metadata.
   * @returns {{ events: NormalizedEvent[], format: string, confidence: number }}
   */
  parseAuto(content, sourceFile = '') {
    const { parser, format, confidence } = this.detect(content);
    const events = parser.parse(content, sourceFile);
    return { events, format, confidence };
  }

  /**
   * Parse with a specific format (bypass auto-detection).
   * @param {string} format - 'nginx' | 'auth' | 'json'
   * @param {string} content
   * @param {string} sourceFile
   * @returns {NormalizedEvent[]}
   */
  parseWithFormat(format, content, sourceFile = '') {
    const entry = this.registry.get(format);
    if (!entry) {
      throw new Error(`Unknown format: ${format}. Supported: ${[...this.registry.keys()].join(', ')}`);
    }
    const parser = new entry.ParserClass();
    return parser.parse(content, sourceFile);
  }

  /**
   * Register a custom parser.
   * @param {string} format - Format name.
   * @param {function} ParserClass - Parser class with static detect() and instance parse().
   */
  register(format, ParserClass) {
    this.registry.set(format, {
      ParserClass,
      detect: ParserClass.detect
    });
  }

  /**
   * Get list of supported formats.
   * @returns {string[]}
   */
  getSupportedFormats() {
    return [...this.registry.keys()];
  }
}
