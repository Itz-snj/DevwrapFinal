/**
 * Project Phoenix — XSS (Cross-Site Scripting) Detection Rules
 * 
 * Detects common XSS payload patterns in request endpoints,
 * query parameters, and log content.
 */

export default [
  {
    id: 'XSS_SCRIPT_TAG',
    category: 'XSS',
    severity: 'HIGH',
    description: 'Script tag injection — classic XSS attack vector',
    pattern: /<\s*script[^>]*>/gi,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'XSS_EVENT_HANDLER',
    category: 'XSS',
    severity: 'HIGH',
    description: 'HTML event handler injection (onerror, onload, onclick)',
    pattern: /\bon(error|load|click|mouseover|focus|blur|submit|change)\s*=/gi,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'XSS_JAVASCRIPT_URI',
    category: 'XSS',
    severity: 'HIGH',
    description: 'JavaScript URI injection (javascript:)',
    pattern: /javascript\s*:/gi,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'XSS_IMG_TAG',
    category: 'XSS',
    severity: 'MEDIUM',
    description: 'IMG tag with event handler — image-based XSS',
    pattern: /<\s*img[^>]+on\w+\s*=/gi,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'XSS_SVG_TAG',
    category: 'XSS',
    severity: 'MEDIUM',
    description: 'SVG tag injection — vector for XSS via embedded scripts',
    pattern: /<\s*svg[^>]*on\w+\s*=/gi,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'XSS_DATA_URI',
    category: 'XSS',
    severity: 'MEDIUM',
    description: 'Data URI injection — can embed executable content',
    pattern: /data\s*:\s*text\/html/gi,
    fields: ['endpoint', 'rawLine']
  }
];
