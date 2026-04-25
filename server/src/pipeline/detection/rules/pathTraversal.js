/**
 * Project Phoenix — Path Traversal Detection Rules
 * 
 * Detects attempts to access files outside the web root using
 * relative path sequences (../) and sensitive file paths.
 */

export default [
  {
    id: 'PATH_TRAVERSAL_DOTDOT',
    category: 'Path Traversal',
    severity: 'CRITICAL',
    description: 'Directory traversal using ../ sequences — attempts to access files outside web root',
    pattern: /(\.\.\/|\.\.\\){2,}/g,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'PATH_TRAVERSAL_ETC_PASSWD',
    category: 'Path Traversal',
    severity: 'CRITICAL',
    description: 'Attempt to access /etc/passwd — system user enumeration',
    pattern: /\/etc\/(passwd|shadow|hosts|group)/gi,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'PATH_TRAVERSAL_PROC',
    category: 'Path Traversal',
    severity: 'HIGH',
    description: 'Attempt to access /proc filesystem — system information disclosure',
    pattern: /\/proc\/(self|version|cpuinfo|meminfo|net)/gi,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'PATH_TRAVERSAL_WIN',
    category: 'Path Traversal',
    severity: 'HIGH',
    description: 'Windows path traversal — boot.ini, win.ini access attempt',
    pattern: /(boot\.ini|win\.ini|system32|windows\\system)/gi,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'PATH_TRAVERSAL_SENSITIVE_FILES',
    category: 'Path Traversal',
    severity: 'HIGH',
    description: 'Attempt to access sensitive application files',
    pattern: /\.(env|htaccess|htpasswd|git\/config|ssh\/|id_rsa|authorized_keys)/gi,
    fields: ['endpoint', 'rawLine']
  }
];
