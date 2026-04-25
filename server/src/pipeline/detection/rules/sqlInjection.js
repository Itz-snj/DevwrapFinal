/**
 * Project Phoenix — SQL Injection Detection Rules
 * 
 * Detects common SQL injection patterns including:
 *   - UNION-based injection
 *   - Tautology attacks (OR 1=1)
 *   - Stacked queries
 *   - Comment-based bypass
 *   - Blind SQL injection probes
 */

export default [
  {
    id: 'SQLI_UNION_SELECT',
    category: 'SQL Injection',
    severity: 'CRITICAL',
    description: 'UNION SELECT injection — attempts to extract data from other tables',
    pattern: /\bUNION\b[\s/\*]+\bSELECT\b/gi,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'SQLI_TAUTOLOGY',
    category: 'SQL Injection',
    severity: 'CRITICAL',
    description: 'Tautology-based SQL injection (OR 1=1, OR true)',
    pattern: /['"]?\s*\bOR\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/gi,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'SQLI_DROP_TABLE',
    category: 'SQL Injection',
    severity: 'CRITICAL',
    description: 'DROP TABLE attempt — destructive SQL command',
    pattern: /\bDROP\b\s+\bTABLE\b/gi,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'SQLI_INSERT_INTO',
    category: 'SQL Injection',
    severity: 'HIGH',
    description: 'INSERT INTO attempt — data manipulation via injection',
    pattern: /\bINSERT\b\s+\bINTO\b/gi,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'SQLI_DELETE_FROM',
    category: 'SQL Injection',
    severity: 'CRITICAL',
    description: 'DELETE FROM attempt — destructive data operation',
    pattern: /\bDELETE\b\s+\bFROM\b/gi,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'SQLI_COMMENT_BYPASS',
    category: 'SQL Injection',
    severity: 'HIGH',
    description: 'SQL comment injection — used to bypass query logic',
    pattern: /('|")\s*;\s*--/g,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'SQLI_SLEEP_BENCHMARK',
    category: 'SQL Injection',
    severity: 'HIGH',
    description: 'Time-based blind SQL injection (SLEEP/BENCHMARK)',
    pattern: /\b(SLEEP|BENCHMARK|WAITFOR\s+DELAY)\s*\(/gi,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'SQLI_INFORMATION_SCHEMA',
    category: 'SQL Injection',
    severity: 'CRITICAL',
    description: 'Information schema access — database enumeration attempt',
    pattern: /\bINFORMATION_SCHEMA\b/gi,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'SQLI_CONCAT_HEX',
    category: 'SQL Injection',
    severity: 'HIGH',
    description: 'CONCAT/HEX function injection — data exfiltration technique',
    pattern: /\b(CONCAT|CHAR|HEX|UNHEX|LOAD_FILE)\s*\(/gi,
    fields: ['endpoint', 'rawLine']
  }
];
