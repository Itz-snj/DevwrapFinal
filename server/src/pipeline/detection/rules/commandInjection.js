/**
 * Project Phoenix — Command Injection Detection Rules
 * 
 * Detects OS command injection patterns — attempts to execute
 * system commands via web application inputs.
 */

export default [
  {
    id: 'CMDI_SEMICOLON',
    category: 'Command Injection',
    severity: 'CRITICAL',
    description: 'Command chaining via semicolon — attempts to execute additional commands',
    pattern: /;\s*(ls|cat|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|perl|ruby|php)\b/gi,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'CMDI_PIPE',
    category: 'Command Injection',
    severity: 'CRITICAL',
    description: 'Command piping — redirecting output to another command',
    pattern: /\|\s*(cat|head|tail|less|more|grep|awk|sed|sort|bash|sh)\b/gi,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'CMDI_BACKTICK',
    category: 'Command Injection',
    severity: 'CRITICAL',
    description: 'Backtick command execution — subshell command injection',
    pattern: /`[^`]+`/g,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'CMDI_DOLLAR_PAREN',
    category: 'Command Injection',
    severity: 'CRITICAL',
    description: '$() command substitution — subshell injection',
    pattern: /\$\([^)]+\)/g,
    fields: ['endpoint', 'rawLine']
  },
  {
    id: 'CMDI_REVERSE_SHELL',
    category: 'Command Injection',
    severity: 'CRITICAL',
    description: 'Reverse shell attempt — connecting back to attacker',
    pattern: /(\/dev\/tcp\/|nc\s+-[elp]|bash\s+-i\s+>|mkfifo|\/bin\/sh\s+-i)/gi,
    fields: ['endpoint', 'rawLine']
  }
];
