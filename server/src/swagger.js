/**
 * Project Phoenix — OpenAPI / Swagger Specification
 * 
 * Living documentation that grows with each phase.
 * Served at /api-docs via swagger-ui-express.
 */

export const swaggerSpec = {
  openapi: '3.0.3',
  info: {
    title: 'Project Phoenix API',
    description: `
**Automated Log Correlation & Incident Forensics Dashboard**

Project Phoenix parses, correlates, and visualizes security-relevant events 
across multiple log sources using deterministic, rule-based logic.

### Phases
| Phase | Status | Description |
|-------|--------|-------------|
| **Phase 1** | ✅ Live | Foundation — Parsing, Deobfuscation, Format Detection |
| **Phase 2** | 🔜 | Detection & Correlation — Regex Vault, Attack Chains |
| **Phase 3** | 🔜 | Full Analysis Pipeline — Upload & Analyze |
| **Phase 4** | 🔜 | Report Generation — PDF/Markdown |
    `,
    version: '1.0.0',
    contact: {
      name: 'Project Phoenix',
    }
  },
  servers: [
    {
      url: 'http://localhost:3001',
      description: 'Local development server'
    }
  ],
  tags: [
    {
      name: 'Health',
      description: 'Server health check'
    },
    {
      name: 'Phase 1 — Parsing',
      description: 'Log ingestion, format detection, and deobfuscation'
    }
  ],
  paths: {
    // ─── Health ───────────────────────────────────────────
    '/api/health': {
      get: {
        tags: ['Health'],
        summary: 'Server health check',
        description: 'Returns server status, version, and uptime.',
        operationId: 'healthCheck',
        responses: {
          200: {
            description: 'Server is healthy',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    status: { type: 'string', example: 'ok' },
                    service: { type: 'string', example: 'Project Phoenix' },
                    version: { type: 'string', example: '1.0.0' },
                    uptime: { type: 'number', example: 42.5 },
                    timestamp: { type: 'string', format: 'date-time' }
                  }
                }
              }
            }
          }
        }
      }
    },

    // ─── Phase 1: Format Detection ───────────────────────
    '/api/formats': {
      get: {
        tags: ['Phase 1 — Parsing'],
        summary: 'List supported log formats',
        description: 'Returns all log formats the parser factory can handle.',
        operationId: 'listFormats',
        responses: {
          200: {
            description: 'Supported formats',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    formats: {
                      type: 'array',
                      items: { type: 'string' },
                      example: ['nginx', 'auth', 'json']
                    }
                  }
                }
              }
            }
          }
        }
      }
    },

    '/api/detect': {
      post: {
        tags: ['Phase 1 — Parsing'],
        summary: 'Auto-detect log format',
        description: 'Analyzes the provided log content and returns the detected format with confidence score. Does NOT parse the full content.',
        operationId: 'detectFormat',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['content'],
                properties: {
                  content: {
                    type: 'string',
                    description: 'Raw log content (first few lines are sufficient)',
                    example: '192.168.1.105 - - [25/Apr/2026:08:02:15 +0000] "GET /admin HTTP/1.1" 403 256 "-" "Mozilla/5.0"'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Format detected successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    format: { type: 'string', example: 'nginx' },
                    confidence: { type: 'number', example: 100 }
                  }
                }
              }
            }
          },
          400: {
            description: 'Could not detect format',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Error' }
              }
            }
          }
        }
      }
    },

    // ─── Phase 1: Parsing ────────────────────────────────
    '/api/parse': {
      post: {
        tags: ['Phase 1 — Parsing'],
        summary: 'Parse log content into normalized events',
        description: `Parses raw log content and returns an array of NormalizedEvents. 
        
Supports:
- **Auto-detection**: Omit \`format\` to auto-detect
- **Manual format**: Set \`format\` to \`nginx\`, \`auth\`, or \`json\`

The parser automatically deobfuscates URL-encoded, Base64, and Unicode payloads before returning events.`,
        operationId: 'parseLogs',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['content'],
                properties: {
                  content: {
                    type: 'string',
                    description: 'Raw log file content'
                  },
                  format: {
                    type: 'string',
                    enum: ['nginx', 'auth', 'json'],
                    description: 'Log format. Omit for auto-detection.'
                  },
                  sourceFile: {
                    type: 'string',
                    description: 'Original filename (for metadata)',
                    example: 'access.log'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Parsed events',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    format: { type: 'string', example: 'nginx' },
                    confidence: { type: 'number', example: 100 },
                    totalEvents: { type: 'integer', example: 23 },
                    events: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/NormalizedEvent' }
                    }
                  }
                }
              }
            }
          },
          400: {
            description: 'Parse error',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Error' }
              }
            }
          }
        }
      }
    },

    '/api/parse/file': {
      post: {
        tags: ['Phase 1 — Parsing'],
        summary: 'Upload and parse a log file',
        description: 'Upload a log file via multipart form data. The format is auto-detected. Returns parsed NormalizedEvents.',
        operationId: 'parseLogFile',
        requestBody: {
          required: true,
          content: {
            'multipart/form-data': {
              schema: {
                type: 'object',
                required: ['file'],
                properties: {
                  file: {
                    type: 'string',
                    format: 'binary',
                    description: 'Log file to parse'
                  },
                  format: {
                    type: 'string',
                    enum: ['nginx', 'auth', 'json'],
                    description: 'Log format. Omit for auto-detection.'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Parsed events from uploaded file',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    filename: { type: 'string', example: 'access.log' },
                    format: { type: 'string', example: 'nginx' },
                    confidence: { type: 'number', example: 100 },
                    totalEvents: { type: 'integer', example: 23 },
                    events: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/NormalizedEvent' }
                    }
                  }
                }
              }
            }
          },
          400: {
            description: 'No file uploaded or parse error',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Error' }
              }
            }
          }
        }
      }
    },

    // ─── Phase 1: Deobfuscation ──────────────────────────
    '/api/deobfuscate': {
      post: {
        tags: ['Phase 1 — Parsing'],
        summary: 'Deobfuscate an encoded string',
        description: `Runs the full deobfuscation pipeline on the input:

1. **URL decode** (handles double/triple encoding)
2. **Base64 decode** (auto-detects Base64 segments)
3. **Unicode normalize** (\\\\uXXXX, \\\\xXX sequences)
4. **HTML entity decode** (&amp;, &#x27;, etc.)

Useful for testing how the pipeline handles encoded attack payloads.`,
        operationId: 'deobfuscate',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['input'],
                properties: {
                  input: {
                    type: 'string',
                    description: 'Encoded/obfuscated string',
                    example: '%2e%2e/%2e%2e/etc/passwd'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Deobfuscated result',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    input: { type: 'string', example: '%2e%2e/%2e%2e/etc/passwd' },
                    output: { type: 'string', example: '../../etc/passwd' },
                    changed: { type: 'boolean', example: true }
                  }
                }
              }
            }
          }
        }
      }
    },

    '/api/parse/sample': {
      get: {
        tags: ['Phase 1 — Parsing'],
        summary: 'Parse a bundled sample log file',
        description: 'Parses one of the sample log files shipped with the project. Useful for quick testing without uploading.',
        operationId: 'parseSampleLog',
        parameters: [
          {
            name: 'file',
            in: 'query',
            required: true,
            schema: {
              type: 'string',
              enum: ['nginx-access.log', 'auth.log', 'app-events.json']
            },
            description: 'Sample file to parse'
          }
        ],
        responses: {
          200: {
            description: 'Parsed events from sample file',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    filename: { type: 'string' },
                    format: { type: 'string' },
                    confidence: { type: 'number' },
                    totalEvents: { type: 'integer' },
                    events: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/NormalizedEvent' }
                    }
                  }
                }
              }
            }
          },
          400: {
            description: 'Invalid sample file name',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Error' }
              }
            }
          }
        }
      }
    }
  },

  components: {
    schemas: {
      NormalizedEvent: {
        type: 'object',
        description: 'Universal log entry format — every parser outputs events in this shape.',
        properties: {
          timestamp: { type: 'string', format: 'date-time', example: '2026-04-25T08:02:15.000Z' },
          source: { type: 'string', enum: ['nginx', 'auth', 'app'], example: 'nginx' },
          sourceFile: { type: 'string', example: 'access.log' },
          ip: { type: 'string', example: '192.168.1.105' },
          method: { type: 'string', example: 'GET' },
          endpoint: { type: 'string', example: '/admin/config' },
          statusCode: { type: 'integer', nullable: true, example: 403 },
          logLevel: { type: 'string', enum: ['info', 'warn', 'error', 'debug'], example: 'warn' },
          userAgent: { type: 'string', example: 'Mozilla/5.0 (X11; Linux x86_64)' },
          user: { type: 'string', example: 'admin' },
          rawLine: { type: 'string', description: 'Original raw log line' },
          lineNumber: { type: 'integer', example: 1 },
          metadata: {
            type: 'object',
            description: 'Additional fields from the source log',
            additionalProperties: true
          }
        }
      },
      Error: {
        type: 'object',
        properties: {
          error: { type: 'string', example: 'Could not auto-detect log format' }
        }
      }
    }
  }
};
