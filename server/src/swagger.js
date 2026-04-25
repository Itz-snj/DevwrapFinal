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
| **Phase 2** | ✅ Live | Detection & Correlation — Regex Vault, Attack Chains |
| **Phase 3** | ✅ Live | Incidents, Reports, WebSocket Live Monitor |
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
    },
    {
      name: 'Phase 2 — Detection & Correlation',
      description: 'Threat detection, event correlation, attack chain analysis, and IP intelligence'
    },
    {
      name: 'Phase 3 — Incidents & Reports',
      description: 'Incident management, forensic reports, timeline, blast radius graph, and real-time monitoring'
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
    },

    // ─── Phase 2: Detection ──────────────────────────────
    '/api/rules': {
      get: {
        tags: ['Phase 2 — Detection & Correlation'],
        summary: 'List loaded detection rules',
        description: 'Returns statistics about all loaded detection rules: total count, breakdown by type and category.',
        operationId: 'listRules',
        responses: {
          200: {
            description: 'Rule statistics',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    totalRules: { type: 'integer', example: 28 },
                    regexRules: { type: 'integer', example: 25 },
                    aggregationRules: { type: 'integer', example: 3 },
                    categories: { type: 'object', example: { 'SQL Injection': 9, 'XSS': 6, 'Path Traversal': 5 } }
                  }
                }
              }
            }
          }
        }
      }
    },

    '/api/detect-threats': {
      post: {
        tags: ['Phase 2 — Detection & Correlation'],
        summary: 'Detect threats in log content',
        description: 'Parses log content and runs all detection rules (regex + aggregation) against the events. Returns alerts grouped by severity and category.',
        operationId: 'detectThreats',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['content'],
                properties: {
                  content: { type: 'string', description: 'Raw log content' },
                  format: { type: 'string', enum: ['nginx', 'auth', 'json'] },
                  sourceFile: { type: 'string', example: 'access.log' }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Detection results',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    totalEvents: { type: 'integer' },
                    totalAlerts: { type: 'integer' },
                    alertsBySeverity: { type: 'object', example: { CRITICAL: 5, HIGH: 3, MEDIUM: 2, LOW: 0 } },
                    alertsByCategory: { type: 'object', example: { 'SQL Injection': 4, 'Path Traversal': 3 } },
                    alerts: { type: 'array', items: { $ref: '#/components/schemas/Alert' } }
                  }
                }
              }
            }
          }
        }
      }
    },

    '/api/correlate': {
      post: {
        tags: ['Phase 2 — Detection & Correlation'],
        summary: 'Correlate events across log sources',
        description: 'Parses → Detects → Correlates events. Groups by IP, builds attack chains using sliding window analysis, computes threat scores, and generates blast radius graph data.',
        operationId: 'correlateEvents',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['content'],
                properties: {
                  content: { type: 'string' },
                  format: { type: 'string', enum: ['nginx', 'auth', 'json'] },
                  sourceFile: { type: 'string' },
                  windowSeconds: { type: 'integer', description: 'Sliding window size in seconds (default: 300)', example: 300 }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Correlation results',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    totalEvents: { type: 'integer' },
                    totalAlerts: { type: 'integer' },
                    attackers: { type: 'array', items: { $ref: '#/components/schemas/AttackerProfile' } },
                    attackChains: { type: 'array', items: { type: 'object' } },
                    correlationAlerts: { type: 'array', items: { type: 'object' } },
                    graphData: { $ref: '#/components/schemas/GraphData' }
                  }
                }
              }
            }
          }
        }
      }
    },

    '/api/analyze/full': {
      post: {
        tags: ['Phase 2 — Detection & Correlation'],
        summary: 'Full analysis pipeline',
        description: 'Complete pipeline: Parse → Detect → Correlate → Enrich (IP geo) → Store as Incident. Returns a full incident report.',
        operationId: 'analyzeFullPipeline',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['content'],
                properties: {
                  content: { type: 'string', description: 'Raw log content' },
                  format: { type: 'string', enum: ['nginx', 'auth', 'json'] },
                  sourceFile: { type: 'string' },
                  enrichIps: { type: 'boolean', description: 'Enable IP geolocation enrichment (default: true)', default: true }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Full analysis results with incident ID',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    incidentId: { type: 'string', example: 'inc_1714039200000_abc123' },
                    format: { type: 'string' },
                    summary: { type: 'object' },
                    attackers: { type: 'array', items: { $ref: '#/components/schemas/AttackerProfile' } },
                    attackChains: { type: 'array', items: { type: 'object' } },
                    correlationAlerts: { type: 'array' },
                    graphData: { $ref: '#/components/schemas/GraphData' },
                    alertsBySeverity: { type: 'object' }
                  }
                }
              }
            }
          }
        }
      }
    },

    '/api/analyze/sample': {
      get: {
        tags: ['Phase 2 — Detection & Correlation'],
        summary: 'Analyze a bundled sample log file',
        description: 'Runs the full analysis pipeline on one of the bundled sample log files.',
        operationId: 'analyzeSampleLog',
        parameters: [
          {
            name: 'file',
            in: 'query',
            required: true,
            schema: { type: 'string', enum: ['nginx-access.log', 'auth.log', 'app-events.json'] }
          },
          {
            name: 'enrichIps',
            in: 'query',
            schema: { type: 'string', enum: ['true', 'false'], default: 'false' }
          }
        ],
        responses: {
          200: {
            description: 'Full analysis results for sample file'
          }
        }
      }
    },

    '/api/ip/{address}': {
      get: {
        tags: ['Phase 2 — Detection & Correlation'],
        summary: 'Lookup IP geolocation',
        description: 'Returns geolocation, ISP, and organization data for a given IP address. Uses ip-api.com with caching.',
        operationId: 'lookupIp',
        parameters: [
          {
            name: 'address',
            in: 'path',
            required: true,
            schema: { type: 'string', example: '8.8.8.8' },
            description: 'IP address to look up'
          }
        ],
        responses: {
          200: {
            description: 'IP intelligence data',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/IpIntelligence' }
              }
            }
          }
        }
      }
    },

    '/api/ip-cache/stats': {
      get: {
        tags: ['Phase 2 — Detection & Correlation'],
        summary: 'IP enrichment cache statistics',
        description: 'Returns cache size and rate limiting status for IP enrichment.',
        operationId: 'ipCacheStats',
        responses: {
          200: {
            description: 'Cache stats',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    cached: { type: 'integer', example: 5 },
                    requestsThisMinute: { type: 'integer', example: 3 },
                    rateLimit: { type: 'integer', example: 45 }
                  }
                }
              }
            }
          }
        }
      }
    },

    // ─── Phase 3: Incidents & Reports ────────────────────
    '/api/analyze': {
      post: {
        tags: ['Phase 3 — Incidents & Reports'],
        summary: 'Upload & analyze log files',
        description: 'Upload one or more log files via multipart form data. Runs the full pipeline: Parse → Detect → Correlate → Enrich → Store. Returns the incident with full analysis.',
        operationId: 'analyzeFiles',
        requestBody: {
          required: true,
          content: {
            'multipart/form-data': {
              schema: {
                type: 'object',
                required: ['files'],
                properties: {
                  files: {
                    type: 'array',
                    items: { type: 'string', format: 'binary' },
                    description: 'Log files to analyze (max 10)'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Analysis complete — incident created',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    incidentId: { type: 'string' },
                    files: { type: 'array', items: { type: 'object' } },
                    summary: { type: 'object' },
                    attackers: { type: 'array', items: { $ref: '#/components/schemas/AttackerProfile' } },
                    graphData: { $ref: '#/components/schemas/GraphData' }
                  }
                }
              }
            }
          }
        }
      }
    },

    '/api/incidents': {
      get: {
        tags: ['Phase 3 — Incidents & Reports'],
        summary: 'List all incidents',
        description: 'Returns summary of all stored incidents, sorted by creation time (newest first).',
        operationId: 'listIncidents',
        responses: {
          200: {
            description: 'Incident list',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    incidents: {
                      type: 'array',
                      items: {
                        type: 'object',
                        properties: {
                          id: { type: 'string' },
                          createdAt: { type: 'string', format: 'date-time' },
                          status: { type: 'string' },
                          threatScore: { type: 'number' },
                          totalAlerts: { type: 'integer' },
                          totalEvents: { type: 'integer' },
                          topAttackerIp: { type: 'string' }
                        }
                      }
                    },
                    total: { type: 'integer' }
                  }
                }
              }
            }
          }
        }
      }
    },

    '/api/incidents/{id}': {
      get: {
        tags: ['Phase 3 — Incidents & Reports'],
        summary: 'Get incident details',
        description: 'Returns full detail for a specific incident including summary, attackers, and alert breakdown.',
        operationId: 'getIncident',
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'Incident detail' },
          404: { description: 'Incident not found' }
        }
      },
      delete: {
        tags: ['Phase 3 — Incidents & Reports'],
        summary: 'Delete an incident',
        operationId: 'deleteIncident',
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'Incident deleted' },
          404: { description: 'Incident not found' }
        }
      }
    },

    '/api/incidents/{id}/timeline': {
      get: {
        tags: ['Phase 3 — Incidents & Reports'],
        summary: 'Get event timeline',
        description: 'Returns paginated, chronologically sorted events for an incident. Each event is enriched with any alerts it triggered.',
        operationId: 'getIncidentTimeline',
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
          { name: 'pageSize', in: 'query', schema: { type: 'integer', default: 100 } }
        ],
        responses: {
          200: {
            description: 'Paginated timeline',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    events: { type: 'array', items: { $ref: '#/components/schemas/NormalizedEvent' } },
                    totalEvents: { type: 'integer' },
                    page: { type: 'integer' },
                    pageSize: { type: 'integer' },
                    totalPages: { type: 'integer' }
                  }
                }
              }
            }
          }
        }
      }
    },

    '/api/incidents/{id}/graph': {
      get: {
        tags: ['Phase 3 — Incidents & Reports'],
        summary: 'Get blast radius graph',
        description: 'Returns the blast radius graph data (nodes + edges) for D3/force-graph visualization.',
        operationId: 'getIncidentGraph',
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: {
            description: 'Graph data',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/GraphData' } } }
          }
        }
      }
    },

    '/api/incidents/{id}/report': {
      get: {
        tags: ['Phase 3 — Incidents & Reports'],
        summary: 'Download forensic report',
        description: 'Generates and downloads a forensic incident report. Supports Markdown and PDF formats.',
        operationId: 'downloadReport',
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'format', in: 'query', schema: { type: 'string', enum: ['md', 'pdf'], default: 'md' } }
        ],
        responses: {
          200: {
            description: 'Report file download',
            content: {
              'text/markdown': { schema: { type: 'string' } },
              'application/pdf': { schema: { type: 'string', format: 'binary' } }
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
      },
      Alert: {
        type: 'object',
        description: 'A security alert triggered by a detection rule.',
        properties: {
          id: { type: 'string', example: 'alert_1714039200_xyz' },
          ruleId: { type: 'string', example: 'SQLI_UNION_SELECT' },
          category: { type: 'string', example: 'SQL Injection' },
          severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
          description: { type: 'string' },
          matchedPattern: { type: 'string', example: 'UNION SELECT' },
          timestamp: { type: 'string', format: 'date-time' },
          event: { $ref: '#/components/schemas/NormalizedEvent' }
        }
      },
      AttackerProfile: {
        type: 'object',
        description: 'Profile of a suspected attacker IP with aggregated intelligence.',
        properties: {
          ip: { type: 'string', example: '192.168.1.105' },
          threatScore: { type: 'number', example: 85 },
          totalRequests: { type: 'integer', example: 45 },
          attackTypes: { type: 'array', items: { type: 'string' }, example: ['SQL Injection', 'Brute Force'] },
          targetedEndpoints: { type: 'array', items: { type: 'string' } },
          firstSeen: { type: 'string', format: 'date-time' },
          lastSeen: { type: 'string', format: 'date-time' },
          geo: {
            type: 'object',
            properties: {
              country: { type: 'string', example: 'Private Network' },
              city: { type: 'string' },
              lat: { type: 'number' },
              lon: { type: 'number' }
            }
          }
        }
      },
      IpIntelligence: {
        type: 'object',
        description: 'Geolocation and ISP data for an IP address.',
        properties: {
          ip: { type: 'string', example: '8.8.8.8' },
          geo: {
            type: 'object',
            properties: {
              country: { type: 'string', example: 'United States' },
              city: { type: 'string', example: 'Mountain View' },
              lat: { type: 'number', example: 37.386 },
              lon: { type: 'number', example: -122.0838 }
            }
          },
          isp: { type: 'string', example: 'Google LLC' },
          org: { type: 'string', example: 'Google Public DNS' },
          as: { type: 'string' },
          isPrivate: { type: 'boolean', example: false },
          cached: { type: 'boolean', example: false }
        }
      },
      GraphData: {
        type: 'object',
        description: 'Blast radius graph data for visualization (nodes = IPs/endpoints/resources, edges = connections).',
        properties: {
          nodes: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                id: { type: 'string' },
                type: { type: 'string', enum: ['attacker', 'endpoint', 'resource'] },
                label: { type: 'string' },
                threatScore: { type: 'number' }
              }
            }
          },
          edges: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                source: { type: 'string' },
                target: { type: 'string' },
                weight: { type: 'integer' },
                severity: { type: 'string' }
              }
            }
          }
        }
      }
    }
  }
};
