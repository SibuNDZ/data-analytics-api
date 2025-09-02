// PUBLIC API DOCUMENTATION

export interface Env {
  DB: D1Database;
}

interface Client {
  id: number;
  name: string;
  api_key: string;
  created_at: string;
}

// Authentication middleware
async function authenticate(request: Request, env: Env): Promise<Client | null> {
  const apiKey = request.headers.get('X-API-Key') || request.headers.get('Authorization')?.replace('Bearer ', '');
  
  if (!apiKey) {
    return null;
  }

  try {
    const client = await env.DB.prepare('SELECT * FROM clients WHERE api_key = ?')
      .bind(apiKey)
      .first<Client>();
    
    return client;
  } catch (error) {
    console.error('Authentication error:', error);
    return null;
  }
}

// Response helpers
function jsonResponse(data: any, status: number = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
    },
  });
}

function errorResponse(message: string, status: number = 400) {
  return jsonResponse({ error: message, success: false }, status);
}

// Data Management Endpoints
async function handleDataUpload(request: Request, env: Env, client: Client) {
  try {
    const body: { source_name: string; source_type: string; data_rows: any[] } = await request.json();
    const { source_name: sourceName, source_type: sourceType, data_rows: dataRows } = body;

    if (!sourceName || !sourceType || !Array.isArray(dataRows)) {
      return errorResponse('Missing required fields: source_name, source_type, data_rows');
    }

    // Create or update data source
    const sourceResult = await env.DB.prepare(`
      INSERT OR REPLACE INTO data_sources (client_id, source_name, source_type, row_count)
      VALUES (?, ?, ?, ?)
    `).bind(client.id, sourceName, sourceType, dataRows.length).run();

    const sourceId = sourceResult.meta.last_row_id;

    // Insert data rows
    const insertPromises = dataRows.map((row: any) =>
      env.DB.prepare('INSERT INTO raw_data (source_id, data_row) VALUES (?, ?)')
        .bind(sourceId, JSON.stringify(row))
        .run()
    );

    await Promise.all(insertPromises);

    return jsonResponse({
      success: true,
      message: `Uploaded ${dataRows.length} rows to ${sourceName}`,
      source_id: sourceId
    });

  } catch (error) {
    console.error('Data upload error:', error);
    return errorResponse('Failed to upload data');
  }
}

async function handleDataSources(request: Request, env: Env, client: Client) {
  try {
    const sources = await env.DB.prepare(`
      SELECT id, source_name, source_type, row_count, last_ingested, created_at
      FROM data_sources 
      WHERE client_id = ?
      ORDER BY created_at DESC
    `).bind(client.id).all();

    return jsonResponse({
      success: true,
      data_sources: sources.results
    });

  } catch (error) {
    console.error('Data sources error:', error);
    return errorResponse('Failed to fetch data sources');
  }
}

// Analytics Endpoints
async function handleAnalyticsQuery(request: Request, env: Env, client: Client) {
  try {
    const body: { source_id: number; analysis_type: string; parameters?: any } = await request.json();
    const { source_id: sourceId, analysis_type: analysisType, parameters } = body;

    if (!sourceId || !analysisType) {
      return errorResponse('Missing required fields: source_id, analysis_type');
    }

    // Create analysis job
    const jobResult = await env.DB.prepare(`
      INSERT INTO analysis_jobs (client_id, job_type, status, parameters)
      VALUES (?, ?, 'pending', ?)
    `).bind(client.id, analysisType, JSON.stringify(parameters || {})).run();

    const jobId = jobResult.meta.last_row_id;

    // For demo purposes, simulate basic analytics
    let results = {};
    
    if (analysisType === 'descriptive') {
      const dataCount = await env.DB.prepare(`
        SELECT COUNT(*) as total_rows FROM raw_data WHERE source_id = ?
      `).bind(sourceId).first();

      results = {
        total_rows: dataCount?.total_rows || 0,
        analysis_type: 'descriptive_statistics',
        summary: 'Basic descriptive analysis completed'
      };
    }

    // Update job with results
    await env.DB.prepare(`
      UPDATE analysis_jobs 
      SET status = 'completed', results = ?, completed_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(JSON.stringify(results), jobId).run();

    return jsonResponse({
      success: true,
      job_id: jobId,
      status: 'completed',
      results: results
    });

  } catch (error) {
    console.error('Analytics error:', error);
    return errorResponse('Failed to process analytics query');
  }
}

async function handleJobStatus(request: Request, env: Env, client: Client, jobId: string) {
  try {
    const job = await env.DB.prepare(`
      SELECT id, job_type, status, results, created_at, completed_at
      FROM analysis_jobs
      WHERE id = ? AND client_id = ?
    `).bind(jobId, client.id).first();

    if (!job) {
      return errorResponse('Job not found', 404);
    }

    return jsonResponse({
      success: true,
      job: {
        ...job,
        results: job.results ? JSON.parse(job.results as string) : null
      }
    });

  } catch (error) {
    console.error('Job status error:', error);
    return errorResponse('Failed to fetch job status');
  }
}

// ML Model Endpoints
async function handleModelList(request: Request, env: Env, client: Client) {
  try {
    const models = await env.DB.prepare(`
      SELECT id, model_name, model_type, version, is_active, created_at
      FROM ml_models 
      WHERE client_id = ? AND is_active = true
      ORDER BY created_at DESC
    `).bind(client.id).all();

    return jsonResponse({
      success: true,
      models: models.results
    });

  } catch (error) {
    console.error('Model list error:', error);
    return errorResponse('Failed to fetch models');
  }
}

async function handleModelPredict(request: Request, env: Env, client: Client) {
  try {
    const body: { model_id: number; input_data: any } = await request.json();
    const { model_id: modelId, input_data: inputData } = body;

    if (!modelId || !inputData) {
      return errorResponse('Missing required fields: model_id, input_data');
    }

    // For demo purposes, return mock prediction
    const prediction = {
      model_id: modelId,
      prediction: Math.random() > 0.5 ? 'positive' : 'negative',
      confidence: Math.random(),
      timestamp: new Date().toISOString()
    };

    return jsonResponse({
      success: true,
      prediction: prediction
    });

  } catch (error) {
    console.error('Prediction error:', error);
    return errorResponse('Failed to generate prediction');
  }
}

// Report Generation
async function handleReportGenerate(request: Request, env: Env, client: Client) {
  try {
    const body: { report_type: string; parameters?: any } = await request.json();
    const { report_type: reportType, parameters } = body;

    // Generate basic dashboard report
    const dataSources = await env.DB.prepare(`
      SELECT COUNT(*) as total_sources, SUM(row_count) as total_rows
      FROM data_sources WHERE client_id = ?
    `).bind(client.id).first();

    const recentJobs = await env.DB.prepare(`
      SELECT COUNT(*) as total_jobs, 
             COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_jobs
      FROM analysis_jobs WHERE client_id = ?
    `).bind(client.id).first();

    const report = {
      client_name: client.name,
      generated_at: new Date().toISOString(),
      summary: {
        data_sources: dataSources?.total_sources || 0,
        total_data_rows: dataSources?.total_rows || 0,
        analysis_jobs: recentJobs?.total_jobs || 0,
        completed_jobs: recentJobs?.completed_jobs || 0
      }
    };

    return jsonResponse({
      success: true,
      report: report
    });

  } catch (error) {
    console.error('Report error:', error);
    return errorResponse('Failed to generate report');
  }
}

// Swagger UI HTML template
const swaggerHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Data Science API - Swagger UI</title>
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css">
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.11.0/index.css">
  <style>
    html {
      box-sizing: border-box;
      overflow: -moz-scrollbars-vertical;
      overflow-y: scroll;
    }
    *,
    *:before,
    *:after {
      box-sizing: inherit;
    }
    body {
      margin: 0;
      background: #fafafa;
    }
    .swagger-ui .topbar {
      display: none;
    }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js" charset="UTF-8"></script>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-standalone-preset.js" charset="UTF-8"></script>
  <script>
    window.onload = function() {
      const ui = SwaggerUIBundle({
        url: '/openapi.json',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "StandaloneLayout",
        defaultModelsExpandDepth: -1,
        defaultModelExpandDepth: 1,
        defaultModelRendering: 'example',
        displayRequestDuration: true,
        docExpansion: 'none',
        tryItOutEnabled: true,
        persistAuthorization: true
      });
      
      window.ui = ui;
    };
  </script>
</body>
</html>
`;

// Main router
async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
      },
    });
  }

  // ✅ Serve Swagger UI documentation (publicly accessible)
  if (path === '/docs' || path === '/swagger' || path === '/api-docs') {
    return new Response(swaggerHtml, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
      },
    });
  }

  // ✅ Serve OpenAPI spec (publicly accessible)
  if (path === '/openapi.json' || path === '/api/openapi.json') {
    const openapiSpec = {
      openapi: "3.0.3",
      info: {
        title: "Predictive Analytics API",
        description: "Comprehensive API for Data Management, Data Analysis, Business Intelligence, Machine Learning, and Artificial Intelligence services",
        version: "1.0.0",
        contact: {
          name: "API Support",
          email: "sibusiso.ndzukuma@dsnresearch.co.za",
          url: "https://dsnresearch.com"
        },
        license: {
          name: "MIT License",
          url: "https://opensource.org/licenses/MIT"
        }
      },
      servers: [
        {
          url: "https://data-analytics-api.sibusiso-ndzukuma.workers.dev",
          description: "Production server"
        },
        {
          url: "http://127.0.0.1:8787",
          description: "Development server"
        }
      ],
      security: [
        {
          ApiKeyAuth: []
        }
      ],
      components: {
        securitySchemes: {
          ApiKeyAuth: {
            type: "apiKey",
            in: "header",
            name: "X-API-Key"
          }
        },
        schemas: {
          ErrorResponse: {
            type: "object",
            properties: {
              error: { type: "string" },
              success: { type: "boolean" }
            }
          }
        }
      },
      paths: {
        "/health": {
          get: {
            summary: "Health check",
            responses: {
              "200": {
                description: "API is healthy",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        status: { type: "string" },
                        timestamp: { type: "string", format: "date-time" }
                      }
                    }
                  }
                }
              }
            }
          }
        },
        "/api/data/upload": {
          post: {
            summary: "Upload data for processing",
            security: [{ ApiKeyAuth: [] }],
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      source_name: { type: "string" },
                      source_type: { type: "string" },
                      data_rows: { type: "array", items: { type: "object" } }
                    },
                    required: ["source_name", "source_type", "data_rows"]
                  }
                }
              }
            },
            responses: {
              "200": {
                description: "Data uploaded successfully",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        message: { type: "string" },
                        source_id: { type: "integer" }
                      }
                    }
                  }
                }
              },
              "401": {
                description: "Unauthorized",
                content: {
                  "application/json": {
                    schema: {
                      "$ref": "#/components/schemas/ErrorResponse"
                    }
                  }
                }
              }
            }
          }
        },
        "/api/data/sources": {
          get: {
            summary: "List data sources",
            security: [{ ApiKeyAuth: [] }],
            responses: {
              "200": {
                description: "List of data sources",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        data_sources: {
                          type: "array",
                          items: {
                            type: "object",
                            properties: {
                              id: { type: "integer" },
                              source_name: { type: "string" },
                              source_type: { type: "string" },
                              row_count: { type: "integer" },
                              last_ingested: { type: "string", format: "date-time" },
                              created_at: { type: "string", format: "date-time" }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              },
              "401": {
                description: "Unauthorized",
                content: {
                  "application/json": {
                    schema: {
                      "$ref": "#/components/schemas/ErrorResponse"
                    }
                  }
                }
              }
            }
          }
        },
        "/api/analytics/query": {
          post: {
            summary: "Run analytics query",
            security: [{ ApiKeyAuth: [] }],
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      source_id: { type: "integer" },
                      analysis_type: { type: "string" },
                      parameters: { type: "object" }
                    },
                    required: ["source_id", "analysis_type"]
                  }
                }
              }
            },
            responses: {
              "200": {
                description: "Analysis job created",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        job_id: { type: "integer" },
                        status: { type: "string" },
                        results: { type: "object" }
                      }
                    }
                  }
                }
              },
              "401": {
                description: "Unauthorized",
                content: {
                  "application/json": {
                    schema: {
                      "$ref": "#/components/schemas/ErrorResponse"
                    }
                  }
                }
              }
            }
          }
        },
        "/api/analytics/jobs/{jobId}": {
          get: {
            summary: "Get analysis job status",
            security: [{ ApiKeyAuth: [] }],
            parameters: [
              {
                name: "jobId",
                in: "path",
                required: true,
                schema: { type: "integer" }
              }
            ],
            responses: {
              "200": {
                description: "Job status and results",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        job: { type: "object" }
                      }
                    }
                  }
                }
              },
              "401": {
                description: "Unauthorized",
                content: {
                  "application/json": {
                    schema: {
                      "$ref": "#/components/schemas/ErrorResponse"
                    }
                  }
                }
              },
              "404": {
                description: "Job not found",
                content: {
                  "application/json": {
                    schema: {
                      "$ref": "#/components/schemas/ErrorResponse"
                    }
                  }
                }
              }
            }
          }
        },
        "/api/models/list": {
          get: {
            summary: "List available ML models",
            security: [{ ApiKeyAuth: [] }],
            responses: {
              "200": {
                description: "List of ML models",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        models: {
                          type: "array",
                          items: {
                            type: "object",
                            properties: {
                              id: { type: "integer" },
                              model_name: { type: "string" },
                              model_type: { type: "string" },
                              version: { type: "string" },
                              is_active: { type: "boolean" },
                              created_at: { type: "string", format: "date-time" }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              },
              "401": {
                description: "Unauthorized",
                content: {
                  "application/json": {
                    schema: {
                      "$ref": "#/components/schemas/ErrorResponse"
                    }
                  }
                }
              }
            }
          }
        },
        "/api/models/predict": {
          post: {
            summary: "Generate prediction",
            security: [{ ApiKeyAuth: [] }],
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      model_id: { type: "integer" },
                      input_data: { type: "object" }
                    },
                    required: ["model_id", "input_data"]
                  }
                }
              }
            },
            responses: {
              "200": {
                description: "Prediction result",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        prediction: { type: "object" }
                      }
                    }
                  }
                }
              },
              "401": {
                description: "Unauthorized",
                content: {
                  "application/json": {
                    schema: {
                      "$ref": "#/components/schemas/ErrorResponse"
                    }
                  }
                }
              }
            }
          }
        },
        "/api/reports/generate": {
          post: {
            summary: "Generate report",
            security: [{ ApiKeyAuth: [] }],
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      report_type: { type: "string" },
                      parameters: { type: "object" }
                    },
                    required: ["report_type"]
                  }
                }
              }
            },
            responses: {
              "200": {
                description: "Generated report",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        report: { type: "object" }
                      }
                    }
                  }
                }
              },
              "401": {
                description: "Unauthorized",
                content: {
                  "application/json": {
                    schema: {
                      "$ref": "#/components/schemas/ErrorResponse"
                    }
                  }
                }
              }
            }
          }
        }
      }
    };

    return new Response(JSON.stringify(openapiSpec, null, 2), {
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }

  // ✅ License endpoint
  if (path === '/license') {
    const year = new Date().getFullYear();
    const licenseText = `Copyright ${year} Sibusiso Ndzukuma

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.`;

    return new Response(licenseText, {
      headers: { 'Content-Type': 'text/plain; charset=utf-8' }
    });
  }

  // Health check
  if (path === '/health') {
    return jsonResponse({ status: 'healthy', timestamp: new Date().toISOString() });
  }

  // API documentation endpoint
  if (path === '/' || path === '/api') {
    return jsonResponse({
      name: 'Predictive Analytics API',
      version: '1.0.0',
      endpoints: {
        'POST /api/data/upload': 'Upload data for processing',
        'GET /api/data/sources': 'List data sources',
        'POST /api/analytics/query': 'Run analytics queries',
        'GET /api/analytics/jobs/{id}': 'Check job status',
        'GET /api/models/list': 'List available ML models',
        'POST /api/models/predict': 'Generate predictions',
        'POST /api/reports/generate': 'Generate reports'
      },
      documentation: {
        'GET /docs': 'Interactive API documentation (Swagger UI)',
        'GET /openapi.json': 'OpenAPI specification',
        'GET /health': 'Health check endpoint'
      },
      authentication: 'Include X-API-Key header or Authorization: Bearer {key}'
    });
  }

  // All API endpoints require authentication
  if (path.startsWith('/api/')) {
    const client = await authenticate(request, env);
    if (!client) {
      return errorResponse('Authentication required. Include X-API-Key header.', 401);
    }

    // Route to specific handlers
    if (path === '/api/data/upload' && request.method === 'POST') {
      return handleDataUpload(request, env, client);
    }

    if (path === '/api/data/sources' && request.method === 'GET') {
      return handleDataSources(request, env, client);
    }

    if (path === '/api/analytics/query' && request.method === 'POST') {
      return handleAnalyticsQuery(request, env, client);
    }

    if (path.startsWith('/api/analytics/jobs/') && request.method === 'GET') {
      const jobId = path.split('/').pop();
      if (jobId) {
        return handleJobStatus(request, env, client, jobId);
      }
    }

    if (path === '/api/models/list' && request.method === 'GET') {
      return handleModelList(request, env, client);
    }

    if (path === '/api/models/predict' && request.method === 'POST') {
      return handleModelPredict(request, env, client);
    }

    if (path === '/api/reports/generate' && request.method === 'POST') {
      return handleReportGenerate(request, env, client);
    }

    return errorResponse('Endpoint not found', 404);
  }

  return errorResponse('Not found', 404);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      console.error('Unhandled error:', error);
      return errorResponse('Internal server error', 500);
    }
  },
};