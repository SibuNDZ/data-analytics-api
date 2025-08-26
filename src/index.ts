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
    const body = await request.json();
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
    const body = await request.json();
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
    const body = await request.json();
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
    const body = await request.json();
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

  // Health check
  if (path === '/health') {
    return jsonResponse({ status: 'healthy', timestamp: new Date().toISOString() });
  }

  // API documentation endpoint
  if (path === '/' || path === '/api') {
    return jsonResponse({
      name: 'Data Science API',
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