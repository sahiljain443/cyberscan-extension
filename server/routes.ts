import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import threatIntelligenceRouter from "./apis/threat-intelligence";
import openaiAnalysisRouter from "./apis/openai-analysis";

export async function registerRoutes(app: Express): Promise<Server> {
  // CORS middleware for Chrome extension
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    
    if (req.method === 'OPTIONS') {
      res.sendStatus(200);
    } else {
      next();
    }
  });

  // API routes
  app.use('/api/threat-intelligence', threatIntelligenceRouter);
  app.use('/api/openai', openaiAnalysisRouter);

  // Health check endpoint
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      virustotal: !!process.env.VIRUSTOTAL_API_KEY,
      abuseipdb: !!process.env.ABUSEIPDB_API_KEY,
      openai: !!process.env.OPENAI_API_KEY
    });
  });

  const httpServer = createServer(app);

  return httpServer;
}
