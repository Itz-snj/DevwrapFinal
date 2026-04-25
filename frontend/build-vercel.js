import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function buildVercel() {
  console.log('Building Vercel Output API v3 structure...');
  
  const vercelDir = path.join(__dirname, '.vercel');
  const outputDir = path.join(vercelDir, 'output');
  const staticDir = path.join(outputDir, 'static');
  const funcDir = path.join(outputDir, 'functions', 'index.func');
  
  // 1. Clean previous builds
  if (fs.existsSync(vercelDir)) {
    fs.rmSync(vercelDir, { recursive: true, force: true });
  }
  
  // 2. Create directories
  fs.mkdirSync(staticDir, { recursive: true });
  fs.mkdirSync(funcDir, { recursive: true });
  
  // 3. Copy static client assets
  const clientDist = path.join(__dirname, 'dist', 'client');
  if (fs.existsSync(clientDist)) {
    fs.cpSync(clientDist, staticDir, { recursive: true });
  }
  
  // 4. Create Vercel routing config
  const routingConfig = {
    version: 3,
    routes: [
      { handle: "filesystem" },
      { src: "/(.*)", dest: "/index" }
    ]
  };
  fs.writeFileSync(
    path.join(outputDir, 'config.json'), 
    JSON.stringify(routingConfig, null, 2)
  );
  
  // 5. Create Node.js Function config
  const funcConfig = {
    runtime: "nodejs20.x",
    handler: "index.js",
    launcherType: "Nodejs"
  };
  fs.writeFileSync(
    path.join(funcDir, '.vc-config.json'), 
    JSON.stringify(funcConfig, null, 2)
  );
  
  // 6. Copy server assets into the function directory
  const serverDist = path.join(__dirname, 'dist', 'server');
  const funcServerDir = path.join(funcDir, 'server');
  if (fs.existsSync(serverDist)) {
    fs.cpSync(serverDist, funcServerDir, { recursive: true });
  }

  // 7. Create Node.js function entrypoint
  const edgeEntry = `
import server from './server/server.js';
export default async function(request) {
  return server.fetch(request);
}
`;
  fs.writeFileSync(
    path.join(funcDir, 'index.js'), 
    edgeEntry
  );
  
  console.log('Vercel Output successfully generated at .vercel/output');
}

buildVercel();
