import os
import json
import urllib.request
import re
import subprocess
import shlex  # NUEVO: Librería de seguridad para comandos de terminal
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from models import Base, Tool, Target, Scan
from fastapi.responses import HTMLResponse

# ==========================================
# 0. AUTO-INSTALADOR DEL CLIENTE DOCKER (/tmp para evitar permisos root)
# ==========================================
DOCKER_CMD = "docker"
try:
    subprocess.run([DOCKER_CMD, "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("✅ Docker CLI ya está instalado.")
except FileNotFoundError:
    print("⚙️ Docker CLI no encontrado. Instalando en /tmp (sin root)...")
    os.system("curl -fsSLO https://download.docker.com/linux/static/stable/x86_64/docker-24.0.9.tgz")
    os.system("tar xzvf docker-24.0.9.tgz")
    os.system("mv docker/docker /tmp/docker")
    os.system("chmod +x /tmp/docker")
    os.system("rm -rf docker docker-24.0.9.tgz")
    DOCKER_CMD = "/tmp/docker"
    print("✅ Docker CLI instalado en /tmp/docker.")
# ==========================================

# ==========================================
# 1. CONFIGURACIÓN DE BASE DE DATOS Y OLLAMA
# ==========================================
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://187.77.206.103:11434/api/generate")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app = FastAPI(title="TECCO SOC API", description="Centro de Operaciones de Seguridad Potenciado por IA")

# --- HABILITAR CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    print("✅ Base de datos lista.")

# ==========================================
# 2. MODELOS DE DATOS
# ==========================================
class RepoRequest(BaseModel):
    repo_url: str

class ScanRequest(BaseModel):
    tool_id: int
    target: str
    args: str = ""

# ==========================================
# 3. RUTAS DE LA API (Backend)
# ==========================================
@app.get("/")
def read_root():
    return {"status": "online", "message": "SOC Backend funcionando. Ve a /dashboard para el panel visual."}

@app.post("/api/tools/add")
def add_tool_from_github(request: RepoRequest, db: Session = Depends(get_db)):
    repo_url = request.repo_url.rstrip("/")
    existing_tool = db.query(Tool).filter(Tool.repo_url == repo_url).first()
    if existing_tool:
        raise HTTPException(status_code=400, detail="Esta herramienta ya existe en el SOC.")

    parts = repo_url.split("/")
    if len(parts) < 4:
        raise HTTPException(status_code=400, detail="URL de GitHub no válida.")
    owner, repo = parts[-2], parts[-1]

    readme_text = ""
    for branch in ["main", "master"]:
        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/README.md"
        try:
            req = urllib.request.Request(raw_url)
            with urllib.request.urlopen(req) as response:
                readme_text = response.read().decode('utf-8')
            break
        except:
            continue
            
    if not readme_text:
        readme_text = "Sin README disponible. Analiza el nombre: " + repo

    prompt = f"""Eres un experto en ciberseguridad. Analiza este README de una herramienta de software.
Devuelve ÚNICAMENTE un objeto JSON válido con estas claves y NADA MÁS:
"name": (Nombre de la herramienta),
"description": (Descripción corta en español, max 2 líneas),
"main_script": (Nombre del script a ejecutar, ej. main.py o script.sh. Si no sabes, pon "desconocido"),
"category": (Una categoría corta, ej. OSINT, CVE, Red, Web, Escáner)

README:
{readme_text[:2000]}
"""

    clean_ollama_url = OLLAMA_URL.replace("[", "").replace("]", "").replace("'", "").replace('"', "")
    data = {"model": "qwen2.5-coder:7b", "prompt": prompt, "stream": False}
    
    try:
        req_ia = urllib.request.Request(clean_ollama_url, data=json.dumps(data).encode('utf-8'), headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req_ia) as response_ia:
            result_ia = json.loads(response_ia.read().decode('utf-8'))
            ia_text = result_ia.get("response", "{}")
            ia_text = re.sub(r'```json|```', '', ia_text).strip()
            ia_data = json.loads(ia_text)
    except Exception as e:
        ia_data = {
            "name": repo, 
            "description": "Herramienta agregada pero hubo error analizando con IA: " + str(e), 
            "main_script": "desconocido", 
            "category": "Sin categoría"
        }

    nueva_herramienta = Tool(
        name=ia_data.get("name", repo),
        repo_url=repo_url,
        description=ia_data.get("description", "Sin descripción"),
        main_script=ia_data.get("main_script", "desconocido"),
        category=ia_data.get("category", "Desconocido")
    )
    
    db.add(nueva_herramienta)
    db.commit()
    db.refresh(nueva_herramienta)
    return {"status": "success", "message": "Herramienta analizada y guardada.", "data": ia_data}

@app.get("/api/tools")
def get_tools(db: Session = Depends(get_db)):
    tools = db.query(Tool).order_by(Tool.created_at.desc()).all()
    return {"status": "success", "total": len(tools), "data": tools}

@app.get("/api/history")
def get_scan_history(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.executed_at.desc()).all()
    history = []
    for scan in scans:
        history.append({
            "id": scan.id,
            "date": scan.executed_at.strftime("%Y-%m-%d %H:%M:%S"),
            "target": scan.target.identity if scan.target else "Desconocido",
            "tool": scan.tool.name if scan.tool else "Desconocida",
            "status": scan.status,
            "raw_output": scan.raw_output,
            "ai_analysis": scan.ai_analysis
        })
    return {"status": "success", "data": history}

@app.post("/api/scans/run")
def run_tool_scan(request: ScanRequest, db: Session = Depends(get_db)):
    # ---------------------------------------------------------
    # 🛡️ CAPA DE SEGURIDAD 1: Validación estricta por Regex
    # Solo permite letras, números, puntos, guiones, barras y dos puntos (URLs/IPs)
    # Rechaza espacios, punto y comas, y operadores de terminal (&, |, >, <)
    # ---------------------------------------------------------
    if not re.match(r"^[a-zA-Z0-9.\-:/]+$", request.target):
        raise HTTPException(status_code=400, detail="Objetivo bloqueado por seguridad. Formato inválido o caracteres peligrosos detectados.")

    tool = db.query(Tool).filter(Tool.id == request.tool_id).first()
    if not tool:
        raise HTTPException(status_code=404, detail="Herramienta no encontrada en el Arsenal.")

    target_record = db.query(Target).filter(Target.identity == request.target).first()
    if not target_record:
        target_record = Target(identity=request.target, type="Automático", tags="Dashboard")
        db.add(target_record)
        db.commit()
        db.refresh(target_record)

    # ---------------------------------------------------------
    # 🛡️ CAPA DE SEGURIDAD 2: Sanitización de terminal (shlex)
    # Envuelve las variables para que el sistema no pueda ejecutarlas como comandos extra
    # ---------------------------------------------------------
    safe_target = shlex.quote(request.target)
    safe_args = shlex.quote(request.args) if request.args else ""
    script_ejecucion = shlex.quote(tool.main_script if tool.main_script != "desconocido" else "main.py")

    bash_script = (
        f"apk add --no-cache git > /dev/null && "
        f"git clone {tool.repo_url} /app > /dev/null 2>&1 && "
        f"cd /app && "
        f"if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt > /dev/null 2>&1; fi && "
        f"python {script_ejecucion} {safe_target} {safe_args}"
    )
    
    # Ejecución usando la ruta de docker segura
    comando = [DOCKER_CMD, "run", "--rm", "python:3.10-alpine", "sh", "-c", bash_script]
    
    try:
        proceso = subprocess.run(comando, capture_output=True, text=True, timeout=180)
        resultado_crudo = proceso.stdout if proceso.stdout else proceso.stderr
        
        prompt_ia = f"""Analiza este resultado de una herramienta de seguridad ({tool.name}) contra el objetivo {request.target}.
        Dime brevemente: 1. Qué encontró. 2. Nivel de criticidad (Seguro, Advertencia, Critico).
        Resultado: {resultado_crudo[:2000]}"""
        
        clean_ollama_url = OLLAMA_URL.replace("[", "").replace("]", "").replace("'", "").replace('"', "")
        data_ia = {"model": "qwen2.5-coder:7b", "prompt": prompt_ia, "stream": False}
        
        analisis_ia = "Análisis no disponible."
        status_ia = "Desconocido"
        try:
            req_ia = urllib.request.Request(clean_ollama_url, data=json.dumps(data_ia).encode('utf-8'), headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req_ia) as response_ia:
                result_ia = json.loads(response_ia.read().decode('utf-8'))
                analisis_ia = result_ia.get("response", "")
                if "Critico" in analisis_ia or "Crítico" in analisis_ia: status_ia = "Crítico"
                elif "Advertencia" in analisis_ia: status_ia = "Advertencia"
                else: status_ia = "Seguro"
        except:
            pass

        nuevo_scan = Scan(
            tool_id=tool.id,
            target_id=target_record.id,
            raw_output=resultado_crudo[:5000],
            ai_analysis=analisis_ia,
            status=status_ia
        )
        db.add(nuevo_scan)
        db.commit()

        return {"status": "success", "message": "Escaneo completado y analizado", "data": {"raw": resultado_crudo, "analysis": analisis_ia, "severity": status_ia}}

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="La herramienta tardó demasiado y fue detenida.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al ejecutar: {str(e)}")

# ==========================================
# 4. DASHBOARD VISUAL (Frontend)
# ==========================================
@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard():
    html_content = """
    <!DOCTYPE html>
    <html lang="es" class="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>TECCO SOC - Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script>
            tailwind.config = {
                darkMode: 'class',
                theme: { extend: { colors: { gray: { 900: '#111827', 800: '#1f2937' }, green: { 400: '#4ade80' } } } }
            }
        </script>
        <style>
            ::-webkit-scrollbar { width: 8px; height: 8px; }
            ::-webkit-scrollbar-track { background: #1f2937; }
            ::-webkit-scrollbar-thumb { background: #4b5563; border-radius: 4px; }
            ::-webkit-scrollbar-thumb:hover { background: #6b7280; }
        </style>
    </head>
    <body class="bg-gray-900 text-white font-sans antialiased p-6">
        
        <script>
            if (sessionStorage.getItem('auth') !== 'true') {
                const pwd = prompt("🔐 Acceso Restringido TECCO SOC. Ingrese contraseña:");
                if (pwd === "admin123") {
                    sessionStorage.setItem('auth', 'true');
                } else {
                    document.body.innerHTML = "<h1 class='text-center text-red-500 text-3xl mt-20'>Acceso Denegado</h1>";
                    throw new Error("Acceso denegado");
                }
            }
        </script>

        <div class="max-w-7xl mx-auto">
            <header class="flex justify-between items-center mb-6 border-b border-gray-700 pb-4">
                <h1 class="text-3xl font-bold text-green-400">🛡️ TECCO SOC <span class="text-gray-400 text-lg font-normal">v2.1 (Secured)</span></h1>
                <div class="text-sm text-gray-400">Centro de Mando Avanzado</div>
            </header>

            <div class="flex space-x-6 mb-8 border-b border-gray-800">
                <button id="tabBtn-arsenal" onclick="switchTab('arsenal')" class="pb-3 text-green-400 border-b-2 border-green-400 font-semibold transition-colors">🚀 Arsenal Táctico</button>
                <button id="tabBtn-history" onclick="switchTab('history')" class="pb-3 text-gray-500 hover:text-gray-300 border-b-2 border-transparent font-semibold transition-colors">🗄️ Historial de Operaciones</button>
            </div>

            <div id="view-arsenal" class="block">
                <div class="bg-gray-800 p-6 rounded-lg shadow-lg mb-8 border border-gray-700">
                    <h2 class="text-xl font-semibold mb-4">Añadir nueva herramienta desde GitHub</h2>
                    <div class="flex gap-4">
                        <input type="text" id="repoUrl" placeholder="https://github.com/usuario/repo" class="w-full bg-gray-900 border border-gray-600 rounded px-4 py-2 text-white focus:outline-none focus:border-green-400">
                        <button onclick="addTool()" id="addBtn" class="bg-green-600 hover:bg-green-500 text-white font-bold py-2 px-6 rounded transition flex-shrink-0">
                            Analizar con IA
                        </button>
                    </div>
                    <p id="statusMsg" class="mt-3 text-sm text-gray-400 hidden"></p>
                </div>

                <h2 class="text-2xl font-semibold mb-6">Arsenal Disponible</h2>
                <div id="toolsGrid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"></div>
            </div>

            <div id="view-history" class="hidden">
                <div class="bg-gray-800 rounded-lg shadow-lg border border-gray-700 overflow-hidden">
                    <table class="w-full text-left border-collapse">
                        <thead>
                            <tr class="bg-gray-900 border-b border-gray-700 text-gray-400 text-sm">
                                <th class="p-4 font-semibold">Fecha y Hora</th>
                                <th class="p-4 font-semibold">Objetivo</th>
                                <th class="p-4 font-semibold">Herramienta</th>
                                <th class="p-4 font-semibold">Estado</th>
                                <th class="p-4 font-semibold text-right">Acción</th>
                            </tr>
                        </thead>
                        <tbody id="historyTableBody" class="text-sm divide-y divide-gray-700/50"></tbody>
                    </table>
                </div>
            </div>

        </div>

        <div id="scanModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(15, 23, 42, 0.85); z-index:1000; justify-content:center; align-items:center; backdrop-filter: blur(4px);">
            <div style="background:#1e293b; padding:25px; border-radius:12px; width:90%; max-width:550px; color:white; border: 1px solid #334155; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);">
                <h3 id="modalTitle" style="margin-top:0; color:#e2e8f0; font-size: 1.5rem;">Lanzar Ataque</h3>
                <p style="color:#94a3b8; font-size: 0.9rem; margin-bottom:15px;">Ingrese el objetivo a evaluar (URL o IP):</p>
                <input type="text" id="targetInput" placeholder="Ej: tecco.com.co" style="width:100%; padding:12px; margin-bottom:20px; border-radius:6px; border:1px solid #475569; background:#0f172a; color:#f8fafc; font-size:1rem; outline:none;">
                
                <div id="loadingIndicator" style="display:none; color:#10b981; margin-bottom:20px; text-align:center;">
                    <p style="animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;">⚙️ Desplegando contenedor aislado y analizando...<br><span style="font-size:0.8rem; color:#64748b;">Esto puede tomar hasta 3 minutos.</span></p>
                </div>
                <div id="resultArea" style="display:none; margin-bottom:20px; padding:15px; border-radius:8px; background:#0f172a; border: 1px solid #334155; max-height: 400px; overflow-y: auto;"></div>

                <div style="display:flex; justify-content:flex-end; gap:12px;">
                    <button onclick="closeModal('scanModal')" style="padding:10px 18px; background:#475569; color:white; border:none; border-radius:6px; cursor:pointer;">Cancelar</button>
                    <button id="runBtn" onclick="ejecutarEscaneo()" style="padding:10px 18px; background:#ef4444; color:white; border:none; border-radius:6px; font-weight:bold;">🚀 Ejecutar</button>
                </div>
            </div>
        </div>

        <div id="reportModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0, 0, 0, 0.9); z-index:2000; justify-content:center; align-items:center; backdrop-filter: blur(8px);">
            <div style="background:#111827; border-radius:12px; width:95%; max-width:800px; max-height:90vh; display:flex; flex-direction:column; border: 1px solid #374151; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 1);">
                <div class="p-6 border-b border-gray-800 flex justify-between items-start">
                    <div>
                        <h3 class="text-2xl font-bold text-white mb-1" id="rep-title">📄 Informe Detallado de Inteligencia</h3>
                        <p class="text-gray-400 text-sm" id="rep-subtitle">Objetivo: -- | Herramienta: -- | Fecha: --</p>
                    </div>
                    <span id="rep-badge" class="px-3 py-1 rounded-full text-sm font-bold border">Estado</span>
                </div>
                <div class="p-6 overflow-y-auto flex-grow bg-gray-900">
                    <h4 class="text-lg font-semibold text-blue-400 mb-3 border-b border-gray-800 pb-2">🧠 Análisis Ejecutivo (Qwen IA)</h4>
                    <div id="rep-ai" class="text-gray-300 text-sm leading-relaxed mb-8 whitespace-pre-wrap">Cargando...</div>
                    <h4 class="text-lg font-semibold text-gray-400 mb-3 border-b border-gray-800 pb-2">💻 Telemetría Cruda (Consola)</h4>
                    <pre id="rep-raw" class="bg-black text-green-500 p-4 rounded-lg text-xs overflow-x-auto border border-gray-800 font-mono">Cargando...</pre>
                </div>
                <div class="p-4 border-t border-gray-800 flex justify-end bg-gray-900 rounded-b-12px">
                    <button onclick="closeModal('reportModal')" class="bg-gray-700 hover:bg-gray-600 text-white font-bold py-2 px-6 rounded transition">Cerrar Informe</button>
                </div>
            </div>
        </div>

        <script>
            let currentToolId = null;
            let historyDataRaw = [];

            function switchTab(tabName) {
                document.getElementById('view-arsenal').classList.add('hidden');
                document.getElementById('view-history').classList.add('hidden');
                document.getElementById('tabBtn-arsenal').className = "pb-3 text-gray-500 hover:text-gray-300 border-b-2 border-transparent font-semibold transition-colors";
                document.getElementById('tabBtn-history').className = "pb-3 text-gray-500 hover:text-gray-300 border-b-2 border-transparent font-semibold transition-colors";
                document.getElementById(`view-${tabName}`).classList.remove('hidden');
                document.getElementById(`tabBtn-${tabName}`).className = "pb-3 text-green-400 border-b-2 border-green-400 font-semibold transition-colors";
                if (tabName === 'history') loadHistory();
            }

            async function loadTools() {
                try {
                    const response = await fetch('/api/tools');
                    const result = await response.json();
                    const grid = document.getElementById('toolsGrid');
                    grid.innerHTML = '';
                    result.data.forEach(tool => {
                        grid.innerHTML += `
                            <div class="bg-gray-800 border border-gray-700 rounded-lg p-5 hover:border-green-400 transition flex flex-col h-full">
                                <div class="flex justify-between items-start mb-3">
                                    <h3 class="text-lg font-bold text-white">${tool.name}</h3>
                                    <span class="bg-gray-700 text-green-400 text-xs px-2 py-1 rounded border border-green-900">${tool.category}</span>
                                </div>
                                <p class="text-gray-400 text-sm mb-4 flex-grow">${tool.description}</p>
                                <div class="text-xs text-gray-500 mt-auto">
                                    <p>⚙️ Script: <span class="text-gray-300">${tool.main_script}</span></p>
                                </div>
                                <div class="mt-5 pt-4 border-t border-gray-700">
                                    <button onclick="openAttackModal(${tool.id}, '${tool.name}')" class="w-full bg-red-600 hover:bg-red-500 text-white font-bold py-2 px-4 rounded transition shadow-lg shadow-red-500/30">
                                        🎯 Lanzar contra objetivo
                                    </button>
                                </div>
                            </div>
                        `;
                    });
                } catch (e) { console.error(e); }
            }

            async function addTool() {
                const urlInput = document.getElementById('repoUrl');
                const btn = document.getElementById('addBtn');
                const msg = document.getElementById('statusMsg');
                if (!urlInput.value) return;

                btn.disabled = true; btn.innerHTML = 'Procesando... ⏳';
                msg.classList.remove('hidden', 'text-red-400', 'text-green-400');
                msg.classList.add('text-gray-400'); msg.innerText = 'Analizando...';

                try {
                    const res = await fetch('/api/tools/add', {
                        method: 'POST', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ repo_url: urlInput.value })
                    });
                    const data = await res.json();
                    if (res.ok) {
                        msg.classList.replace('text-gray-400', 'text-green-400');
                        msg.innerText = '¡Añadida con éxito!';
                        urlInput.value = ''; loadTools();
                    } else throw new Error(data.detail);
                } catch (err) {
                    msg.classList.replace('text-gray-400', 'text-red-400');
                    msg.innerText = '❌ Error: ' + err.message;
                } finally {
                    btn.disabled = false; btn.innerHTML = 'Analizar con IA';
                }
            }

            async function loadHistory() {
                try {
                    const tbody = document.getElementById('historyTableBody');
                    tbody.innerHTML = '<tr><td colspan="5" class="p-4 text-center text-gray-500">Cargando base de datos táctica...</td></tr>';
                    const response = await fetch('/api/history');
                    const result = await response.json();
                    historyDataRaw = result.data;
                    tbody.innerHTML = '';
                    if(historyDataRaw.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="5" class="p-4 text-center text-gray-500">No hay operaciones registradas.</td></tr>';
                        return;
                    }
                    historyDataRaw.forEach((scan, index) => {
                        let badgeHtml = `<span class="bg-green-900/50 text-green-400 px-2 py-1 rounded text-xs border border-green-800">✅ Seguro</span>`;
                        if (scan.status === "Crítico") badgeHtml = `<span class="bg-red-900/50 text-red-400 px-2 py-1 rounded text-xs border border-red-800">🚨 Crítico</span>`;
                        if (scan.status === "Advertencia") badgeHtml = `<span class="bg-yellow-900/50 text-yellow-400 px-2 py-1 rounded text-xs border border-yellow-800">⚠️ Advertencia</span>`;

                        tbody.innerHTML += `
                            <tr class="hover:bg-gray-800/50 transition">
                                <td class="p-4 text-gray-400 font-mono">${scan.date}</td>
                                <td class="p-4 font-semibold text-blue-300">${scan.target}</td>
                                <td class="p-4">${scan.tool}</td>
                                <td class="p-4">${badgeHtml}</td>
                                <td class="p-4 text-right">
                                    <button onclick="openReportModal(${index})" class="text-xs bg-gray-700 hover:bg-gray-600 text-white py-1 px-3 rounded border border-gray-600 transition">
                                        Ver Informe
                                    </button>
                                </td>
                            </tr>
                        `;
                    });
                } catch (e) { console.error(e); }
            }

            function openAttackModal(toolId, toolName) {
                currentToolId = toolId;
                document.getElementById('modalTitle').innerText = 'Operación: ' + toolName;
                document.getElementById('targetInput').value = '';
                document.getElementById('resultArea').style.display = 'none';
                document.getElementById('loadingIndicator').style.display = 'none';
                document.getElementById('runBtn').style.display = 'block';
                document.getElementById('scanModal').style.display = 'flex';
            }

            function openReportModal(index) {
                const scan = historyDataRaw[index];
                document.getElementById('rep-subtitle').innerText = `Objetivo: ${scan.target} | Herramienta: ${scan.tool} | Fecha: ${scan.date}`;
                const badge = document.getElementById('rep-badge');
                if (scan.status === "Crítico") { badge.className = "px-3 py-1 rounded-full text-sm font-bold border bg-red-900/30 text-red-400 border-red-800"; badge.innerText = "🚨 Crítico"; }
                else if (scan.status === "Advertencia") { badge.className = "px-3 py-1 rounded-full text-sm font-bold border bg-yellow-900/30 text-yellow-400 border-yellow-800"; badge.innerText = "⚠️ Advertencia"; }
                else { badge.className = "px-3 py-1 rounded-full text-sm font-bold border bg-green-900/30 text-green-400 border-green-800"; badge.innerText = "✅ Seguro"; }

                document.getElementById('rep-ai').innerHTML = scan.ai_analysis.replace(/\\n/g, '<br>');
                document.getElementById('rep-raw').innerText = scan.raw_output;
                document.getElementById('reportModal').style.display = 'flex';
            }

            function closeModal(modalId) { document.getElementById(modalId).style.display = 'none'; }

            async function ejecutarEscaneo() {
                const target = document.getElementById('targetInput').value.trim();
                if (!target) { alert("⚠️ Ingresa un objetivo válido."); return; }

                document.getElementById('runBtn').style.display = 'none';
                document.getElementById('loadingIndicator').style.display = 'block';

                try {
                    const response = await fetch('/api/scans/run', {
                        method: 'POST', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ tool_id: currentToolId, target: target })
                    });
                    const data = await response.json();
                    
                    if (response.ok) {
                        document.getElementById('loadingIndicator').style.display = 'none';
                        closeModal('scanModal'); 
                        switchTab('history');
                        setTimeout(() => { openReportModal(0); }, 500); 
                    } else throw new Error(data.detail);
                } catch (error) {
                    document.getElementById('loadingIndicator').style.display = 'none';
                    document.getElementById('runBtn').style.display = 'block';
                    alert("⚠️ Bloqueo de Seguridad o Falla: " + error.message);
                }
            }

            loadTools();
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)
