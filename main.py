import os
import json
import urllib.request
import re
import subprocess
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from models import Base, Tool
from fastapi.responses import HTMLResponse


# ==========================================
# 1. CONFIGURACIÓN DE BASE DE DATOS Y OLLAMA
# ==========================================
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://187.77.206.103:11434/api/generate")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app = FastAPI(title="SOC Backend API", description="Centro de Operaciones de Seguridad Potenciado por IA")

# --- NUEVO: HABILITAR CORS PARA EVITAR EL "FAILED TO FETCH" ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permite que nuestro futuro Dashboard visual se conecte sin problemas
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
# 2. MODELOS DE DATOS (Lo que recibe la API)
# ==========================================
class RepoRequest(BaseModel):
    repo_url: str

# ==========================================
# 3. RUTAS DE LA API
# ==========================================
@app.get("/")
def read_root():
    return {"status": "online", "message": "SOC Backend funcionando. Ve a /docs para el panel interactivo."}

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
def get_all_tools(db: Session = Depends(get_db)):
    """Devuelve el catálogo completo de herramientas guardadas en el SOC."""
    tools = db.query(Tool).all()
    return {
        "status": "success", 
        "total": len(tools), 
        "data": tools
    }




# ... [Aquí va todo tu código actual de BD, modelos y rutas de API] ...

# ==========================================
# 4. DASHBOARD VISUAL (Frontend)
# ==========================================
@app.get("/api/tools")
def get_tools(db: Session = Depends(get_db)):
    """Devuelve todas las herramientas guardadas."""
    tools = db.query(Tool).order_by(Tool.created_at.desc()).all()
    return {"status": "success", "total": len(tools), "data": tools}

@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard():
    """Sirve la interfaz visual del SOC."""
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
    </head>
    <body class="bg-gray-900 text-white font-sans antialiased p-6">
        
        <script>
            if (sessionStorage.getItem('auth') !== 'true') {
                const pwd = prompt("🔐 Acceso Restringido TECCO SOC. Ingrese contraseña:");
                if (pwd === "admin123") { // Puedes cambiar esta contraseña
                    sessionStorage.setItem('auth', 'true');
                } else {
                    document.body.innerHTML = "<h1 class='text-center text-red-500 text-3xl mt-20'>Acceso Denegado</h1>";
                    throw new Error("Acceso denegado");
                }
            }
        </script>

        <div class="max-w-6xl mx-auto">
            <header class="flex justify-between items-center mb-10 border-b border-gray-700 pb-4">
                <h1 class="text-3xl font-bold text-green-400">🛡️ TECCO SOC <span class="text-gray-400 text-lg font-normal">v1.0</span></h1>
                <div class="text-sm text-gray-400">Operaciones Tácticas e IA</div>
            </header>

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
            <div id="toolsGrid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                </div>
        </div>

        <script>
            // Función para cargar las herramientas al entrar
            async function loadTools() {
                try {
                    const response = await fetch('/api/tools');
                    const result = await response.json();
                    const grid = document.getElementById('toolsGrid');
                    grid.innerHTML = '';

                    result.data.forEach(tool => {
                        const card = `
                            <div class="bg-gray-800 border border-gray-700 rounded-lg p-5 hover:border-green-400 transition flex flex-col h-full">
                                <div class="flex justify-between items-start mb-3">
                                    <h3 class="text-lg font-bold text-white">${tool.name}</h3>
                                    <span class="bg-gray-700 text-green-400 text-xs px-2 py-1 rounded border border-green-900">${tool.category}</span>
                                </div>
                                <p class="text-gray-400 text-sm mb-4 flex-grow">${tool.description}</p>
                                <div class="text-xs text-gray-500 mt-auto">
                                    <p>⚙️ Script: <span class="text-gray-300">${tool.main_script}</span></p>
                                    <a href="${tool.repo_url}" target="_blank" class="text-blue-400 hover:underline mt-2 inline-block">Ver en GitHub ↗</a>
                                </div>
                                <!-- Ejemplo dentro de tu tarjeta de cPanelSniper -->
                                <div class="card-footer">
                                    <!-- Asumiendo que el ID en la base de datos de cPanelSniper es 1 -->
                                    <button onclick="openModal(1, 'cPanelSniper')" style="margin-top:15px; padding:8px 15px; background:#3b82f6; color:white; border:none; border-radius:6px; cursor:pointer; font-weight: 500;">
                                        🎯 Lanzar contra objetivo
                                    </button>
                                </div>
                            </div>
                        `;
                        grid.innerHTML += card;
                    });
                } catch (error) {
                    console.error("Error cargando herramientas:", error);
                }
            }

            // Función para enviar URL a la API y que Qwen la analice
            async function addTool() {
                const urlInput = document.getElementById('repoUrl');
                const btn = document.getElementById('addBtn');
                const msg = document.getElementById('statusMsg');
                
                if (!urlInput.value) return;

                btn.disabled = true;
                btn.innerHTML = 'Procesando con IA... ⏳';
                msg.classList.remove('hidden', 'text-red-400', 'text-green-400');
                msg.classList.add('text-gray-400');
                msg.innerText = 'Descargando repositorio y analizando manual...';

                try {
                    const res = await fetch('/api/tools/add', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ repo_url: urlInput.value })
                    });
                    const data = await res.json();

                    if (res.ok) {
                        msg.classList.replace('text-gray-400', 'text-green-400');
                        msg.innerText = '¡Herramienta añadida y clasificada con éxito!';
                        urlInput.value = '';
                        loadTools(); // Recargamos el grid
                    } else {
                        throw new Error(data.detail || "Error desconocido");
                    }
                } catch (error) {
                    msg.classList.replace('text-gray-400', 'text-red-400');
                    msg.innerText = '❌ Error: ' + error.message;
                } finally {
                    btn.disabled = false;
                    btn.innerHTML = 'Analizar con IA';
                }
            }

            // Cargar datos al iniciar
            loadTools();

            // Variable global para saber qué herramienta vamos a ejecutar
let currentToolId = null;

// Reemplaza esto con la URL completa de tu API en Coolify
const API_BASE_URL = "http://ekr8q5muf7m7xnr139m0qset.187.77.206.103.sslip.io"; 

function openModal(toolId, toolName) {
    currentToolId = toolId;
    document.getElementById('modalTitle').innerText = 'Operación: ' + toolName;
    document.getElementById('targetInput').value = '';
    document.getElementById('resultArea').style.display = 'none';
    document.getElementById('loadingIndicator').style.display = 'none';
    document.getElementById('runBtn').style.display = 'block';
    
    // Mostramos el modal
    document.getElementById('scanModal').style.display = 'flex';
}

function closeModal() {
    document.getElementById('scanModal').style.display = 'none';
}

async function ejecutarEscaneo() {
    const target = document.getElementById('targetInput').value.trim();
    if (!target) {
        alert("⚠️ Por favor, ingresa un objetivo válido.");
        return;
    }

    // Cambiamos la interfaz a "Modo Carga"
    document.getElementById('runBtn').style.display = 'none';
    document.getElementById('loadingIndicator').style.display = 'block';
    document.getElementById('resultArea').style.display = 'none';

    try {
        const response = await fetch(`${API_BASE_URL}/api/scans/run`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                tool_id: currentToolId,
                target: target
            })
        });

        const data = await response.json();

        if (response.ok) {
            mostrarResultado(data.data);
        } else {
            // Maneja errores controlados por FastAPI (ej. no existe la herramienta)
            mostrarError(data.detail || "Error desconocido en el servidor");
        }
    } catch (error) {
        // Maneja errores graves (red caída, timeout de 3 min)
        mostrarError("La operación falló o excedió el tiempo límite (Timeout). Detalles: " + error.message);
    }
}

function mostrarResultado(data) {
    // Ocultamos la carga y mostramos el cuadro de resultados
    document.getElementById('loadingIndicator').style.display = 'none';
    const resultArea = document.getElementById('resultArea');
    resultArea.style.display = 'block';
    
    // Sistema de Alertas Visuales (Semáforo)
    let colorCode = "#10b981"; // Verde (Seguro) por defecto
    let icon = "✅";
    
    if (data.severity === "Crítico") {
        colorCode = "#ef4444"; // Rojo
        icon = "🚨";
    } else if (data.severity === "Advertencia") {
        colorCode = "#f59e0b"; // Naranja/Amarillo
        icon = "⚠️";
    }

    // Construimos la vista de respuesta usando HTML dinámico
    resultArea.innerHTML = `
        <h4 style="color:${colorCode}; margin-top:0; font-size:1.2rem; border-bottom:1px solid #334155; padding-bottom:8px;">
            ${icon} Criticidad: ${data.severity}
        </h4>
        
        <p style="color:#e2e8f0; font-size:0.95rem; line-height:1.5;">
            <strong style="color:#38bdf8;">Reporte IA (Qwen):</strong><br>
            ${data.analysis.replace(/\n/g, '<br>')}
        </p>
        
        <details style="margin-top:15px; border-top:1px solid #334155; padding-top:10px;">
            <summary style="cursor:pointer; color:#94a3b8; font-size:0.85rem; user-select:none;">
                [+] Ver salida en crudo de la terminal Docker
            </summary>
            <pre style="background:#000; color:#00ff00; padding:12px; border-radius:6px; overflow-x:auto; font-size:0.75rem; margin-top:10px; border:1px solid #1f2937;">${data.raw}</pre>
        </details>
    `;
}

function mostrarError(mensaje) {
    document.getElementById('loadingIndicator').style.display = 'none';
    document.getElementById('runBtn').style.display = 'block';
    
    const resultArea = document.getElementById('resultArea');
    resultArea.style.display = 'block';
    resultArea.innerHTML = `
        <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid #ef4444; padding: 12px; border-radius: 6px;">
            <p style="color:#ef4444; margin:0; font-weight:500;">❌ Falla Crítica Operacional</p>
            <p style="color:#f8fafc; margin:5px 0 0 0; font-size:0.85rem;">${mensaje}</p>
        </div>
    `;
}

        </script>
        <!-- Modal de Ejecución (Oculto por defecto) -->
<div id="scanModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(15, 23, 42, 0.85); z-index:1000; justify-content:center; align-items:center; backdrop-filter: blur(4px);">
    <div style="background:#1e293b; padding:25px; border-radius:12px; width:90%; max-width:550px; color:white; border: 1px solid #334155; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);">
        
        <h3 id="modalTitle" style="margin-top:0; color:#e2e8f0; font-size: 1.5rem;">Lanzar Ataque</h3>
        <p style="color:#94a3b8; font-size: 0.9rem;">Ingrese el objetivo a evaluar (URL o IP):</p>
        
        <input type="text" id="targetInput" placeholder="Ej: tecco.com.co" style="width:100%; padding:12px; margin-bottom:20px; border-radius:6px; border:1px solid #475569; background:#0f172a; color:#f8fafc; font-size:1rem; outline:none;">
        
        <!-- Indicador de Carga -->
        <div id="loadingIndicator" style="display:none; color:#10b981; margin-bottom:20px; text-align:center;">
            <p style="animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;">⚙️ Desplegando contenedor y analizando con IA...<br><span style="font-size:0.8rem; color:#64748b;">Esto puede tomar hasta 3 minutos.</span></p>
        </div>

        <!-- Área de Resultados (donde Qwen escupirá el reporte) -->
        <div id="resultArea" style="display:none; margin-bottom:20px; padding:15px; border-radius:8px; background:#0f172a; border: 1px solid #334155; max-height: 400px; overflow-y: auto;">
            <!-- El JS inyectará el contenido aquí -->
        </div>

        <!-- Botones de Acción -->
        <div style="display:flex; justify-content:flex-end; gap:12px;">
            <button onclick="closeModal()" style="padding:10px 18px; background:#475569; color:white; border:none; border-radius:6px; cursor:pointer; font-weight:500; transition: background 0.3s;">Cancelar</button>
            <button id="runBtn" onclick="ejecutarEscaneo()" style="padding:10px 18px; background:#ef4444; color:white; border:none; border-radius:6px; cursor:pointer; font-weight:bold; box-shadow: 0 4px 6px -1px rgba(239, 68, 68, 0.3); transition: background 0.3s;">🚀 Ejecutar Herramienta</button>
        </div>
    </div>
</div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)



# ... (tus clases BaseModel actuales)

class ScanRequest(BaseModel):
    tool_id: int
    target: str
    args: str = "" # Argumentos adicionales si se necesitan

@app.post("/api/scans/run")
def run_tool_scan(request: ScanRequest, db: Session = Depends(get_db)):
    # 1. Buscamos la herramienta en la BD
    tool = db.query(Tool).filter(Tool.id == request.tool_id).first()
    if not tool:
        raise HTTPException(status_code=404, detail="Herramienta no encontrada en el Arsenal.")

    # 2. Registramos el objetivo en la BD (o lo obtenemos si ya existe)
    from models import Target, Scan # Asegurar importación
    target_record = db.query(Target).filter(Target.identity == request.target).first()
    if not target_record:
        target_record = Target(identity=request.target, type="Automático", tags="Dashboard")
        db.add(target_record)
        db.commit()
        db.refresh(target_record)

    # 3. Construimos el script de ejecución aislado en Docker
    script_ejecucion = tool.main_script if tool.main_script != "desconocido" else "main.py"
    bash_script = (
        f"apk add --no-cache git > /dev/null && "
        f"git clone {tool.repo_url} /app > /dev/null 2>&1 && "
        f"cd /app && "
        f"if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt > /dev/null 2>&1; fi && "
        f"python {script_ejecucion} {request.target} {request.args}"
    )
    
    comando = ["docker", "run", "--rm", "python:3.10-alpine", "sh", "-c", bash_script]
    
    try:
        # 4. Ejecutamos la herramienta (Timeout de 3 minutos)
        proceso = subprocess.run(comando, capture_output=True, text=True, timeout=180)
        resultado_crudo = proceso.stdout if proceso.stdout else proceso.stderr
        
        # 5. Pasamos el resultado a Qwen para análisis (Evaluación de Riesgo)
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
                # Asignamos color para el Dashboard según lo que diga la IA
                if "Critico" in analisis_ia or "Crítico" in analisis_ia: status_ia = "Crítico"
                elif "Advertencia" in analisis_ia: status_ia = "Advertencia"
                else: status_ia = "Seguro"
        except:
            pass

        # 6. Guardamos el historial en la Base de Datos
        nuevo_scan = Scan(
            tool_id=tool.id,
            target_id=target_record.id,
            raw_output=resultado_crudo[:5000], # Limitamos tamaño
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


