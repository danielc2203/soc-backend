import os
import json
import urllib.request
import re
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from models import Base, Tool

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

# Dependencia para abrir y cerrar la base de datos de forma segura
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
    
    # Verificamos si ya existe en la base de datos
    existing_tool = db.query(Tool).filter(Tool.repo_url == repo_url).first()
    if existing_tool:
        raise HTTPException(status_code=400, detail="Esta herramienta ya existe en el SOC.")

    # 1. Extraemos usuario y repositorio de la URL
    parts = repo_url.split("/")
    if len(parts) < 4:
        raise HTTPException(status_code=400, detail="URL de GitHub no válida.")
    owner, repo = parts[-2], parts[-1]

    # 2. Descargamos el README desde GitHub
    readme_text = ""
    for branch in ["main", "master"]:
        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/README.md"
        try:
            req = urllib.request.Request(raw_url)
            with urllib.request.urlopen(req) as response:
                readme_text = response.read().decode('utf-8')
            break # Si lo encuentra, salimos del ciclo
        except:
            continue
            
    if not readme_text:
        readme_text = "Sin README disponible. Analiza el nombre: " + repo

    # 3. Preparamos la orden para Qwen (IA)
    # Limitamos a 2000 caracteres para no saturar a la IA
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
    
    # 4. Le preguntamos a Qwen
    try:
        req_ia = urllib.request.Request(clean_ollama_url, data=json.dumps(data).encode('utf-8'), headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req_ia) as response_ia:
            result_ia = json.loads(response_ia.read().decode('utf-8'))
            ia_text = result_ia.get("response", "{}")
            
            # Limpiamos el texto por si la IA le pone comillas de Markdown
            ia_text = re.sub(r'```json|```', '', ia_text).strip()
            ia_data = json.loads(ia_text)
    except Exception as e:
        ia_data = {
            "name": repo, 
            "description": "Herramienta agregada pero hubo error analizando con IA: " + str(e), 
            "main_script": "desconocido", 
            "category": "Sin categoría"
        }

    # 5. Guardamos la magia en PostgreSQL
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

    return {"status": "success", "message": "Herramienta analizada por IA y guardada.", "data": ia_data}
