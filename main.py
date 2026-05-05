import os
from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base

# Tomamos la URL de la base de datos desde las variables de Coolify
DATABASE_URL = os.getenv("DATABASE_URL")

# Adaptación de formato obligatoria: SQLAlchemy requiere 'postgresql://' en lugar de 'postgres://'
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Conectamos con la base de datos
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app = FastAPI(title="SOC Backend API")

# Evento de inicio: Crea las tablas automáticamente si no existen
@app.on_event("startup")
def on_startup():
    try:
        Base.metadata.create_all(bind=engine)
        print("✅ Tablas de la base de datos creadas/verificadas con éxito.")
    except Exception as e:
        print(f"❌ Error conectando a la base de datos: {e}")

# Ruta de prueba para verificar que el servidor vive
@app.get("/")
def read_root():
    return {"status": "online", "message": "SOC Backend funcionando y conectado a PostgreSQL."}
