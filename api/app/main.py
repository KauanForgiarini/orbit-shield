"""
============================================================
ORBIT-SHIELD | main.py — Ponto de entrada da API
Global Solution 2026.1 — FIAP
Disciplinas: Programação Python + Cibersegurança para IA
============================================================

DESCRIÇÃO:
    API RESTful construída com FastAPI para ingestão segura
    dos dados dos sensores ESP32. Atua como camada central
    do ORBIT-SHIELD, integrando todos os pilares do projeto.

ARQUITETURA (Clean Code + POO):
    main.py         → ponto de entrada, configuração do app
    routes/         → endpoints organizados por domínio
    services/       → regras de negócio (lógica principal)
    models/         → schemas Pydantic (validação de dados)
    security/       → HMAC, JWT, Rate Limiting
    db/             → conexão e operações com PostgreSQL

COMO RODAR:
    pip install -r requirements.txt
    uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

DOCUMENTAÇÃO AUTOMÁTICA (gerada pelo FastAPI):
    http://localhost:8000/docs  (Swagger UI)
    http://localhost:8000/redoc (ReDoc)
============================================================
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import time
import logging

# Importações internas
from app.routes import sensors, alerts, health
from app.security.rate_limiter import RateLimiterMiddleware

# ============================================================
# CONFIGURAÇÃO DE LOGGING
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("orbit_shield.main")

# ============================================================
# INSTÂNCIA PRINCIPAL DO APP
# ============================================================
app = FastAPI(
    title="🛰️ ORBIT-SHIELD API",
    description="""
    ## Sistema de Detecção de Cyberataques em Ground Stations Satelitais

    API de ingestão e análise de dados dos sensores ESP32.
    Integra Machine Learning, Banco de Dados e Cibersegurança.

    ### Funcionalidades
    - **Ingestão segura** de leituras de sensores com validação HMAC
    - **Detecção de anomalias** via Isolation Forest em tempo real
    - **Classificação de ataques** via Random Forest
    - **Rate limiting** contra DDoS na própria API
    - **Audit log** completo para conformidade LGPD

    ### Global Solution 2026.1 — FIAP
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    # Desabilitar docs em produção (segurança)
    # docs_url=None, redoc_url=None
)

# ============================================================
# MIDDLEWARES — Executados em toda requisição
# ============================================================

# 1. CORS — Define quais origens podem acessar a API
# CONEXÃO CIBERSEGURANÇA: restringe acesso a origens conhecidas
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8501"],  # Dashboard Streamlit
    allow_credentials=True,
    allow_methods=["GET", "POST"],   # Apenas métodos necessários
    allow_headers=["Authorization", "Content-Type", "X-Station-ID"],
)

# 2. Trusted Hosts — Rejeita requisições com Host header inválido
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*.orbit-shield.fiap.br"]
)

# 3. Rate Limiter customizado — Proteção contra DDoS na API
# CONEXÃO CIBERSEGURANÇA: contramedida STRIDE #5 (Denial of Service)
app.add_middleware(RateLimiterMiddleware)

# 4. Middleware de logging e tempo de resposta
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """
    Registra todas as requisições com tempo de resposta.
    CONEXÃO CIBERSEGURANÇA: base do audit trail (STRIDE #3 Repudiation).
    """
    inicio = time.time()
    
    # Log da requisição recebida
    logger.info(
        f"→ {request.method} {request.url.path} "
        f"| IP: {request.client.host} "
        f"| Station: {request.headers.get('X-Station-ID', 'N/A')}"
    )
    
    # Processar requisição
    response = await call_next(request)
    
    # Log da resposta
    duracao_ms = round((time.time() - inicio) * 1000, 2)
    logger.info(
        f"← {response.status_code} "
        f"| {request.url.path} "
        f"| {duracao_ms}ms"
    )
    
    # Adicionar header de tempo de resposta
    response.headers["X-Process-Time-Ms"] = str(duracao_ms)
    return response

# ============================================================
# ROTAS
# ============================================================
app.include_router(health.router,   prefix="/health",   tags=["Health"])
app.include_router(sensors.router,  prefix="/sensors",  tags=["Sensores"])
app.include_router(alerts.router,   prefix="/alerts",   tags=["Alertas"])

# ============================================================
# HANDLERS DE ERRO GLOBAIS
# ============================================================
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(
        status_code=404,
        content={"erro": "Endpoint não encontrado", "path": str(request.url.path)}
    )

@app.exception_handler(500)
async def server_error_handler(request: Request, exc):
    logger.error(f"Erro interno: {exc}")
    return JSONResponse(
        status_code=500,
        content={"erro": "Erro interno do servidor. Verifique os logs."}
    )

# ============================================================
# EVENTOS DE STARTUP E SHUTDOWN
# ============================================================
@app.on_event("startup")
async def startup_event():
    logger.info("=" * 50)
    logger.info("🛰️  ORBIT-SHIELD API iniciando...")
    logger.info("   Versão: 1.0.0 | Global Solution 2026.1")
    logger.info("=" * 50)

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("🛰️  ORBIT-SHIELD API encerrando...")
