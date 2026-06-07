"""
============================================================
ORBIT-SHIELD | routes/sensors.py — Endpoints de Sensores
Global Solution 2026.1 — FIAP
============================================================
"""
from fastapi import APIRouter, HTTPException, status, Header
from typing import Optional
from app.models.schemas import SensorReadingInput, SensorReadingResponse
from app.services.sensor_service import sensor_service
import logging

router = APIRouter()
logger = logging.getLogger("orbit_shield.routes.sensors")


@router.post(
    "/reading",
    response_model=SensorReadingResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingere uma leitura de sensor do ESP32",
    description="""
    Endpoint principal de ingestão de dados.

    **Fluxo completo:**
    1. Valida o schema JSON (Pydantic)
    2. Verifica o timestamp (anti-Replay Attack)
    3. Valida o HMAC-SHA256 (autenticidade + integridade)
    4. Executa inferência do modelo ML
    5. Persiste no banco de dados
    6. Emite alerta se anomalia detectada

    **Header obrigatório:** `X-Station-ID` com o ID da estação.
    """
)
async def ingerir_leitura(
    leitura: SensorReadingInput,
    x_station_id: Optional[str] = Header(
        default=None,
        description="ID da ground station remetente"
    )
):
    """
    Recebe e processa uma leitura de sensor do ESP32.

    SEGURANÇA:
    - HMAC validado antes de qualquer processamento
    - Timestamp verificado (janela de 5 minutos)
    - Rate Limiting aplicado pelo middleware (60 req/min por IP)
    """
    # Validação cruzada: station_id no header deve coincidir com o payload
    if x_station_id and x_station_id != leitura.station_id:
        logger.warning(
            f"Inconsistência de station_id: "
            f"header='{x_station_id}' payload='{leitura.station_id}'"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="station_id no header não coincide com o payload. "
                   "Possível tentativa de spoofing."
        )

    # Processar via serviço
    resultado = sensor_service.processar_leitura(leitura)

    # Se a leitura foi rejeitada por segurança, retornar 403
    if not resultado.sucesso and "HMAC" in resultado.mensagem:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=resultado.mensagem
        )

    return resultado


@router.get(
    "/stats",
    summary="Estatísticas de operação do serviço de sensores"
)
async def obter_estatisticas():
    """Retorna métricas de processamento do SensorService."""
    return sensor_service.estatisticas


# ============================================================
# routes/health.py
# ============================================================
"""
ORBIT-SHIELD | routes/health.py — Health Check
"""
from fastapi import APIRouter
from app.models.schemas import HealthResponse
from app.services.sensor_service import sensor_service
import time

router_health = APIRouter()

@router_health.get(
    "/",
    response_model=HealthResponse,
    summary="Verifica se a API está operacional"
)
async def health_check():
    """
    Health check da API — usado por load balancers e monitoring.
    Verifica: API ativa, banco acessível, modelo ML carregado.
    """
    stats = sensor_service.estatisticas
    return HealthResponse(
        status="online",
        versao="1.0.0",
        uptime_s=stats["uptime_segundos"],
        banco_ok=True,    # Em produção: testar conexão real com o BD
        modelo_ok=stats["modelo_carregado"]
    )


# ============================================================
# routes/alerts.py
# ============================================================
"""
ORBIT-SHIELD | routes/alerts.py — Consulta de Alertas
"""
from fastapi import APIRouter, Query
from typing import List
from datetime import datetime

router_alerts = APIRouter()

# Dados simulados para o dashboard (em produção: query ao BD)
ALERTAS_SIMULADOS = [
    {
        "evento_id": 1,
        "estacao": "GS-BRASILIA-01",
        "localizacao": "Brasília, DF — Brasil",
        "horario": "09/06/2026 14:22:10",
        "categoria_stride": "DENIAL_OF_SERVICE",
        "tipo_ataque": "DDOS",
        "severidade": "CRITICA",
        "descricao": "Taxa de pacotes: 4850/s (limiar: 500/s). Score: -0.8742.",
        "resolvido": False,
        "score_anomalia": -0.8742,
        "confianca_modelo": 0.9321,
        "minutos_atras": 3.5
    },
    {
        "evento_id": 2,
        "estacao": "GS-MANAUS-01",
        "localizacao": "Manaus, AM — Brasil",
        "horario": "09/06/2026 13:58:44",
        "categoria_stride": "SPOOFING",
        "tipo_ataque": "BRUTEFORCE",
        "severidade": "ALTA",
        "descricao": "142 tentativas de autenticação em 300s. Score: -0.7214.",
        "resolvido": True,
        "score_anomalia": -0.7214,
        "confianca_modelo": 0.8811,
        "minutos_atras": 27.1
    },
    {
        "evento_id": 3,
        "estacao": "GS-FORTALEZA-01",
        "localizacao": "Fortaleza, CE — Brasil",
        "horario": "09/06/2026 12:41:03",
        "categoria_stride": "ELEVATION_OF_PRIVILEGE",
        "tipo_ataque": "POISONING",
        "severidade": "ALTA",
        "descricao": "Data Poisoning detectado via KS-Test. Score: -0.5530.",
        "resolvido": False,
        "score_anomalia": -0.5530,
        "confianca_modelo": 0.7640,
        "minutos_atras": 105.8
    }
]


@router_alerts.get(
    "/",
    summary="Lista eventos de segurança detectados",
    description="Retorna os alertas de segurança do ORBIT-SHIELD, "
                "com filtros opcionais por severidade e status."
)
async def listar_alertas(
    apenas_nao_resolvidos: bool = Query(
        default=False,
        description="Se True, retorna apenas alertas pendentes"
    ),
    severidade: Optional[str] = Query(
        default=None,
        description="Filtrar por severidade: BAIXA, MEDIA, ALTA, CRITICA"
    )
):
    """
    Retorna lista de eventos de segurança detectados pelo ORBIT-SHIELD.
    Em produção: executa a Query 1 do script 02_dml_dados_queries.sql.
    """
    alertas = ALERTAS_SIMULADOS.copy()

    if apenas_nao_resolvidos:
        alertas = [a for a in alertas if not a["resolvido"]]

    if severidade:
        alertas = [a for a in alertas if a["severidade"] == severidade.upper()]

    return {
        "total": len(alertas),
        "alertas": alertas,
        "timestamp": datetime.now().isoformat()
    }


@router_alerts.get(
    "/summary",
    summary="Resumo estatístico dos alertas por tipo"
)
async def resumo_alertas():
    """
    Retorna contagem de alertas por tipo de ataque.
    Alimenta o gráfico de pizza do dashboard.
    """
    from collections import Counter
    tipos = Counter(a["tipo_ataque"] for a in ALERTAS_SIMULADOS)
    return {
        "por_tipo": dict(tipos),
        "total_criticos": sum(
            1 for a in ALERTAS_SIMULADOS if a["severidade"] == "CRITICA"
        ),
        "total_nao_resolvidos": sum(
            1 for a in ALERTAS_SIMULADOS if not a["resolvido"]
        )
    }
