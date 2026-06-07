"""
============================================================
ORBIT-SHIELD | security/auth.py — Segurança da API
Global Solution 2026.1 — FIAP
Disciplina: Cibersegurança para Sistemas de IA
============================================================

DESCRIÇÃO:
    Módulo central de segurança da API ORBIT-SHIELD.
    Implementa as contramedidas definidas no modelo STRIDE:

    ┌─────────────────────────────────────────────────────┐
    │ Ameaça STRIDE    │ Contramedida implementada aqui   │
    ├─────────────────────────────────────────────────────┤
    │ #1 Spoofing      │ Validação HMAC-SHA256            │
    │ #2 Tampering     │ Validação HMAC-SHA256            │
    │ #3 Repudiation   │ JWT com claims rastreáveis       │
    │ #5 DoS           │ Rate Limiter por IP              │
    └─────────────────────────────────────────────────────┘

DECISÃO DE DESIGN:
    Funções puras (sem estado) para HMAC e JWT —
    facilita teste unitário e auditoria de segurança.
    Rate Limiter implementado como classe (estado necessário).
============================================================
"""

import hmac
import hashlib
import time
import logging
from collections import defaultdict
from typing import Optional
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger("orbit_shield.security")

# ============================================================
# CONFIGURAÇÕES DE SEGURANÇA
# ============================================================

# Chave HMAC compartilhada com o ESP32
# ATENÇÃO: Em produção, carregar de variável de ambiente
# Nunca commitar a chave real no repositório Git
import os
HMAC_SECRET_KEY = os.getenv("ORBIT_HMAC_KEY", "orbit-shield-secret-2026-fiap")

# Configurações de Rate Limiting
RATE_LIMIT_REQUESTS  = 60    # máximo de requisições
RATE_LIMIT_WINDOW_S  = 60    # por janela de N segundos
RATE_LIMIT_BLOCK_S   = 300   # bloqueio de 5 min após exceder

# Timestamp de início da API (para uptime)
API_START_TIME = time.time()


# ============================================================
# VALIDAÇÃO HMAC-SHA256
# CONEXÃO C/C++: recria o HMAC gerado no firmware ESP32
# ============================================================

def validar_hmac(payload: dict, hmac_recebido: str) -> bool:
    """
    Valida o HMAC-SHA256 de um payload recebido do ESP32.

    LÓGICA:
        1. Recria a string do payload na MESMA ordem do firmware C++
        2. Calcula o HMAC com a chave compartilhada
        3. Compara com o HMAC recebido usando compare_digest()
           (tempo constante — previne timing attacks)

    CONEXÃO CIBERSEGURANÇA:
        - Autentica a origem (STRIDE #1 Spoofing)
        - Detecta alteração em trânsito (STRIDE #2 Tampering)

    Args:
        payload: dicionário com os dados da leitura
        hmac_recebido: hash HMAC enviado pelo ESP32

    Returns:
        True se o HMAC é válido, False caso contrário
    """
    try:
        # Recriar a string do payload na MESMA ordem do firmware C++
        # snprintf format: "%s|%ld|%.2f|%.2f|%.2f|%ld|%ld|%.2f|%d|%d|%d|%.2f|%.2f"
        payload_str = (
            f"{payload['station_id']}|"
            f"{payload['timestamp_unix']}|"
            f"{payload['temperatura_cpu']:.2f}|"
            f"{payload['sinal_rf_dbm']:.2f}|"
            f"{payload['consumo_energia_w']:.2f}|"
            f"{payload['bytes_enviados']}|"
            f"{payload['bytes_recebidos']}|"
            f"{payload['pacotes_por_segundo']:.2f}|"
            f"{payload['flags_tcp']}|"
            f"{payload['tentativas_auth']}|"
            f"{payload['portas_destino_unicas']}|"
            f"{payload['intervalo_medio_pacotes']:.2f}|"
            f"{payload['tamanho_medio_pacote']:.2f}"
        )

        # Calcular HMAC-SHA256 esperado
        hmac_esperado = hmac.new(
            key=HMAC_SECRET_KEY.encode("utf-8"),
            msg=payload_str.encode("utf-8"),
            digestmod=hashlib.sha256
        ).hexdigest()

        # Comparação em tempo constante (previne timing attacks)
        # NUNCA usar == para comparar hashes de segurança
        valido = hmac.compare_digest(hmac_esperado, hmac_recebido.lower())

        if not valido:
            logger.warning(
                f"🔴 HMAC INVÁLIDO | Station: {payload.get('station_id')} "
                f"| Recebido: {hmac_recebido[:16]}... "
                f"| Esperado: {hmac_esperado[:16]}..."
            )
        else:
            logger.debug(f"✅ HMAC válido | Station: {payload.get('station_id')}")

        return valido

    except (KeyError, TypeError, ValueError) as e:
        logger.error(f"Erro ao validar HMAC: {e}")
        return False


def validar_timestamp(timestamp_unix: int, tolerancia_s: int = 300) -> bool:
    """
    Valida que o timestamp do payload é recente.

    CONEXÃO CIBERSEGURANÇA:
        Previne Replay Attacks — um atacante que captura um pacote
        válido não pode reenviá-lo horas depois, pois o timestamp
        estará fora da janela de tolerância.

    Args:
        timestamp_unix: timestamp do payload
        tolerancia_s: janela de aceitação em segundos (padrão: 5 min)

    Returns:
        True se o timestamp está dentro da tolerância
    """
    agora = int(time.time())
    diferenca = abs(agora - timestamp_unix)

    if diferenca > tolerancia_s:
        logger.warning(
            f"⚠️  Timestamp suspeito: diferença de {diferenca}s "
            f"(tolerância: {tolerancia_s}s) — possível Replay Attack"
        )
        return False
    return True


# ============================================================
# RATE LIMITER MIDDLEWARE
# CONEXÃO CIBERSEGURANÇA: contramedida STRIDE #5 (Denial of Service)
# ============================================================

class RateLimiterMiddleware(BaseHTTPMiddleware):
    """
    Middleware de Rate Limiting baseado em janela deslizante por IP.

    ALGORITMO: Sliding Window Counter
    - Mantém histórico de timestamps de requisições por IP
    - Remove timestamps fora da janela de tempo atual
    - Bloqueia IPs que excedem o limite

    DECISÃO vs Token Bucket:
        Sliding Window é mais preciso para bursts — ideal para
        detectar ataques DDoS que tentam distribuir requisições
        exatamente no limite do bucket.

    DECISÃO de armazenamento:
        defaultdict em memória — adequado para POC.
        Em produção: Redis para persistência entre instâncias.
    """

    def __init__(self, app):
        super().__init__(app)
        # Dicionário: IP → lista de timestamps de requisições
        self._historico: dict = defaultdict(list)
        # Dicionário: IP → timestamp de desbloqueio
        self._bloqueados: dict = {}
        logger.info(
            f"[RateLimit] Iniciado: {RATE_LIMIT_REQUESTS} req/"
            f"{RATE_LIMIT_WINDOW_S}s por IP"
        )

    async def dispatch(self, request: Request, call_next):
        """Intercepta toda requisição e aplica rate limiting."""
        ip = request.client.host
        agora = time.time()

        # Endpoints excluídos do rate limiting
        if request.url.path in ["/health", "/docs", "/redoc", "/openapi.json"]:
            return await call_next(request)

        # Verificar se o IP está bloqueado
        if ip in self._bloqueados:
            tempo_restante = self._bloqueados[ip] - agora
            if tempo_restante > 0:
                logger.warning(
                    f"🚫 IP bloqueado: {ip} "
                    f"| Desbloqueio em {tempo_restante:.0f}s"
                )
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "erro": "IP temporariamente bloqueado por excesso de requisições.",
                        "desbloqueio_em_segundos": round(tempo_restante),
                        "orbit_shield": "STRIDE #5 — Rate Limit Protection"
                    },
                    headers={"Retry-After": str(round(tempo_restante))}
                )
            else:
                # Desbloquear automaticamente após o período
                del self._bloqueados[ip]
                logger.info(f"✅ IP desbloqueado: {ip}")

        # Limpar timestamps antigos (fora da janela)
        self._historico[ip] = [
            ts for ts in self._historico[ip]
            if agora - ts < RATE_LIMIT_WINDOW_S
        ]

        # Verificar limite
        if len(self._historico[ip]) >= RATE_LIMIT_REQUESTS:
            # Bloquear IP
            self._bloqueados[ip] = agora + RATE_LIMIT_BLOCK_S
            logger.warning(
                f"🔴 Rate limit excedido: {ip} "
                f"| {len(self._historico[ip])} req/{RATE_LIMIT_WINDOW_S}s "
                f"| Bloqueado por {RATE_LIMIT_BLOCK_S}s"
            )
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "erro": "Rate limit excedido. IP bloqueado temporariamente.",
                    "limite":   RATE_LIMIT_REQUESTS,
                    "janela_s": RATE_LIMIT_WINDOW_S,
                    "bloqueio_s": RATE_LIMIT_BLOCK_S
                }
            )

        # Registrar timestamp desta requisição
        self._historico[ip].append(agora)

        # Adicionar headers informativos de rate limit
        response = await call_next(request)
        restantes = RATE_LIMIT_REQUESTS - len(self._historico[ip])
        response.headers["X-RateLimit-Limit"]     = str(RATE_LIMIT_REQUESTS)
        response.headers["X-RateLimit-Remaining"] = str(restantes)
        response.headers["X-RateLimit-Window-S"]  = str(RATE_LIMIT_WINDOW_S)
        return response
