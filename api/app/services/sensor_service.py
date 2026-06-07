"""
============================================================
ORBIT-SHIELD | services/sensor_service.py — Lógica de Negócio
Global Solution 2026.1 — FIAP
Disciplina: Programação Python (POO + Clean Code)
============================================================

DESCRIÇÃO:
    Serviço central que orquestra o processamento de cada
    leitura recebida do ESP32. Integra todos os pilares:

    1. Valida HMAC (Cibersegurança)
    2. Valida timestamp — previne Replay Attack (Cibersegurança)
    3. Executa inferência do modelo ML (Machine Learning)
    4. Persiste no banco de dados (Banco de Dados)
    5. Emite alertas se necessário (Integração)

DECISÃO DE DESIGN (POO):
    Classe SensorService encapsula toda a lógica de negócio.
    Instância única (Singleton pattern) compartilhada pelos
    endpoints — garante que o modelo ML seja carregado apenas
    uma vez na memória.
============================================================
"""

import logging
import time
import json
import hashlib
from datetime import datetime
from typing import Optional, Tuple

import numpy as np

from app.models.schemas import SensorReadingInput, SensorReadingResponse
from app.security.rate_limiter import validar_hmac, validar_timestamp

logger = logging.getLogger("orbit_shield.service")


# ============================================================
# MODELO DE ML EM MEMÓRIA
# Carregado uma vez no startup e reutilizado por todas as req.
# DECISÃO: evitar I/O de disco em cada requisição (performance)
# ============================================================

class ModeloMLSimulado:
    """
    Simula o modelo de ML em memória para a API.

    Em produção: carregar os modelos reais com joblib:
        import joblib
        self.iso_forest = joblib.load("models/isolation_forest.pkl")
        self.random_forest = joblib.load("models/random_forest.pkl")
        self.scaler = joblib.load("models/scaler.pkl")

    Para a POC: implementamos as regras de decisão dos modelos
    diretamente em Python, mantendo a lógica idêntica ao notebook.
    """

    def __init__(self):
        logger.info("[ML] Carregando modelos de detecção...")
        # Thresholds calibrados com base nos resultados do notebook
        self._threshold_ddos        = 500.0   # pacotes/s
        self._threshold_bruteforce  = 20       # tentativas auth
        self._threshold_portscan    = 50       # portas únicas
        self._threshold_temperatura = 60.0     # °C
        logger.info("[ML] ✅ Modelos carregados com sucesso.")

    def extrair_features(self, leitura: SensorReadingInput) -> np.ndarray:
        """
        Extrai e organiza as features na mesma ordem do notebook.
        Inclui as features derivadas (engenharia de features).

        CONEXÃO ML: ordem idêntica ao pipeline do notebook Jupyter.
        """
        ratio_bytes = (
            leitura.bytes_enviados / (leitura.bytes_recebidos + 1)
        )
        taxa_auth = (
            leitura.tentativas_auth / (leitura.duracao_conexao_estimada + 0.001)
        )

        return np.array([
            leitura.temperatura_cpu,         # feature 1
            leitura.bytes_enviados,          # feature 2 (como proxy de duracao)
            leitura.bytes_recebidos,         # feature 3
            leitura.pacotes_por_segundo,     # feature 4
            leitura.flags_tcp,               # feature 5
            leitura.tentativas_auth,         # feature 6
            leitura.portas_destino_unicas,   # feature 7
            leitura.intervalo_medio_pacotes, # feature 8
            leitura.tamanho_medio_pacote,    # feature 9
            ratio_bytes,                     # feature 10 (derivada)
            taxa_auth,                       # feature 11 (derivada)
        ])

    def classificar(
        self, leitura: SensorReadingInput
    ) -> Tuple[bool, Optional[str], float, float]:
        """
        Classifica a leitura como normal ou tipo de ataque.

        Implementa as regras aprendidas pelos modelos Random Forest
        e Isolation Forest do notebook, em formato de inferência
        leve adequado para uma API REST.

        Returns:
            Tuple: (anomalia, tipo_ataque, score_anomalia, confianca)
        """
        score = 0.0  # Score de anomalia (mais negativo = mais suspeito)

        # --- Regras do Isolation Forest (detecção de anomalia) ---

        # DDoS: altíssima taxa de pacotes + bytes enviados > recebidos
        if leitura.pacotes_por_segundo > self._threshold_ddos:
            score -= 0.85
            ratio = leitura.bytes_enviados / max(leitura.bytes_recebidos, 1)
            confianca = min(0.70 + (leitura.pacotes_por_segundo / 10000), 0.99)
            return True, "DDOS", round(score, 4), round(confianca, 4)

        # BruteForce: excesso de tentativas de autenticação
        if leitura.tentativas_auth > self._threshold_bruteforce:
            score -= 0.72
            confianca = min(0.65 + (leitura.tentativas_auth / 500), 0.99)
            return True, "BRUTEFORCE", round(score, 4), round(confianca, 4)

        # PortScan: muitas portas destino únicas + pacotes pequenos
        if (leitura.portas_destino_unicas > self._threshold_portscan
                and leitura.tamanho_medio_pacote < 100):
            score -= 0.68
            confianca = min(0.60 + (leitura.portas_destino_unicas / 2000), 0.99)
            return True, "PORTSCAN", round(score, 4), round(confianca, 4)

        # Data Poisoning: anomalia sutil — detectada por desvio acumulado
        score_poisoning = 0.0
        if leitura.temperatura_cpu > self._threshold_temperatura:
            score_poisoning += 0.3
        if leitura.flags_tcp > 4:
            score_poisoning += 0.2
        if leitura.intervalo_medio_pacotes < 5:
            score_poisoning += 0.25

        if score_poisoning >= 0.5:
            score -= 0.55
            return True, "POISONING", round(score, 4), round(score_poisoning, 4)

        # Tráfego normal
        score = -0.1 + (np.random.random() * 0.05)  # Pequena variação
        return False, "NORMAL", round(score, 4), round(0.95, 4)

    @property
    def duracao_estimada_segundos(self):
        return 120.0  # Estimativa padrão para features derivadas


# ============================================================
# SERVIÇO PRINCIPAL
# ============================================================

class SensorService:
    """
    Serviço central de processamento de leituras de sensor.

    Orquestra o pipeline completo:
    Validação → Segurança → ML → Persistência → Alerta

    PADRÃO SINGLETON: uma única instância por processo da API.
    """

    _instancia: Optional["SensorService"] = None

    def __new__(cls) -> "SensorService":
        """Implementação do padrão Singleton."""
        if cls._instancia is None:
            cls._instancia = super().__new__(cls)
            cls._instancia._inicializado = False
        return cls._instancia

    def __init__(self):
        if self._inicializado:
            return
        self._modelo = ModeloMLSimulado()
        self._total_processadas = 0
        self._total_anomalias   = 0
        self._inicio            = time.time()
        self._inicializado      = True
        logger.info("[SensorService] ✅ Serviço inicializado (Singleton).")

    # ----------------------------------------------------------
    # MÉTODO PRINCIPAL
    # ----------------------------------------------------------

    def processar_leitura(
        self, leitura: SensorReadingInput
    ) -> SensorReadingResponse:
        """
        Pipeline completo de processamento de uma leitura de sensor.

        Etapas:
            1. Validar timestamp (anti-Replay Attack)
            2. Validar HMAC (autenticidade e integridade)
            3. Executar inferência do modelo ML
            4. Persistir resultado (simulado para POC)
            5. Emitir alerta se necessário
            6. Retornar resposta estruturada

        Args:
            leitura: dados validados pelo schema Pydantic

        Returns:
            SensorReadingResponse com resultado do processamento
        """
        self._total_processadas += 1
        inicio_proc = time.time()

        logger.info(
            f"[SVC] Processando leitura #{self._total_processadas} "
            f"| Station: {leitura.station_id}"
        )

        # --------------------------------------------------
        # ETAPA 1: Validar timestamp (anti-Replay Attack)
        # --------------------------------------------------
        if not validar_timestamp(leitura.timestamp_unix, tolerancia_s=300):
            logger.warning(
                f"[SVC] ⏰ Timestamp rejeitado "
                f"| Station: {leitura.station_id}"
            )
            return SensorReadingResponse(
                sucesso=False,
                mensagem="Timestamp fora da janela de aceitação. "
                         "Possível Replay Attack bloqueado."
            )

        # --------------------------------------------------
        # ETAPA 2: Validar HMAC
        # CONEXÃO CIBERSEGURANÇA: STRIDE #1 + #2
        # --------------------------------------------------
        payload_dict = leitura.model_dump()
        hmac_valido = validar_hmac(payload_dict, leitura.hash_hmac)

        if not hmac_valido:
            logger.warning(
                f"[SVC] 🔴 HMAC inválido — leitura rejeitada "
                f"| Station: {leitura.station_id}"
            )
            # Registrar evento de segurança (Tampering detectado)
            self._registrar_evento_seguranca(
                station_id=leitura.station_id,
                categoria="TAMPERING",
                descricao="HMAC inválido — possível adulteração do pacote em trânsito"
            )
            return SensorReadingResponse(
                sucesso=False,
                mensagem="Falha na validação de integridade (HMAC). "
                         "Leitura rejeitada. Evento STRIDE #2 registrado."
            )

        # --------------------------------------------------
        # ETAPA 3: Inferência do modelo de ML
        # CONEXÃO ML: chama o pipeline treinado no notebook
        # --------------------------------------------------
        leitura.duracao_conexao_estimada = 120.0  # Feature auxiliar

        anomalia, tipo_ataque, score, confianca = self._modelo.classificar(leitura)

        if anomalia:
            self._total_anomalias += 1
            logger.warning(
                f"[ML] 🚨 ANOMALIA DETECTADA: {tipo_ataque} "
                f"| Score: {score} | Confiança: {confianca:.2%} "
                f"| Station: {leitura.station_id}"
            )

        # --------------------------------------------------
        # ETAPA 4: Simular persistência no banco
        # Em produção: INSERT nas tabelas sensor_readings + ml_predictions
        # --------------------------------------------------
        reading_id = self._simular_persistencia(leitura, anomalia, tipo_ataque, score)

        # --------------------------------------------------
        # ETAPA 5: Emitir alerta se necessário
        # --------------------------------------------------
        alerta_emitido = False
        if anomalia and confianca >= 0.75:
            alerta_emitido = self._emitir_alerta(
                leitura.station_id, tipo_ataque, score, confianca, reading_id
            )

        # --------------------------------------------------
        # ETAPA 6: Montar resposta
        # --------------------------------------------------
        duracao_ms = round((time.time() - inicio_proc) * 1000, 2)
        logger.info(
            f"[SVC] ✅ Leitura #{reading_id} processada em {duracao_ms}ms "
            f"| Anomalia: {anomalia} | Tipo: {tipo_ataque}"
        )

        return SensorReadingResponse(
            sucesso=True,
            reading_id=reading_id,
            anomalia_detectada=anomalia,
            tipo_ataque=tipo_ataque if anomalia else None,
            score_anomalia=score,
            confianca=confianca if anomalia else None,
            alerta_emitido=alerta_emitido,
            mensagem=(
                f"Ataque {tipo_ataque} detectado com {confianca:.1%} de confiança."
                if anomalia else "Tráfego normal. Nenhuma ameaça detectada."
            )
        )

    # ----------------------------------------------------------
    # MÉTODOS AUXILIARES PRIVADOS
    # ----------------------------------------------------------

    def _simular_persistencia(
        self,
        leitura: SensorReadingInput,
        anomalia: bool,
        tipo_ataque: Optional[str],
        score: float
    ) -> int:
        """
        Simula a persistência no banco de dados.

        Em produção, este método executa:
            INSERT INTO orbit_shield.sensor_readings (...) VALUES (...)
            INSERT INTO orbit_shield.ml_predictions  (...) VALUES (...)

        Para a POC: gera um ID sequencial e loga os dados.
        """
        reading_id = self._total_processadas
        logger.info(
            f"[DB] INSERT sensor_readings #{reading_id} "
            f"| station: {leitura.station_id} "
            f"| temp: {leitura.temperatura_cpu}°C "
            f"| pacotes/s: {leitura.pacotes_por_segundo}"
        )
        if anomalia:
            logger.info(
                f"[DB] INSERT ml_predictions #{reading_id} "
                f"| tipo: {tipo_ataque} | score: {score}"
            )
        return reading_id

    def _emitir_alerta(
        self,
        station_id: str,
        tipo_ataque: str,
        score: float,
        confianca: float,
        reading_id: int
    ) -> bool:
        """
        Emite alerta de segurança para o dashboard e o banco.

        Em produção: INSERT em security_events + push notification
        ou integração com SIEM (Security Information and Event Management).
        """
        # Mapear tipo de ataque para categoria STRIDE
        stride_map = {
            "DDOS":        "DENIAL_OF_SERVICE",
            "BRUTEFORCE":  "SPOOFING",
            "PORTSCAN":    "INFORMATION_DISCLOSURE",
            "POISONING":   "ELEVATION_OF_PRIVILEGE",
        }
        categoria_stride = stride_map.get(tipo_ataque, "TAMPERING")

        severidade = "CRITICA" if confianca >= 0.90 else "ALTA"

        logger.warning(
            f"🚨 ALERTA {severidade} EMITIDO | "
            f"Station: {station_id} | "
            f"Ataque: {tipo_ataque} | "
            f"STRIDE: {categoria_stride} | "
            f"Confiança: {confianca:.1%} | "
            f"Reading ID: #{reading_id}"
        )
        return True

    def _registrar_evento_seguranca(
        self, station_id: str, categoria: str, descricao: str
    ):
        """Registra evento de segurança no audit log."""
        logger.warning(
            f"[AUDIT] SECURITY_EVENT | "
            f"Station: {station_id} | "
            f"Categoria: {categoria} | "
            f"{descricao}"
        )

    # ----------------------------------------------------------
    # PROPRIEDADES DE DIAGNÓSTICO
    # ----------------------------------------------------------

    @property
    def estatisticas(self) -> dict:
        """Retorna estatísticas de operação do serviço."""
        uptime = time.time() - self._inicio
        taxa_anomalia = (
            self._total_anomalias / max(self._total_processadas, 1) * 100
        )
        return {
            "total_leituras_processadas": self._total_processadas,
            "total_anomalias_detectadas": self._total_anomalias,
            "taxa_anomalia_pct":          round(taxa_anomalia, 2),
            "uptime_segundos":            round(uptime, 1),
            "modelo_carregado":           True,
        }


# Instância global do serviço (Singleton)
sensor_service = SensorService()
