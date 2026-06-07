"""
============================================================
ORBIT-SHIELD | models/schemas.py — Validação de Dados
Global Solution 2026.1 — FIAP
Disciplina: Programação Python (POO + Clean Code)
============================================================
"""

from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional
from datetime import datetime
import re


class SensorReadingBase(BaseModel):
    station_id:   str = Field(..., min_length=3, max_length=32)
    firmware_ver: str = Field(..., pattern=r"^v\d+\.\d+\.\d+$")


class SensorReadingInput(SensorReadingBase):
    timestamp_unix:          int   = Field(..., gt=1700000000)
    temperatura_cpu:         float = Field(..., ge=-10.0, le=120.0)
    sinal_rf_dbm:            float = Field(..., ge=-120.0, le=0.0)
    consumo_energia_w:       float = Field(..., ge=0.0, le=5000.0)
    bytes_enviados:          int   = Field(..., ge=0)
    bytes_recebidos:         int   = Field(..., ge=0)
    pacotes_por_segundo:     float = Field(..., ge=0.0, le=100000.0)
    flags_tcp:               int   = Field(..., ge=0, le=63)
    tentativas_auth:         int   = Field(..., ge=0, le=10000)
    portas_destino_unicas:   int   = Field(..., ge=0, le=65535)
    intervalo_medio_pacotes: float = Field(..., ge=0.0, le=10000.0)
    tamanho_medio_pacote:    float = Field(..., ge=0.0, le=65535.0)
    hash_hmac:               str   = Field(..., min_length=64, max_length=64)
    integridade_ok:          bool  = Field(default=True)
    anomalia_local:          bool  = Field(default=False)
    tipo_anomalia:           str   = Field(default="", max_length=32)

    # Campo auxiliar usado internamente pelo service (não vem do ESP32)
    duracao_conexao_estimada: float = Field(default=120.0, exclude=True)

    @field_validator("station_id")
    @classmethod
    def validar_station_id(cls, v: str) -> str:
        if not re.match(r"^[A-Z0-9\-]+$", v):
            raise ValueError("station_id contém caracteres inválidos.")
        return v

    @field_validator("hash_hmac")
    @classmethod
    def validar_formato_hmac(cls, v: str) -> str:
        if not re.match(r"^[a-fA-F0-9]{64}$", v):
            raise ValueError("hash_hmac deve ser hexadecimal de 64 caracteres.")
        return v.lower()

    @field_validator("tipo_anomalia")
    @classmethod
    def validar_tipo_anomalia(cls, v: str) -> str:
        tipos_validos = {
            "", "TEMP_ALTA_CPU", "DDOS_SUSPEITO",
            "BRUTEFORCE_SUSPEITO", "RF_DEGRADADO", "ENERGIA_ANORMAL"
        }
        return v if v in tipos_validos else "ANOMALIA_DESCONHECIDA"

    class Config:
        json_schema_extra = {
            "example": {
                "station_id":              "GS-BRASILIA-01",
                "firmware_ver":            "v2.3.1",
                "timestamp_unix":          1748908200,
                "temperatura_cpu":         44.23,
                "sinal_rf_dbm":            -61.80,
                "consumo_energia_w":       372.50,
                "bytes_enviados":          51420,
                "bytes_recebidos":         79830,
                "pacotes_por_segundo":     49.80,
                "flags_tcp":               1,
                "tentativas_auth":         2,
                "portas_destino_unicas":   3,
                "intervalo_medio_pacotes": 19.42,
                "tamanho_medio_pacote":    508.30,
                "hash_hmac":               "a" * 64,
                "integridade_ok":          True,
                "anomalia_local":          False,
                "tipo_anomalia":           ""
            }
        }


class SensorReadingResponse(BaseModel):
    sucesso:            bool
    reading_id:         Optional[int]   = None
    anomalia_detectada: bool            = False
    tipo_ataque:        Optional[str]   = None
    score_anomalia:     Optional[float] = None
    confianca:          Optional[float] = None
    alerta_emitido:     bool            = False
    mensagem:           str             = ""
    timestamp_api:      datetime        = Field(default_factory=datetime.now)


class AlertaResponse(BaseModel):
    evento_id:        int
    estacao:          str
    localizacao:      str
    horario:          str
    categoria_stride: str
    tipo_ataque:      str
    severidade:       str
    descricao:        str
    resolvido:        bool
    score_anomalia:   Optional[float]
    confianca_modelo: Optional[float]
    minutos_atras:    float


class HealthResponse(BaseModel):
    status:    str
    versao:    str
    uptime_s:  float
    banco_ok:  bool
    modelo_ok: bool
    timestamp: datetime = Field(default_factory=datetime.now)
