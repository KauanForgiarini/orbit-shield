-- ============================================================
-- ORBIT-SHIELD | Script 01 — DDL: Criação do Banco de Dados
-- Global Solution 2026.1 — FIAP
-- Disciplina: Banco de Dados
-- ============================================================
-- DECISÃO DE ARQUITETURA:
--   Usamos PostgreSQL puro (sem TimescaleDB) para garantir
--   compatibilidade máxima com ambientes sem extensões instaladas.
--   A estrutura de particionamento por data é feita manualmente
--   via índices BRIN, adequados para séries temporais em PostgreSQL nativo.
--
-- CONEXÃO COM OUTROS PILARES:
--   → sensor_readings: alimentada pelo ESP32 via C/C++ (Pilar IoT)
--   → ml_predictions:  alimentada pelo pipeline Python/ML (Pilar ML)
--   → security_events: base do mapa STRIDE (Pilar Cibersegurança)
--   → audit_log:       conformidade LGPD (Pilar Cibersegurança)
-- ============================================================

-- ------------------------------------------------------------
-- 0. SETUP INICIAL
-- ------------------------------------------------------------

-- Criar banco (rodar separadamente no psql se necessário)
-- CREATE DATABASE orbit_shield;
-- \c orbit_shield

-- Remover schema anterior em caso de re-execução (desenvolvimento)
DROP SCHEMA IF EXISTS orbit_shield CASCADE;
CREATE SCHEMA orbit_shield;
SET search_path TO orbit_shield;

-- Extensão para UUIDs (identificadores únicos universais)
-- Evita colisões de IDs entre múltiplos sensores/estações
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ------------------------------------------------------------
-- 1. TABELA: ground_stations
--    Cadastro das estações terrestres monitoradas
--    DECISÃO: chave primária UUID em vez de SERIAL para
--    suportar múltiplas estações distribuídas sem conflito de ID
-- ------------------------------------------------------------
CREATE TABLE orbit_shield.ground_stations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nome            VARCHAR(100) NOT NULL,
    localizacao     VARCHAR(150) NOT NULL,
    latitude        NUMERIC(9,6) NOT NULL,
    longitude       NUMERIC(9,6) NOT NULL,
    operadora       VARCHAR(100),
    data_instalacao DATE NOT NULL DEFAULT CURRENT_DATE,
    ativa           BOOLEAN NOT NULL DEFAULT TRUE,
    criado_em       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraint: coordenadas válidas
    CONSTRAINT chk_latitude  CHECK (latitude  BETWEEN -90  AND 90),
    CONSTRAINT chk_longitude CHECK (longitude BETWEEN -180 AND 180)
);

COMMENT ON TABLE orbit_shield.ground_stations IS
    'Cadastro das ground stations satelitais monitoradas pelo ORBIT-SHIELD';

-- ------------------------------------------------------------
-- 2. TABELA: sensors
--    Sensores físicos cadastrados por estação (ESP32)
--    DECISÃO: normalização em tabela separada permite adicionar
--    novos tipos de sensor sem alterar a estrutura principal
-- ------------------------------------------------------------
CREATE TABLE orbit_shield.sensors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    station_id      UUID NOT NULL REFERENCES orbit_shield.ground_stations(id)
                         ON DELETE CASCADE,
    tipo            VARCHAR(50) NOT NULL,    -- ex: TEMPERATURA, RF_SIGNAL, ENERGIA
    unidade         VARCHAR(20) NOT NULL,    -- ex: Celsius, dBm, Watts
    descricao       VARCHAR(200),
    ativo           BOOLEAN NOT NULL DEFAULT TRUE,
    criado_em       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Um sensor tem tipo único por estação
    CONSTRAINT uq_sensor_tipo_station UNIQUE (station_id, tipo)
);

COMMENT ON TABLE orbit_shield.sensors IS
    'Sensores físicos (ESP32) registrados por ground station';

-- ------------------------------------------------------------
-- 3. TABELA: sensor_readings (TABELA PRINCIPAL DE SÉRIE TEMPORAL)
--    Leituras brutas dos sensores — maior volume do sistema
--    DECISÃO DE ÍNDICES:
--      → BRIN em timestamp: ideal para séries temporais (baixo custo de storage)
--      → BTREE em sensor_id: queries por sensor específico
--      → Índice composto (sensor_id, timestamp): range queries temporais
-- ------------------------------------------------------------
CREATE TABLE orbit_shield.sensor_readings (
    id              BIGSERIAL PRIMARY KEY,
    sensor_id       UUID NOT NULL REFERENCES orbit_shield.sensors(id),
    station_id      UUID NOT NULL REFERENCES orbit_shield.ground_stations(id),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Leituras do sensor (baseadas nas features do modelo ML)
    temperatura_cpu     NUMERIC(6,2),   -- °C
    sinal_rf_dbm        NUMERIC(8,2),   -- dBm (intensidade do sinal)
    consumo_energia_w   NUMERIC(8,2),   -- Watts
    bytes_enviados      BIGINT,         -- bytes na janela de leitura
    bytes_recebidos     BIGINT,         -- bytes na janela de leitura
    pacotes_por_seg     NUMERIC(10,2),  -- taxa de pacotes
    flags_tcp           SMALLINT,       -- contagem de flags TCP anômalos
    tentativas_auth     SMALLINT,       -- tentativas de autenticação
    portas_unicas       INTEGER,        -- portas destino únicas
    intervalo_pacotes   NUMERIC(8,2),   -- ms entre pacotes

    -- Integridade do pacote (validação do hash HMAC do ESP32)
    -- CONEXÃO C/C++: hash gerado no firmware e validado aqui
    hash_hmac           VARCHAR(64),    -- HMAC-SHA256 do payload
    integridade_ok      BOOLEAN NOT NULL DEFAULT TRUE,

    -- Metadados
    versao_firmware     VARCHAR(20),
    ruido_filtrado      BOOLEAN DEFAULT FALSE  -- indica se passou pelo filtro de ruído
);

-- Índices otimizados para série temporal
CREATE INDEX idx_readings_timestamp    ON orbit_shield.sensor_readings USING BRIN (timestamp);
CREATE INDEX idx_readings_sensor       ON orbit_shield.sensor_readings (sensor_id);
CREATE INDEX idx_readings_station_time ON orbit_shield.sensor_readings (station_id, timestamp DESC);
CREATE INDEX idx_readings_integridade  ON orbit_shield.sensor_readings (integridade_ok)
    WHERE integridade_ok = FALSE;  -- Índice parcial: apenas registros comprometidos

COMMENT ON TABLE orbit_shield.sensor_readings IS
    'Série temporal de leituras dos sensores ESP32. Alto volume — índices BRIN otimizados.';

-- ------------------------------------------------------------
-- 4. TABELA: ml_predictions
--    Predições do pipeline de ML armazenadas por leitura
--    CONEXÃO ML: resultado direto do Isolation Forest + Random Forest
-- ------------------------------------------------------------
CREATE TABLE orbit_shield.ml_predictions (
    id                  BIGSERIAL PRIMARY KEY,
    reading_id          BIGINT NOT NULL REFERENCES orbit_shield.sensor_readings(id),
    station_id          UUID NOT NULL REFERENCES orbit_shield.ground_stations(id),
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Resultado do Isolation Forest (detecção de anomalia)
    anomalia_detectada  BOOLEAN NOT NULL,
    score_anomalia      NUMERIC(8,4),   -- quanto mais negativo, mais suspeito

    -- Resultado do Random Forest (classificação do tipo)
    tipo_ataque         VARCHAR(30),    -- NORMAL, DDOS, PORTSCAN, BRUTEFORCE, POISONING
    confianca           NUMERIC(5,4),   -- probabilidade da predição (0.0 a 1.0)

    -- Alerta gerado
    alerta_emitido      BOOLEAN NOT NULL DEFAULT FALSE,
    alerta_timestamp    TIMESTAMPTZ,

    -- Versão do modelo usado (rastreabilidade)
    versao_modelo       VARCHAR(20) DEFAULT 'v1.0',

    CONSTRAINT chk_confianca CHECK (confianca BETWEEN 0 AND 1)
);

CREATE INDEX idx_predictions_anomalia   ON orbit_shield.ml_predictions (anomalia_detectada)
    WHERE anomalia_detectada = TRUE;
CREATE INDEX idx_predictions_tipo       ON orbit_shield.ml_predictions (tipo_ataque);
CREATE INDEX idx_predictions_timestamp  ON orbit_shield.ml_predictions USING BRIN (timestamp);
CREATE INDEX idx_predictions_station    ON orbit_shield.ml_predictions (station_id, timestamp DESC);

COMMENT ON TABLE orbit_shield.ml_predictions IS
    'Predições do pipeline ML (Isolation Forest + Random Forest) por leitura de sensor';

-- ------------------------------------------------------------
-- 5. TABELA: security_events
--    Eventos de segurança confirmados — base do painel de alertas
--    CONEXÃO CIBERSEGURANÇA: alimenta o relatório STRIDE em tempo real
-- ------------------------------------------------------------
CREATE TABLE orbit_shield.security_events (
    id              BIGSERIAL PRIMARY KEY,
    station_id      UUID NOT NULL REFERENCES orbit_shield.ground_stations(id),
    prediction_id   BIGINT REFERENCES orbit_shield.ml_predictions(id),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Classificação do evento (baseada no STRIDE)
    categoria_stride    VARCHAR(30) NOT NULL,  -- SPOOFING, TAMPERING, REPUDIATION, etc.
    tipo_ataque         VARCHAR(30) NOT NULL,  -- DDOS, PORTSCAN, BRUTEFORCE, POISONING
    severidade          VARCHAR(10) NOT NULL,  -- BAIXA, MEDIA, ALTA, CRITICA
    descricao           TEXT,

    -- Status de resolução
    resolvido           BOOLEAN NOT NULL DEFAULT FALSE,
    resolvido_em        TIMESTAMPTZ,
    responsavel         VARCHAR(100),

    -- Hash encadeado para imutabilidade do log
    -- CONEXÃO CIBERSEGURANÇA: contramedida STRIDE #3 (Repudiation)
    hash_evento         VARCHAR(64),   -- SHA-256 do conteúdo do evento
    hash_anterior       VARCHAR(64),   -- hash do evento anterior (encadeamento)

    CONSTRAINT chk_severidade CHECK (severidade IN ('BAIXA', 'MEDIA', 'ALTA', 'CRITICA')),
    CONSTRAINT chk_stride CHECK (categoria_stride IN (
        'SPOOFING', 'TAMPERING', 'REPUDIATION',
        'INFORMATION_DISCLOSURE', 'DENIAL_OF_SERVICE', 'ELEVATION_OF_PRIVILEGE'
    ))
);

CREATE INDEX idx_events_station       ON orbit_shield.security_events (station_id, timestamp DESC);
CREATE INDEX idx_events_severidade    ON orbit_shield.security_events (severidade);
CREATE INDEX idx_events_nao_resolvido ON orbit_shield.security_events (resolvido)
    WHERE resolvido = FALSE;

COMMENT ON TABLE orbit_shield.security_events IS
    'Eventos de segurança confirmados. Hash encadeado garante imutabilidade (anti-repudiation).';

-- ------------------------------------------------------------
-- 6. TABELA: audit_log
--    Log de auditoria de todas as operações — conformidade LGPD
--    DECISÃO: tabela APPEND-ONLY (sem UPDATE/DELETE) — garantida via trigger
-- ------------------------------------------------------------
CREATE TABLE orbit_shield.audit_log (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tabela          VARCHAR(50) NOT NULL,
    operacao        VARCHAR(10) NOT NULL,   -- INSERT, UPDATE, DELETE, SELECT
    usuario_db      VARCHAR(100) NOT NULL DEFAULT CURRENT_USER,
    ip_origem       INET,
    registro_id     TEXT,                  -- ID do registro afetado
    dados_antes     JSONB,                 -- estado anterior (UPDATE/DELETE)
    dados_depois    JSONB,                 -- estado posterior (INSERT/UPDATE)
    justificativa   TEXT                   -- obrigatório para operações sensíveis
);

-- Índice para auditoria por período
CREATE INDEX idx_audit_timestamp ON orbit_shield.audit_log USING BRIN (timestamp);
CREATE INDEX idx_audit_tabela    ON orbit_shield.audit_log (tabela, operacao);

COMMENT ON TABLE orbit_shield.audit_log IS
    'Log de auditoria imutável. Conformidade LGPD — rastreabilidade de todas as operações.';

-- ------------------------------------------------------------
-- 7. TRIGGER: Proteção da audit_log (APPEND-ONLY)
--    Impede UPDATE e DELETE na tabela de auditoria
--    CONEXÃO CIBERSEGURANÇA: contramedida contra adulteração de logs
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION orbit_shield.proteger_audit_log()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'ORBIT-SHIELD SECURITY: Operação % proibida na tabela audit_log. '
        'Logs de auditoria são imutáveis (LGPD + STRIDE Repudiation).', TG_OP;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_proteger_audit
    BEFORE UPDATE OR DELETE ON orbit_shield.audit_log
    FOR EACH ROW EXECUTE FUNCTION orbit_shield.proteger_audit_log();

-- ------------------------------------------------------------
-- 8. VIEW: vw_dashboard_alertas
--    View materializada para o dashboard — evita queries pesadas
--    em tempo real no painel de monitoramento
-- ------------------------------------------------------------
CREATE VIEW orbit_shield.vw_dashboard_alertas AS
SELECT
    se.id                                           AS evento_id,
    gs.nome                                         AS estacao,
    gs.localizacao,
    se.timestamp,
    se.categoria_stride,
    se.tipo_ataque,
    se.severidade,
    se.descricao,
    se.resolvido,
    mp.score_anomalia,
    mp.confianca                                    AS confianca_modelo,
    EXTRACT(EPOCH FROM (NOW() - se.timestamp))/60  AS minutos_desde_evento
FROM
    orbit_shield.security_events se
    JOIN orbit_shield.ground_stations gs ON gs.id = se.station_id
    LEFT JOIN orbit_shield.ml_predictions mp ON mp.id = se.prediction_id
ORDER BY
    se.timestamp DESC;

COMMENT ON VIEW orbit_shield.vw_dashboard_alertas IS
    'View para o dashboard de segurança. Combina eventos, estações e predições ML.';

-- Confirmação
DO $$
BEGIN
    RAISE NOTICE '✅ ORBIT-SHIELD: Schema criado com sucesso.';
    RAISE NOTICE '   Tabelas: ground_stations, sensors, sensor_readings, ml_predictions, security_events, audit_log';
    RAISE NOTICE '   Views: vw_dashboard_alertas';
    RAISE NOTICE '   Triggers: trg_proteger_audit';
END $$;
