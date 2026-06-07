-- ============================================================
-- ORBIT-SHIELD | Script 02 — DML: Dados de Exemplo + Queries
-- Global Solution 2026.1 — FIAP
-- Disciplina: Banco de Dados
-- ============================================================

SET search_path TO orbit_shield;

-- ------------------------------------------------------------
-- 1. INSERÇÃO DE DADOS DE EXEMPLO
-- ------------------------------------------------------------

-- 1.1 Ground Stations
INSERT INTO orbit_shield.ground_stations
    (nome, localizacao, latitude, longitude, operadora)
VALUES
    ('GS-BRASILIA-01', 'Brasília, DF — Brasil',        -15.7942, -47.8822, 'INPE'),
    ('GS-MANAUS-01',   'Manaus, AM — Brasil',           -3.1190, -60.0217, 'INPE'),
    ('GS-FORTALEZA-01','Fortaleza, CE — Brasil',        -3.7172, -38.5433, 'Embratel'),
    ('GS-CUIABA-01',   'Cuiabá, MT — Brasil',          -15.5989, -56.0949, 'Embratel');

-- Capturar IDs para uso nas próximas inserções
DO $$
DECLARE
    v_gs_bsb UUID;
    v_gs_man UUID;
    v_sensor_temp UUID;
    v_sensor_rf   UUID;
    v_sensor_net  UUID;
BEGIN
    SELECT id INTO v_gs_bsb FROM orbit_shield.ground_stations WHERE nome = 'GS-BRASILIA-01';
    SELECT id INTO v_gs_man FROM orbit_shield.ground_stations WHERE nome = 'GS-MANAUS-01';

    -- 1.2 Sensores da estação Brasília
    INSERT INTO orbit_shield.sensors (station_id, tipo, unidade, descricao)
    VALUES
        (v_gs_bsb, 'TEMPERATURA', '°C',    'Sensor de temperatura do rack principal'),
        (v_gs_bsb, 'RF_SIGNAL',   'dBm',   'Monitor de intensidade do sinal RF'),
        (v_gs_bsb, 'ENERGIA',     'Watts', 'Medidor de consumo energético'),
        (v_gs_bsb, 'REDE',        'bps',   'Monitor de tráfego de rede'),
        (v_gs_man, 'TEMPERATURA', '°C',    'Sensor de temperatura do rack principal'),
        (v_gs_man, 'RF_SIGNAL',   'dBm',   'Monitor de intensidade do sinal RF'),
        (v_gs_man, 'REDE',        'bps',   'Monitor de tráfego de rede');

    -- 1.3 Leituras simuladas — tráfego NORMAL
    SELECT id INTO v_sensor_temp
    FROM orbit_shield.sensors WHERE station_id = v_gs_bsb AND tipo = 'TEMPERATURA';

    SELECT id INTO v_sensor_net
    FROM orbit_shield.sensors WHERE station_id = v_gs_bsb AND tipo = 'REDE';

    -- Inserir 10 leituras normais nas últimas 2 horas
    INSERT INTO orbit_shield.sensor_readings
        (sensor_id, station_id, timestamp, temperatura_cpu, sinal_rf_dbm,
         consumo_energia_w, bytes_enviados, bytes_recebidos,
         pacotes_por_seg, flags_tcp, tentativas_auth, portas_unicas,
         intervalo_pacotes, hash_hmac, integridade_ok, versao_firmware)
    SELECT
        v_sensor_net,
        v_gs_bsb,
        NOW() - (generate_series * INTERVAL '12 minutes'),
        42.0 + random() * 5,       -- temperatura normal: 42-47°C
        -65.0 + random() * 10,     -- sinal RF normal: -65 a -55 dBm
        350.0 + random() * 50,     -- energia normal: 350-400W
        (45000 + random() * 10000)::BIGINT,
        (72000 + random() * 15000)::BIGINT,
        45.0 + random() * 15,
        (random() * 2)::SMALLINT,
        1,
        (1 + random() * 3)::INTEGER,
        18.0 + random() * 5,
        md5(random()::text),       -- hash simulado
        TRUE,
        'v2.3.1'
    FROM generate_series(1, 10);

    -- 1.4 Leitura com anomalia (DDoS simulado)
    INSERT INTO orbit_shield.sensor_readings
        (sensor_id, station_id, timestamp, temperatura_cpu, sinal_rf_dbm,
         consumo_energia_w, bytes_enviados, bytes_recebidos,
         pacotes_por_seg, flags_tcp, tentativas_auth, portas_unicas,
         intervalo_pacotes, hash_hmac, integridade_ok, versao_firmware)
    VALUES
        (v_sensor_net, v_gs_bsb, NOW() - INTERVAL '5 minutes',
         68.5,      -- temperatura elevada (CPU sobrecarregada)
         -72.0,     -- sinal degradado
         680.0,     -- consumo anormal: 680W
         215000,    -- bytes enviados muito alto
         4200,      -- bytes recebidos muito baixo
         4850.0,    -- pacotes/seg: 4850 (normal é 50)
         12,        -- muitos flags TCP
         1,
         2,
         0.2,       -- intervalo curtíssimo entre pacotes
         md5('ddos_simulado'),
         TRUE,
         'v2.3.1');

    -- 1.5 Leitura com hash comprometido (Tampering detectado)
    INSERT INTO orbit_shield.sensor_readings
        (sensor_id, station_id, timestamp, temperatura_cpu,
         bytes_enviados, bytes_recebidos, pacotes_por_seg,
         flags_tcp, tentativas_auth, portas_unicas,
         hash_hmac, integridade_ok, versao_firmware)
    VALUES
        (v_sensor_net, v_gs_man, NOW() - INTERVAL '15 minutes',
         44.0, 48000, 76000, 52.0, 1, 1, 2,
         'hash_adulterado_000000000000000000000000000000',
         FALSE,   -- <-- integridade comprometida: STRIDE Tampering
         'v2.3.1');

    RAISE NOTICE '✅ Dados de exemplo inseridos com sucesso.';
END $$;

-- 1.6 Predição ML para a leitura de DDoS
-- (em produção, este INSERT é feito automaticamente pelo pipeline Python)
INSERT INTO orbit_shield.ml_predictions
    (reading_id, station_id, timestamp,
     anomalia_detectada, score_anomalia,
     tipo_ataque, confianca, alerta_emitido, alerta_timestamp)
SELECT
    sr.id,
    sr.station_id,
    NOW() - INTERVAL '4 minutes',
    TRUE,
    -0.8742,      -- score muito negativo = alta anomalia
    'DDOS',
    0.9321,       -- 93.21% de confiança
    TRUE,
    NOW() - INTERVAL '4 minutes'
FROM orbit_shield.sensor_readings sr
WHERE sr.pacotes_por_seg > 1000
LIMIT 1;

-- 1.7 Evento de segurança gerado pelo alerta
INSERT INTO orbit_shield.security_events
    (station_id, prediction_id, timestamp,
     categoria_stride, tipo_ataque, severidade, descricao,
     hash_evento, hash_anterior)
SELECT
    mp.station_id,
    mp.id,
    NOW() - INTERVAL '4 minutes',
    'DENIAL_OF_SERVICE',
    'DDOS',
    'CRITICA',
    'Ataque DDoS detectado: taxa de pacotes 4850/s (limiar: 200/s). '
    'Score de anomalia: -0.8742. Confiança do modelo: 93.21%.',
    md5('ddos_event_' || mp.id::text),
    'genesis_block_orbit_shield_2026'
FROM orbit_shield.ml_predictions mp
WHERE mp.tipo_ataque = 'DDOS'
LIMIT 1;

-- ============================================================
-- 2. QUERIES DE ANÁLISE (DML) — Documentadas para o PDF
-- ============================================================

-- ------------------------------------------------------------
-- QUERY 1: Dashboard — Alertas críticos não resolvidos
-- USO: Alimenta o painel principal do ORBIT-SHIELD em tempo real
-- ------------------------------------------------------------
SELECT
    v.evento_id,
    v.estacao,
    v.localizacao,
    TO_CHAR(v.timestamp, 'DD/MM/YYYY HH24:MI:SS')  AS horario,
    v.categoria_stride,
    v.tipo_ataque,
    v.severidade,
    ROUND(v.score_anomalia::NUMERIC, 4)             AS score_anomalia,
    ROUND((v.confianca_modelo * 100)::NUMERIC, 2)   AS confianca_pct,
    ROUND(v.minutos_desde_evento::NUMERIC, 1)       AS minutos_atras
FROM orbit_shield.vw_dashboard_alertas v
WHERE
    v.resolvido    = FALSE
    AND v.severidade IN ('ALTA', 'CRITICA')
ORDER BY
    v.timestamp DESC;

-- ------------------------------------------------------------
-- QUERY 2: Agregação temporal — Média de leituras por hora
-- USO: Gráfico de série temporal no dashboard (Streamlit/Matplotlib)
-- DECISÃO: DATE_TRUNC agrupa por hora — eficiente com índice BRIN
-- ------------------------------------------------------------
SELECT
    DATE_TRUNC('hour', sr.timestamp)               AS hora,
    gs.nome                                        AS estacao,
    ROUND(AVG(sr.temperatura_cpu)::NUMERIC, 2)    AS temp_media_cpu,
    ROUND(AVG(sr.pacotes_por_seg)::NUMERIC, 2)    AS pacotes_media,
    ROUND(AVG(sr.consumo_energia_w)::NUMERIC, 2)  AS energia_media_w,
    SUM(sr.bytes_enviados)                         AS total_bytes_enviados,
    COUNT(*)                                       AS total_leituras,
    SUM(CASE WHEN sr.integridade_ok = FALSE THEN 1 ELSE 0 END) AS leituras_comprometidas
FROM
    orbit_shield.sensor_readings sr
    JOIN orbit_shield.ground_stations gs ON gs.id = sr.station_id
WHERE
    sr.timestamp >= NOW() - INTERVAL '24 hours'
GROUP BY
    DATE_TRUNC('hour', sr.timestamp), gs.nome
ORDER BY
    hora DESC, gs.nome;

-- ------------------------------------------------------------
-- QUERY 3: Contagem de ataques por tipo e estação (últimos 7 dias)
-- USO: Gráfico de barras no dashboard e relatório PDF
-- ------------------------------------------------------------
SELECT
    gs.nome                                         AS estacao,
    mp.tipo_ataque,
    COUNT(*)                                        AS total_deteccoes,
    ROUND(AVG(mp.score_anomalia)::NUMERIC, 4)      AS score_medio,
    ROUND(AVG(mp.confianca)::NUMERIC, 4)           AS confianca_media,
    SUM(CASE WHEN mp.alerta_emitido THEN 1 ELSE 0 END) AS alertas_emitidos,
    MAX(mp.timestamp)                               AS ultima_deteccao
FROM
    orbit_shield.ml_predictions mp
    JOIN orbit_shield.ground_stations gs ON gs.id = mp.station_id
WHERE
    mp.anomalia_detectada = TRUE
    AND mp.timestamp >= NOW() - INTERVAL '7 days'
GROUP BY
    gs.nome, mp.tipo_ataque
ORDER BY
    total_deteccoes DESC;

-- ------------------------------------------------------------
-- QUERY 4: Detecção de leituras com integridade comprometida
-- USO: Contramedida STRIDE #2 (Tampering) — alert imediato
-- DECISÃO: Índice parcial em integridade_ok=FALSE torna esta
--          query extremamente rápida mesmo com milhões de registros
-- ------------------------------------------------------------
SELECT
    sr.id                                           AS reading_id,
    gs.nome                                         AS estacao,
    TO_CHAR(sr.timestamp, 'DD/MM/YYYY HH24:MI:SS') AS horario,
    sr.hash_hmac,
    sr.versao_firmware,
    'HASH_INVALIDO — Possível ataque de Tampering (STRIDE #2)' AS alerta
FROM
    orbit_shield.sensor_readings sr
    JOIN orbit_shield.ground_stations gs ON gs.id = sr.station_id
WHERE
    sr.integridade_ok = FALSE
ORDER BY
    sr.timestamp DESC;

-- ------------------------------------------------------------
-- QUERY 5: Análise de distribuição de ataques por categoria STRIDE
-- USO: Gráfico de pizza no PDF e relatório de conformidade
-- ------------------------------------------------------------
SELECT
    se.categoria_stride,
    se.severidade,
    COUNT(*)                                        AS total_eventos,
    SUM(CASE WHEN se.resolvido THEN 1 ELSE 0 END)  AS resolvidos,
    SUM(CASE WHEN NOT se.resolvido THEN 1 ELSE 0 END) AS pendentes,
    ROUND(
        100.0 * COUNT(*) / SUM(COUNT(*)) OVER (),
        2
    )                                               AS percentual
FROM
    orbit_shield.security_events se
GROUP BY
    se.categoria_stride, se.severidade
ORDER BY
    total_eventos DESC;

-- ------------------------------------------------------------
-- QUERY 6: Ranking de estações por nível de risco
-- USO: Mapa de risco no dashboard
-- ------------------------------------------------------------
SELECT
    gs.nome                                         AS estacao,
    gs.localizacao,
    COUNT(se.id)                                    AS total_eventos,
    SUM(CASE WHEN se.severidade = 'CRITICA' THEN 1 ELSE 0 END) AS criticos,
    SUM(CASE WHEN se.severidade = 'ALTA'    THEN 1 ELSE 0 END) AS altos,
    SUM(CASE WHEN NOT se.resolvido          THEN 1 ELSE 0 END) AS pendentes,
    CASE
        WHEN SUM(CASE WHEN se.severidade = 'CRITICA' THEN 1 ELSE 0 END) > 0 THEN '🔴 CRÍTICO'
        WHEN SUM(CASE WHEN se.severidade = 'ALTA'    THEN 1 ELSE 0 END) > 3 THEN '🟠 ALTO'
        WHEN COUNT(se.id) > 0                                             THEN '🟡 MÉDIO'
        ELSE '🟢 NORMAL'
    END                                             AS nivel_risco
FROM
    orbit_shield.ground_stations gs
    LEFT JOIN orbit_shield.security_events se ON se.station_id = gs.id
        AND se.timestamp >= NOW() - INTERVAL '30 days'
GROUP BY
    gs.id, gs.nome, gs.localizacao
ORDER BY
    criticos DESC, altos DESC, total_eventos DESC;

-- Confirmação
SELECT
    'orbit_shield' AS schema,
    COUNT(*)       AS total_tabelas
FROM information_schema.tables
WHERE table_schema = 'orbit_shield'
  AND table_type   = 'BASE TABLE';
