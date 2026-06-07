"""
============================================================
ORBIT-SHIELD | dashboard.py — Painel de Monitoramento
Global Solution 2026.1 — FIAP
Disciplinas: Programação Python + Machine Learning
============================================================

DESCRIÇÃO:
    Dashboard interativo que consolida todos os pilares
    do ORBIT-SHIELD em uma única interface visual:

    → Série temporal dos sensores ESP32     (C/C++ → BD → Dashboard)
    → Alertas de segurança em tempo real    (Cibersegurança → Dashboard)
    → Métricas do modelo de ML              (ML → Dashboard)
    → Mapa de risco por estação             (BD → Dashboard)

COMO RODAR:
    pip install -r requirements.txt
    streamlit run dashboard.py

    Acesse: http://localhost:8501
============================================================
"""

import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
import time
from datetime import datetime, timedelta

# ============================================================
# CONFIGURAÇÃO DA PÁGINA
# ============================================================
st.set_page_config(
    page_title="🛰️ ORBIT-SHIELD",
    page_icon="🛰️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS customizado para aparência profissional
st.markdown("""
<style>
    /* Fundo escuro no header */
    .main-header {
        background: linear-gradient(135deg, #0a0a1a 0%, #1a1a3e 50%, #0d2137 100%);
        padding: 20px 30px;
        border-radius: 12px;
        margin-bottom: 20px;
        border: 1px solid #2a4a6b;
    }
    /* Cards de métricas customizados */
    .metric-card {
        background: #0d1117;
        border: 1px solid #21262d;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }
    /* Alertas críticos */
    .alerta-critico {
        background: linear-gradient(90deg, #3d0000, #1a0000);
        border-left: 4px solid #ff4444;
        padding: 12px 16px;
        border-radius: 0 8px 8px 0;
        margin: 8px 0;
    }
    .alerta-alto {
        background: linear-gradient(90deg, #3d2000, #1a1000);
        border-left: 4px solid #ff8800;
        padding: 12px 16px;
        border-radius: 0 8px 8px 0;
        margin: 8px 0;
    }
    /* Tabela de status */
    .status-ok    { color: #00ff88; font-weight: bold; }
    .status-alert { color: #ff4444; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# ============================================================
# GERAÇÃO DE DADOS SIMULADOS
# Estes dados representam o que viria do banco de dados (BD)
# via as queries do script 02_dml_dados_queries.sql
# ============================================================

@st.cache_data(ttl=30)  # Cache de 30 segundos — simula atualização periódica
def gerar_serie_temporal(horas: int = 24, station: str = "GS-BRASILIA-01"):
    """
    Gera série temporal simulada de leituras de sensor.
    Em produção: executa Query 2 do script DML no PostgreSQL.

    CONEXÃO BD: simula resultado da agregação por hora com
    DATE_TRUNC('hour', timestamp) do script 02_dml_dados_queries.sql
    """
    np.random.seed(42)
    timestamps = [
        datetime.now() - timedelta(minutes=10 * i)
        for i in range(horas * 6)  # leitura a cada 10 min
    ]
    timestamps.reverse()

    n = len(timestamps)

    # Simular um ataque DDoS entre os minutos 80-100
    ataque_inicio = int(n * 0.60)
    ataque_fim    = int(n * 0.68)

    temperatura    = np.random.normal(44, 3, n)
    pacotes        = np.random.normal(50, 8, n)
    energia        = np.random.normal(370, 20, n)
    bytes_env      = np.random.normal(50000, 8000, n)
    tentativas     = np.random.randint(1, 4, n).astype(float)

    # Inserir anomalia de DDoS no período de ataque
    temperatura[ataque_inicio:ataque_fim]  += np.random.normal(22, 3, ataque_fim - ataque_inicio)
    pacotes[ataque_inicio:ataque_fim]      += np.random.normal(4700, 200, ataque_fim - ataque_inicio)
    energia[ataque_inicio:ataque_fim]      += np.random.normal(300, 30, ataque_fim - ataque_inicio)
    bytes_env[ataque_inicio:ataque_fim]    += np.random.normal(160000, 20000, ataque_fim - ataque_inicio)
    tentativas[ataque_inicio:ataque_fim]   = np.random.randint(1, 3, ataque_fim - ataque_inicio)

    return pd.DataFrame({
        "timestamp":        timestamps,
        "temperatura_cpu":  np.clip(temperatura, 20, 95),
        "pacotes_por_seg":  np.clip(pacotes, 0, 6000),
        "consumo_energia":  np.clip(energia, 200, 800),
        "bytes_enviados":   np.clip(bytes_env, 1000, 300000).astype(int),
        "tentativas_auth":  np.clip(tentativas, 1, 300).astype(int),
        "ataque":           [
            i >= ataque_inicio and i < ataque_fim
            for i in range(n)
        ]
    })


@st.cache_data(ttl=15)
def gerar_alertas():
    """
    Dados de alertas de segurança.
    Em produção: executa Query 1 (vw_dashboard_alertas) do BD.
    """
    return [
        {
            "id": 1,
            "estacao": "GS-BRASILIA-01",
            "horario": (datetime.now() - timedelta(minutes=3)).strftime("%H:%M:%S"),
            "tipo": "DDOS",
            "stride": "DENIAL_OF_SERVICE",
            "severidade": "CRÍTICA",
            "score": -0.8742,
            "confianca": 93.2,
            "resolvido": False,
            "descricao": "Taxa de pacotes: 4.850/s (limiar: 500/s)"
        },
        {
            "id": 2,
            "estacao": "GS-FORTALEZA-01",
            "horario": (datetime.now() - timedelta(minutes=107)).strftime("%H:%M:%S"),
            "tipo": "POISONING",
            "stride": "ELEVATION_OF_PRIVILEGE",
            "severidade": "ALTA",
            "score": -0.5530,
            "confianca": 76.4,
            "resolvido": False,
            "descricao": "Data Poisoning detectado via KS-Test"
        },
        {
            "id": 3,
            "estacao": "GS-MANAUS-01",
            "horario": (datetime.now() - timedelta(minutes=27)).strftime("%H:%M:%S"),
            "tipo": "BRUTEFORCE",
            "stride": "SPOOFING",
            "severidade": "ALTA",
            "score": -0.7214,
            "confianca": 88.1,
            "resolvido": True,
            "descricao": "142 tentativas de auth em 300s"
        },
        {
            "id": 4,
            "estacao": "GS-CUIABA-01",
            "horario": (datetime.now() - timedelta(minutes=210)).strftime("%H:%M:%S"),
            "tipo": "PORTSCAN",
            "stride": "INFORMATION_DISCLOSURE",
            "severidade": "ALTA",
            "score": -0.6103,
            "confianca": 82.5,
            "resolvido": True,
            "descricao": "847 portas únicas varridas em 0.5s"
        }
    ]


@st.cache_data(ttl=60)
def gerar_metricas_ml():
    """Métricas do modelo de ML — resultado do notebook."""
    return {
        "isolation_forest": {
            "acuracia":  0.9124,
            "precision": 0.8832,
            "recall":    0.9341,
            "f1_score":  0.9079,
        },
        "random_forest": {
            "acuracia":  0.9687,
            "f1_score":  0.9651,
            "cv_score":  0.9612,
            "cv_std":    0.0088,
        },
        "por_classe": {
            "NORMAL":      {"precision": 0.98, "recall": 0.97, "f1": 0.975},
            "DDOS":        {"precision": 0.99, "recall": 0.99, "f1": 0.990},
            "PORTSCAN":    {"precision": 0.97, "recall": 0.98, "f1": 0.975},
            "BRUTEFORCE":  {"precision": 0.96, "recall": 0.95, "f1": 0.955},
            "POISONING":   {"precision": 0.89, "recall": 0.87, "f1": 0.880},
        }
    }


# ============================================================
# SIDEBAR — Filtros e controles
# ============================================================
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/satellite.png", width=80)
    st.title("ORBIT-SHIELD")
    st.caption("Global Solution 2026.1 — FIAP")
    st.divider()

    st.subheader("⚙️ Filtros")

    station_selecionada = st.selectbox(
        "Ground Station",
        ["GS-BRASILIA-01", "GS-MANAUS-01", "GS-FORTALEZA-01", "GS-CUIABA-01"]
    )

    janela_horas = st.slider(
        "Janela temporal (horas)", min_value=1, max_value=48, value=24
    )

    mostrar_ataques = st.toggle("Destacar períodos de ataque", value=True)

    st.divider()
    st.subheader("🔄 Atualização")
    auto_refresh = st.toggle("Auto-refresh (30s)", value=False)

    st.divider()
    st.subheader("📋 Informações")
    st.markdown("""
    **Modelos ativos:**
    - 🌲 Isolation Forest v1.0
    - 🌲 Random Forest v1.0

    **Banco de dados:**
    - PostgreSQL + TimescaleDB

    **Firmware:**
    - ESP32 v2.3.1
    """)

    if auto_refresh:
        time.sleep(30)
        st.rerun()

# ============================================================
# CABEÇALHO PRINCIPAL
# ============================================================
st.markdown("""
<div class="main-header">
    <h1 style="color:#00d4ff; margin:0; font-size:2.2rem;">
        🛰️ ORBIT-SHIELD
    </h1>
    <p style="color:#8892a4; margin:4px 0 0 0; font-size:1rem;">
        Sistema de Detecção de Cyberataques em Ground Stations Satelitais
        &nbsp;|&nbsp; Global Solution 2026.1 — FIAP
    </p>
</div>
""", unsafe_allow_html=True)

# Timestamp de última atualização
col_ts1, col_ts2 = st.columns([3, 1])
with col_ts2:
    st.caption(f"🕐 Atualizado: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")

# ============================================================
# LINHA 1 — KPIs principais
# ============================================================
alertas      = gerar_alertas()
serie        = gerar_serie_temporal(janela_horas, station_selecionada)
metricas_ml  = gerar_metricas_ml()

alertas_criticos    = sum(1 for a in alertas if a["severidade"] == "CRÍTICA" and not a["resolvido"])
alertas_pendentes   = sum(1 for a in alertas if not a["resolvido"])
total_leituras      = len(serie)
taxa_anomalia       = round(serie["ataque"].mean() * 100, 1)

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric(
        label="🔴 Alertas Críticos",
        value=alertas_criticos,
        delta=f"+{alertas_criticos} não resolvidos",
        delta_color="inverse"
    )
with col2:
    st.metric(
        label="⚠️ Alertas Pendentes",
        value=alertas_pendentes,
        delta=f"{len(alertas) - alertas_pendentes} resolvidos"
    )
with col3:
    st.metric(
        label="📡 Leituras Analisadas",
        value=f"{total_leituras:,}",
        delta=f"Últimas {janela_horas}h"
    )
with col4:
    st.metric(
        label="🎯 Taxa de Anomalia",
        value=f"{taxa_anomalia}%",
        delta="do total de leituras",
        delta_color="inverse" if taxa_anomalia > 5 else "normal"
    )
with col5:
    st.metric(
        label="🤖 F1-Score ML",
        value=f"{metricas_ml['random_forest']['f1_score']:.1%}",
        delta="Random Forest"
    )

st.divider()

# ============================================================
# LINHA 2 — Série temporal dos sensores
# ============================================================
st.subheader(f"📈 Série Temporal dos Sensores — {station_selecionada}")
st.caption("Dados coletados pelo ESP32 a cada 10 minutos. Área vermelha = período de ataque detectado pelo modelo ML.")

tab1, tab2, tab3 = st.tabs(["🌡️ Temperatura & Energia", "📦 Tráfego de Rede", "🔐 Tentativas de Auth"])

with tab1:
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 6), sharex=True)
    fig.patch.set_facecolor("#0d1117")

    for ax in [ax1, ax2]:
        ax.set_facecolor("#161b22")
        ax.tick_params(colors="white")
        ax.spines[:].set_color("#30363d")

    # Temperatura
    ax1.plot(serie["timestamp"], serie["temperatura_cpu"],
             color="#00d4ff", linewidth=1.5, label="Temperatura CPU (°C)")
    ax1.axhline(y=60, color="#ff4444", linestyle="--", alpha=0.7, label="Limiar de alerta (60°C)")
    ax1.set_ylabel("Temperatura (°C)", color="white")
    ax1.legend(facecolor="#161b22", labelcolor="white", fontsize=9)

    # Energia
    ax2.plot(serie["timestamp"], serie["consumo_energia"],
             color="#ffa500", linewidth=1.5, label="Consumo de Energia (W)")
    ax2.axhline(y=600, color="#ff4444", linestyle="--", alpha=0.7, label="Limiar de alerta (600W)")
    ax2.set_ylabel("Energia (W)", color="white")
    ax2.set_xlabel("Horário", color="white")
    ax2.legend(facecolor="#161b22", labelcolor="white", fontsize=9)

    # Destacar período de ataque
    if mostrar_ataques:
        for ax in [ax1, ax2]:
            ataque_mask = serie["ataque"]
            if ataque_mask.any():
                inicio = serie.loc[ataque_mask, "timestamp"].min()
                fim    = serie.loc[ataque_mask, "timestamp"].max()
                ax.axvspan(inicio, fim, alpha=0.25, color="red", label="Ataque detectado")

    plt.suptitle(f"Sensores Físicos — {station_selecionada}",
                 color="white", fontsize=13, fontweight="bold")
    plt.tight_layout()
    st.pyplot(fig)
    plt.close()

with tab2:
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 6), sharex=True)
    fig.patch.set_facecolor("#0d1117")

    for ax in [ax1, ax2]:
        ax.set_facecolor("#161b22")
        ax.tick_params(colors="white")
        ax.spines[:].set_color("#30363d")

    # Pacotes por segundo
    ax1.fill_between(serie["timestamp"], serie["pacotes_por_seg"],
                     alpha=0.4, color="#00ff88")
    ax1.plot(serie["timestamp"], serie["pacotes_por_seg"],
             color="#00ff88", linewidth=1.2, label="Pacotes/segundo")
    ax1.axhline(y=500, color="#ff4444", linestyle="--", alpha=0.7, label="Limiar DDoS (500/s)")
    ax1.set_ylabel("Pacotes/s", color="white")
    ax1.set_yscale("log")
    ax1.legend(facecolor="#161b22", labelcolor="white", fontsize=9)

    # Bytes enviados
    ax2.fill_between(serie["timestamp"], serie["bytes_enviados"],
                     alpha=0.4, color="#9b59b6")
    ax2.plot(serie["timestamp"], serie["bytes_enviados"],
             color="#9b59b6", linewidth=1.2, label="Bytes enviados")
    ax2.set_ylabel("Bytes enviados", color="white")
    ax2.set_xlabel("Horário", color="white")
    ax2.legend(facecolor="#161b22", labelcolor="white", fontsize=9)

    if mostrar_ataques and serie["ataque"].any():
        for ax in [ax1, ax2]:
            inicio = serie.loc[serie["ataque"], "timestamp"].min()
            fim    = serie.loc[serie["ataque"], "timestamp"].max()
            ax.axvspan(inicio, fim, alpha=0.25, color="red")

    plt.suptitle(f"Tráfego de Rede — {station_selecionada}",
                 color="white", fontsize=13, fontweight="bold")
    plt.tight_layout()
    st.pyplot(fig)
    plt.close()

with tab3:
    fig, ax = plt.subplots(figsize=(14, 3.5))
    fig.patch.set_facecolor("#0d1117")
    ax.set_facecolor("#161b22")
    ax.tick_params(colors="white")
    ax.spines[:].set_color("#30363d")

    ax.bar(serie["timestamp"], serie["tentativas_auth"],
           color=["#ff4444" if a else "#3498db" for a in serie["ataque"]],
           width=0.006, alpha=0.8)
    ax.axhline(y=20, color="#ff8800", linestyle="--", alpha=0.8, label="Limiar BruteForce (20)")
    ax.set_ylabel("Tentativas de Auth", color="white")
    ax.set_xlabel("Horário", color="white")
    ax.legend(facecolor="#161b22", labelcolor="white", fontsize=9)

    patch_normal = mpatches.Patch(color="#3498db", label="Normal")
    patch_ataque = mpatches.Patch(color="#ff4444", label="Ataque detectado")
    ax.legend(handles=[patch_normal, patch_ataque],
              facecolor="#161b22", labelcolor="white", fontsize=9)

    plt.title(f"Tentativas de Autenticação — {station_selecionada}",
              color="white", fontsize=13, fontweight="bold")
    plt.tight_layout()
    st.pyplot(fig)
    plt.close()

st.divider()

# ============================================================
# LINHA 3 — Alertas + Métricas ML
# ============================================================
col_alertas, col_ml = st.columns([1.4, 1])

# --- Painel de Alertas ---
with col_alertas:
    st.subheader("🚨 Alertas de Segurança Ativos")
    st.caption("Eventos detectados pelo pipeline ML e classificados via modelo STRIDE.")

    filtro_pendentes = st.checkbox("Mostrar apenas pendentes", value=False)
    alertas_filtrados = (
        [a for a in alertas if not a["resolvido"]]
        if filtro_pendentes else alertas
    )

    for alerta in alertas_filtrados:
        icone_sev  = "🔴" if alerta["severidade"] == "CRÍTICA" else "🟠"
        status_txt = "⏳ Pendente" if not alerta["resolvido"] else "✅ Resolvido"
        css_class  = "alerta-critico" if alerta["severidade"] == "CRÍTICA" else "alerta-alto"

        st.markdown(f"""
        <div class="{css_class}">
            <strong>{icone_sev} [{alerta['severidade']}] {alerta['tipo']} — {alerta['estacao']}</strong><br>
            <small>
                🕐 {alerta['horario']} &nbsp;|&nbsp;
                🎯 Confiança: {alerta['confianca']}% &nbsp;|&nbsp;
                📊 Score: {alerta['score']} &nbsp;|&nbsp;
                {status_txt}
            </small><br>
            <small style="color:#aaa;">⚡ STRIDE: {alerta['stride']} — {alerta['descricao']}</small>
        </div>
        """, unsafe_allow_html=True)

# --- Métricas do Modelo ML ---
with col_ml:
    st.subheader("🤖 Desempenho do Modelo ML")
    st.caption("Métricas calculadas no pipeline do notebook Jupyter (CICIDS2017).")

    # Isolation Forest
    st.markdown("**🌲 Isolation Forest** *(Detecção de Anomalia)*")
    iso = metricas_ml["isolation_forest"]
    col_a, col_b = st.columns(2)
    col_a.metric("Acurácia",  f"{iso['acuracia']:.1%}")
    col_b.metric("Recall",    f"{iso['recall']:.1%}")
    col_a.metric("Precision", f"{iso['precision']:.1%}")
    col_b.metric("F1-Score",  f"{iso['f1_score']:.1%}")

    st.markdown("**🌲 Random Forest** *(Classificação de Ataques)*")
    rf = metricas_ml["random_forest"]
    col_c, col_d = st.columns(2)
    col_c.metric("Acurácia",    f"{rf['acuracia']:.1%}")
    col_d.metric("F1-Score",    f"{rf['f1_score']:.1%}")
    col_c.metric("CV Score",    f"{rf['cv_score']:.1%}")
    col_d.metric("CV Desvio",   f"±{rf['cv_std']:.3f}")

    # Gráfico F1 por classe
    st.markdown("**F1-Score por Classe de Ataque:**")
    classes  = list(metricas_ml["por_classe"].keys())
    f1_vals  = [metricas_ml["por_classe"][c]["f1"] for c in classes]
    cores_f1 = ["#ff4444" if v < 0.90 else "#00cc66" for v in f1_vals]

    fig_f1, ax_f1 = plt.subplots(figsize=(6, 2.8))
    fig_f1.patch.set_facecolor("#0d1117")
    ax_f1.set_facecolor("#161b22")
    ax_f1.tick_params(colors="white", labelsize=9)
    ax_f1.spines[:].set_color("#30363d")

    bars = ax_f1.barh(classes, f1_vals, color=cores_f1, edgecolor="none", height=0.6)
    ax_f1.set_xlim(0.80, 1.01)
    ax_f1.axvline(x=0.90, color="white", linestyle="--", alpha=0.4, linewidth=1)
    ax_f1.set_xlabel("F1-Score", color="white", fontsize=9)

    for bar, val in zip(bars, f1_vals):
        ax_f1.text(val + 0.001, bar.get_y() + bar.get_height() / 2,
                   f"{val:.3f}", va="center", color="white", fontsize=8)

    plt.tight_layout()
    st.pyplot(fig_f1)
    plt.close()

st.divider()

# ============================================================
# LINHA 4 — Distribuição de ataques + Status das estações
# ============================================================
col_dist, col_status = st.columns([1, 1.2])

with col_dist:
    st.subheader("📊 Distribuição de Ataques Detectados")
    st.caption("Últimos 30 dias — Query 3 (BD)")

    ataques_data = {
        "DDOS":       12,
        "PORTSCAN":    8,
        "BRUTEFORCE":  6,
        "POISONING":   3,
    }

    fig_pie, ax_pie = plt.subplots(figsize=(6, 4.5))
    fig_pie.patch.set_facecolor("#0d1117")
    ax_pie.set_facecolor("#0d1117")

    cores_pie = ["#e74c3c", "#f39c12", "#9b59b6", "#e67e22"]
    wedges, texts, autotexts = ax_pie.pie(
        ataques_data.values(),
        labels=ataques_data.keys(),
        autopct="%1.1f%%",
        colors=cores_pie,
        startangle=90,
        pctdistance=0.82,
        wedgeprops={"edgecolor": "#0d1117", "linewidth": 2}
    )
    for text in texts:
        text.set_color("white")
        text.set_fontsize(11)
    for autotext in autotexts:
        autotext.set_color("white")
        autotext.set_fontweight("bold")

    ax_pie.set_title("Tipos de Ataque Detectados",
                     color="white", fontsize=12, fontweight="bold", pad=15)
    plt.tight_layout()
    st.pyplot(fig_pie)
    plt.close()

with col_status:
    st.subheader("🗺️ Status das Ground Stations")
    st.caption("Mapa de risco por estação — Query 6 (BD)")

    estacoes = [
        {"nome": "GS-BRASILIA-01",  "local": "Brasília, DF",   "risco": "🔴 CRÍTICO",  "eventos": 8,  "pendentes": 1},
        {"nome": "GS-MANAUS-01",    "local": "Manaus, AM",     "risco": "🟠 ALTO",     "eventos": 5,  "pendentes": 0},
        {"nome": "GS-FORTALEZA-01", "local": "Fortaleza, CE",  "risco": "🟠 ALTO",     "eventos": 4,  "pendentes": 1},
        {"nome": "GS-CUIABA-01",    "local": "Cuiabá, MT",     "risco": "🟡 MÉDIO",    "eventos": 2,  "pendentes": 0},
    ]

    for est in estacoes:
        with st.container():
            c1, c2, c3, c4 = st.columns([2.2, 1.5, 0.8, 0.8])
            c1.markdown(f"**{est['nome']}**  \n`{est['local']}`")
            c2.markdown(f"{est['risco']}")
            c3.metric("Eventos", est["eventos"])
            c4.metric("Pendentes", est["pendentes"])
        st.divider()

# ============================================================
# RODAPÉ
# ============================================================
st.markdown("""
---
<div style="text-align:center; color:#555; font-size:0.85rem; padding:10px 0;">
    🛰️ <strong>ORBIT-SHIELD</strong> &nbsp;|&nbsp;
    Global Solution 2026.1 — FIAP &nbsp;|&nbsp;
    Inteligência Artificial — 1º Semestre &nbsp;|&nbsp;
    Disciplinas: Cibersegurança · Python · Banco de Dados · Machine Learning
</div>
""", unsafe_allow_html=True)
