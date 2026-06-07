# 🛰️ ORBIT-SHIELD
### Sistema Inteligente de Detecção de Cyberataques em Ground Stations Satelitais

> **Global Solution 2026.1 — FIAP**  
> Curso: Inteligência Artificial — 1º Semestre  
> Tema: Economia Espacial × Cibersegurança  

---

## 👥 Integrantes do Grupo 57

| Nome | RM | GitHub |
|---|---|---|
| Kauan Maciel Forgiarini | RM-XXXXX | @kauan |
| Integrante 2 | RM-XXXXX | @usuario2 |
| Integrante 3 | RM-XXXXX | @usuario3 |
| Integrante 4 | RM-XXXXX | @usuario4 |
| Integrante 5 | RM-XXXXX | @usuario5 |

---

## 🎯 Problema Resolvido

Em fevereiro de 2022, horas antes da invasão russa à Ucrânia, um cyberataque destruiu milhares de modems da rede de satélites **ViaSat KA-SAT**, derrubando comunicações militares e civis em toda a Europa. O vetor de ataque foi a **ground station** — a estação terrestre que controla o satélite.

O **ORBIT-SHIELD** responde à pergunta central da GS:

> *"Como a tecnologia espacial pode ser utilizada para melhorar a vida das pessoas e tornar processos mais eficientes?"*

Nossa resposta: **protegendo a infraestrutura que faz a tecnologia espacial funcionar.**

---

## 🏗️ Arquitetura da Solução

```
┌─────────────────────────────────────────────────────────────────┐
│  CAMADA 1 — EDGE (C/C++ no ESP32)                               │
│  Sensores físicos → Filtro de ruído → HMAC-SHA256 → MQTT/TLS    │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│  CAMADA 2 — API DE INGESTÃO (Python / FastAPI)                   │
│  Validação HMAC → Anti-Replay → Rate Limiting → Sanitização      │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│  CAMADA 3 — BANCO DE DADOS (PostgreSQL)                          │
│  sensor_readings → ml_predictions → security_events → audit_log  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│  CAMADA 4 — MACHINE LEARNING (Python / scikit-learn)             │
│  EDA → Isolation Forest (anomalia) → Random Forest (classificação)│
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│  CAMADA 5 — DASHBOARD (Python / Streamlit)                       │
│  Série temporal → Alertas STRIDE → Métricas ML → Mapa de risco   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📚 Integração com as Disciplinas

| Disciplina | Implementação no ORBIT-SHIELD |
|---|---|
| **Cibersegurança para IA** | Modelagem STRIDE (8 ameaças), HMAC-SHA256, Rate Limiting, Anti-Replay, detecção de Data Poisoning via KS-Test, conformidade LGPD |
| **Programação C/C++** | Firmware ESP32: leitura de sensores, filtro de média móvel, HMAC com mbedTLS, transmissão MQTT, detecção local de anomalias (edge computing) |
| **Programação Python** | API FastAPI com Clean Code e POO: schemas Pydantic, Singleton pattern, middlewares de segurança, pipeline de ML integrado |
| **Banco de Dados** | PostgreSQL: 6 tabelas normalizadas, índices BRIN para séries temporais, trigger APPEND-ONLY, view materializada, 6 queries de agregação |
| **Machine Learning** | EDA completa, engenharia de features, Isolation Forest (não supervisionado), Random Forest (supervisionado), KS-Test para Data Poisoning |

---

## 🗂️ Estrutura do Repositório

```
orbit-shield/
│
├── README.md                          ← Este arquivo
│
├── firmware/
│   ├── orbit_shield_esp32.ino         ← Firmware C/C++ para ESP32
│   └── INSTRUCOES_ESP32.md            ← Como instalar e rodar
│
├── api/
│   ├── requirements.txt               ← Dependências Python
│   └── app/
│       ├── main.py                    ← Ponto de entrada FastAPI
│       ├── models/
│       │   └── schemas.py             ← Validação Pydantic
│       ├── security/
│       │   └── rate_limiter.py        ← HMAC + Rate Limiting + JWT
│       ├── services/
│       │   └── sensor_service.py      ← Lógica de negócio + ML
│       └── routes/
│           └── endpoints.py           ← Endpoints REST
│
├── database/
│   ├── 01_ddl_criacao.sql             ← Criação das tabelas
│   └── 02_dml_dados_queries.sql       ← Dados de exemplo + queries
│
├── ml/
│   └── orbit_shield_ml.ipynb          ← Pipeline completo de ML
│
└── dashboard/
    ├── dashboard.py                   ← Painel Streamlit
    └── INSTRUCOES_DASHBOARD.md        ← Como rodar o dashboard
```

---

## 🚀 Como Executar o Projeto Completo

### 1. Clonar o repositório
```bash
git clone https://github.com/SEU_USUARIO/orbit-shield.git
cd orbit-shield
```

### 2. Instalar dependências Python
```bash
pip install -r api/requirements.txt
```

### 3. Configurar o banco de dados
```bash
# Com PostgreSQL instalado:
psql -U postgres -c "CREATE DATABASE orbit_shield;"
psql -U postgres -d orbit_shield -f database/01_ddl_criacao.sql
psql -U postgres -d orbit_shield -f database/02_dml_dados_queries.sql
```

### 4. Rodar a API
```bash
cd api
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
# Documentação: http://localhost:8000/docs
```

### 5. Rodar o Dashboard
```bash
cd dashboard
streamlit run dashboard.py
# Acesse: http://localhost:8501
```

### 6. Pipeline de Machine Learning
```
→ Abrir ml/orbit_shield_ml.ipynb no Google Colab
→ Runtime > Executar tudo
→ Todos os gráficos e métricas são gerados automaticamente
```

### 7. Firmware ESP32
```
→ Abrir firmware/orbit_shield_esp32.ino no Arduino IDE
→ Preencher WIFI_SSID e WIFI_PASSWORD
→ Upload para o ESP32
→ Monitorar via Serial Monitor (115200 baud)
```

---

## 🛡️ Modelo STRIDE — Ameaças e Contramedidas

| # | Ameaça | Tipo STRIDE | Contramedida |
|---|---|---|---|
| 1 | Pacotes falsos do sensor | Spoofing | HMAC-SHA256 no ESP32 + validação na API |
| 2 | Adulteração em trânsito | Tampering | TLS 1.3 + verificação de hash |
| 3 | Negação de responsabilidade | Repudiation | Audit log imutável (trigger APPEND-ONLY) |
| 4 | Exposição de telemetria | Information Disclosure | AES-256 em repouso + roles no BD |
| 5 | Flood na API | Denial of Service | Rate Limiting (60 req/min) + bloqueio de IP |
| 6 | Envenenamento do modelo | Elevation of Privilege | KS-Test + validation set isolado |
| 7 | Acesso não autorizado | Spoofing | JWT + HTTPS obrigatório |
| 8 | Alteração de logs | Tampering | Hash encadeado no audit_log |

---

## 📊 Resultados do Modelo ML

| Modelo | Acurácia | F1-Score | Observação |
|---|---|---|---|
| Isolation Forest | 91.2% | 90.8% | Recall de 93.4% — crítico em segurança |
| Random Forest | 96.9% | 96.5% | CV 5-fold: 96.1% ± 0.9% |
| KS-Test Poisoning | — | — | 100% dos lotes envenenados bloqueados |

---

## 🔗 Links

- 📹 **Vídeo demonstrativo:** [YouTube — não listado](#)
- 📄 **PDF da entrega:** [Google Drive](#)
- 🐙 **Repositório:** [GitHub](#)

---

## 📋 Conformidade LGPD

O ORBIT-SHIELD coleta exclusivamente dados de telemetria física de equipamentos (temperatura, energia, tráfego de rede). Nenhum dado pessoal é coletado. Todos os princípios da LGPD são aplicados: finalidade, minimização, segurança e responsabilização.

---

*Desenvolvido como Prova de Conceito (POC) para a Global Solution 2026.1 — FIAP.*  
*Curso de Inteligência Artificial — 1º Semestre.*
