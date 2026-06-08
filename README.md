# FIAP - Faculdade de Informática e Administração Paulista

<p align="center">
<a href="https://www.fiap.com.br/">
  <img src="https://upload.wikimedia.org/wikipedia/commons/d/d4/Fiap-logo-novo.jpg" alt="FIAP Logo" width="200"/>
</a>
</p>

---

# 🛰️ ORBIT-SHIELD
## Sistema Inteligente de Detecção de Cyberataques em Ground Stations Satelitais

**Global Solution 2026.1 — FIAP**
**Curso:** Graduação ON em Inteligência Artificial
**Fase:** 4 — Safra do Conhecimento Cibernético
**Tema:** Economia Espacial × Cibersegurança

---

## 👥 Integrantes do Grupo 57

| Nome | RM | GitHub |
|---|---|---|
| Kauan Maciel Forgiarini | RM574005 | [@kauanforgiarini](https://github.com/kauanforgiarini) |
| Wagner Adriano de Souza Silva Junior | RM569431 | [@wags2](https://github.com/wags2) |
| Thiago Lucas da Costa Bessa | RM570367 | — |
| Willian Kauê Tobias do Carmo | RM570038 | [@willktdc](https://github.com/willktdc) |

---

## 👨‍🏫 Professor Orientador

| Nome |
|---|---|
| Sabrina Otoni |
| Andre Godoi |
---

## 📜 Descrição do Projeto

Em fevereiro de 2022, horas antes da invasão russa à Ucrânia, um cyberataque à rede de satélites **ViaSat KA-SAT** destruiu mais de 30.000 modems em toda a Europa, derrubando comunicações militares e civis. O vetor de ataque foi a **ground station** — a estação terrestre que controla o satélite — e o ataque ficou ativo por horas porque não havia sistema inteligente de monitoramento capaz de identificar o padrão anômalo.

O **ORBIT-SHIELD** é uma Prova de Conceito (POC) de sistema de detecção de intrusão (IDS) especializado para ground stations satelitais, respondendo à pergunta central da GS:

> *"Como a tecnologia espacial pode ser utilizada para melhorar a vida das pessoas e tornar processos mais eficientes?"*

**Nossa resposta:** protegendo a infraestrutura que faz a tecnologia espacial funcionar.

---

## 🎯 Problema Resolvido

O problema tem três dimensões técnicas interligadas:

1. **DETECÇÃO** — ataques sofisticados produzem padrões sutis que regras simples não capturam. É necessário Machine Learning para identificar anomalias estatísticas.
2. **INTEGRIDADE** — dados dos sensores podem ser falsificados ou adulterados em trânsito. É necessário criptografia e autenticação em cada camada.
3. **ESCALA** — uma ground station gera centenas de leituras por hora. É necessário banco de dados otimizado para séries temporais e API de alta disponibilidade.

---

## 🏗️ Arquitetura da Solução

```
┌─────────────────────────────────────────────────────────────────┐
│  CAMADA 1 — EDGE (C/C++ no ESP32)                               │
│  Sensores físicos → Filtro de ruído → HMAC-SHA256 → MQTT/TLS    │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│  CAMADA 2 — API DE INGESTÃO (Python / FastAPI)                  │
│  Validação HMAC → Anti-Replay → Rate Limiting → Sanitização     │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│  CAMADA 3 — BANCO DE DADOS (PostgreSQL)                         │
│  sensor_readings → ml_predictions → security_events → audit_log │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│  CAMADA 4 — MACHINE LEARNING (Python / scikit-learn)            │
│  EDA → Isolation Forest (anomalia) → Random Forest (classif.)   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│  CAMADA 5 — DASHBOARD (Python / Streamlit)                      │
│  Série temporal → Alertas STRIDE → Métricas ML → Mapa de risco  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📚 Integração com as Disciplinas

| Disciplina | Implementação no ORBIT-SHIELD |
|---|---|
| **Cibersegurança para IA** | Modelagem STRIDE (8 ameaças), HMAC-SHA256, Rate Limiting, Anti-Replay Attack, detecção de Data Poisoning via KS-Test, conformidade LGPD |
| **Programação C/C++** | Firmware ESP32: leitura de sensores, filtro de média móvel (DSP), HMAC com mbedTLS, transmissão MQTT, detecção local de anomalias (edge computing) |
| **Programação Python** | API FastAPI com Clean Code e POO: schemas Pydantic, Singleton pattern, middlewares de segurança, pipeline de ML integrado |
| **Banco de Dados** | PostgreSQL: 6 tabelas normalizadas, índices BRIN para séries temporais, trigger APPEND-ONLY, view materializada, 6 queries de agregação |
| **Machine Learning** | EDA completa, engenharia de features, Isolation Forest (não supervisionado), Random Forest (supervisionado), KS-Test para Data Poisoning |

---

## 🛡️ Modelo STRIDE — Ameaças e Contramedidas

| # | Ameaça | Tipo STRIDE | Contramedida Implementada |
|---|---|---|---|
| 1 | Pacotes falsos do sensor | Spoofing | HMAC-SHA256 no ESP32 + validação na API |
| 2 | Adulteração em trânsito | Tampering | TLS 1.3 + verificação de hash |
| 3 | Negação de responsabilidade | Repudiation | Audit log imutável (trigger APPEND-ONLY) |
| 4 | Exposição de telemetria | Information Disclosure | AES-256 em repouso + roles no BD |
| 5 | Flood na API | Denial of Service | Rate Limiting (60 req/min) + bloqueio de IP |
| 6 | Envenenamento do modelo | Elevation of Privilege | KS-Test + validation set isolado |
| 7 | Acesso não autorizado ao dashboard | Spoofing | JWT + HTTPS obrigatório |
| 8 | Alteração de logs | Tampering | Hash encadeado no audit_log |

---

## 📊 Resultados do Modelo ML

| Modelo | Acurácia | F1-Score | Observação |
|---|---|---|---|
| Isolation Forest | 91.2% | 90.8% | Recall de 93.4% — métrica principal em segurança |
| Random Forest | 98.4% | 98.3% | CV 5-fold: 98.5% ± 0.37% |
| KS-Test Poisoning | — | — | 100% dos lotes envenenados bloqueados |

---

## 🗂️ Estrutura do Repositório

```
orbit-shield/
│
├── README.md                              ← Este arquivo
│
├── firmware/
│   └── orbit_shield_esp32.ino            ← Firmware C/C++ para ESP32
│
├── api/
│   ├── requirements.txt                  ← Dependências Python
│   └── app/
│       ├── main.py                       ← Ponto de entrada FastAPI
│       ├── models/
│       │   └── schemas.py               ← Validação Pydantic
│       ├── security/
│       │   └── rate_limiter.py          ← HMAC + Rate Limiting
│       ├── services/
│       │   └── sensor_service.py        ← Lógica de negócio + ML
│       └── routes/
│           └── endpoints.py             ← Endpoints REST
│
├── database/
│   ├── 01_ddl_criacao.sql               ← Criação das tabelas
│   └── 02_dml_dados_queries.sql         ← Dados de exemplo + queries
│
├── ml/
│   ├── orbit_shield_ml.ipynb            ← Pipeline completo de ML
│   ├── orbit_shield_predicoes.csv       ← Predições exportadas
│   └── images/                          ← Gráficos gerados pelo pipeline
│       ├── Figura 1 - Distribuição das classes no dataset.png
│       ├── Figura 2 - Distribuição das features por tipo de ataque.png
│       ├── Figura 3 - Mapa de correlação entre features.png
│       ├── Figura 4 - Isolation Forest Matriz de Confusão.png
│       ├── Figura 5 - Separação de scores NORMAL VS ATAQUE.png
│       ├── Figura 6 - Random Forest Matriz de Confusão.png
│       └── Figura 7 - Importancia das features no Random Forest.png
│
└── dashboard/
    └── dashboard.py                     ← Painel Streamlit
```

---

## 🚀 Como Executar o Projeto

### Pré-requisitos

- Python 3.10+
- PostgreSQL 14+
- Arduino IDE 2.x (para o firmware)
- Conta no Google Colab (para o notebook ML)

### 1. Clonar o repositório

```bash
git clone https://github.com/KauanForgiarini/orbit-shield.git
cd orbit-shield
```

### 2. Instalar dependências Python

```bash
pip install -r api/requirements.txt
```

### 3. Configurar o banco de dados

```bash
psql -U postgres -c "CREATE DATABASE orbit_shield;"
psql -U postgres -d orbit_shield -f database/01_ddl_criacao.sql
psql -U postgres -d orbit_shield -f database/02_dml_dados_queries.sql
```

### 4. Rodar a API

```bash
cd api
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Acesse a documentação automática: `http://localhost:8000/docs`

### 5. Rodar o Dashboard

```bash
cd dashboard
streamlit run dashboard.py
```

Acesse: `http://localhost:8501`

### 6. Pipeline de Machine Learning

```
1. Acessar: colab.research.google.com
2. File > Upload notebook > selecionar ml/orbit_shield_ml.ipynb
3. Runtime > Executar tudo
4. Todos os gráficos e métricas são gerados automaticamente
```

### 7. Firmware ESP32

```
1. Abrir firmware/orbit_shield_esp32.ino no Arduino IDE
2. Instalar bibliotecas: PubSubClient e ArduinoJson
3. Preencher WIFI_SSID e WIFI_PASSWORD no código
4. Selecionar: Tools > Board > ESP32 Dev Module
5. Upload para o ESP32
6. Monitorar via Serial Monitor (115200 baud)
```

---

## 🔗 Links do Projeto

| Recurso | Link |
|---|---|
| 📹 Vídeo Demonstrativo (YouTube) | https://www.youtube.com/watch?si=WtngK7hczQKdAv8a&v=F4z4RoBuSys&feature=youtu.be |
| 📄 PDF da Entrega (Google Drive) | https://drive.google.com/drive/folders/1C3W4as7gk7yzJvvEW81L7oDhvbpjSQ4X |
| 🐙 Repositório GitHub | https://github.com/KauanForgiarini/orbit-shield |

---

## 📋 Conformidade LGPD

O ORBIT-SHIELD coleta exclusivamente dados de telemetria física de equipamentos (temperatura, energia, tráfego de rede). Nenhum dado pessoal é coletado. Princípios aplicados: **finalidade** (detecção de ameaças), **minimização** (apenas dados necessários), **segurança** (AES-256 + TLS), **responsabilização** (audit log completo com rastreabilidade).

---

## 📋 Licença

[![CC BY 4.0](https://mirrors.creativecommons.org/presskit/icons/cc.svg?ref=chooser-v1)](http://creativecommons.org/licenses/by/4.0/?ref=chooser-v1)
[![BY](https://mirrors.creativecommons.org/presskit/icons/by.svg?ref=chooser-v1)](http://creativecommons.org/licenses/by/4.0/?ref=chooser-v1)

Este projeto está licenciado sob [Attribution 4.0 International](http://creativecommons.org/licenses/by/4.0/?ref=chooser-v1).

---

*Desenvolvido como Prova de Conceito (POC) para a Global Solution 2026.1 — FIAP.*
*Curso de Inteligência Artificial — 1º Semestre.*
