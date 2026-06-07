/**
 * ============================================================
 * ORBIT-SHIELD | Firmware ESP32 — Sensor de Ground Station
 * Global Solution 2026.1 — FIAP
 * Disciplinas: Programação C/C++ + Cibersegurança para IA
 * ============================================================
 *
 * DESCRIÇÃO:
 *   Firmware para ESP32 que simula os sensores físicos de uma
 *   ground station satelital. Realiza leitura periódica de dados,
 *   aplica filtro de ruído, assina cada pacote com HMAC-SHA256
 *   e transmite via MQTT over TLS para a API de ingestão.
 *
 * CONEXÃO COM OS PILARES:
 *   → Banco de Dados: payload JSON mapeado 1:1 com sensor_readings
 *   → Cibersegurança: HMAC-SHA256 (STRIDE #1 Spoofing + #2 Tampering)
 *   → Machine Learning: features coletadas = features do modelo
 *   → API Python: dados entregues via MQTT/TLS para ingestão segura
 *
 * BIBLIOTECAS NECESSÁRIAS (instalar no Arduino IDE):
 *   - PubSubClient (MQTT):  Sketch > Include Library > Manage Libraries
 *   - ArduinoJson:          Sketch > Include Library > Manage Libraries
 *   - WiFiClientSecure:     Já inclusa no ESP32 board package
 *   - mbedTLS (HMAC):       Já inclusa no ESP32 board package
 *
 * COMO USAR:
 *   1. Abra no Arduino IDE
 *   2. Preencha WIFI_SSID, WIFI_PASSWORD e MQTT_BROKER abaixo
 *   3. Selecione: Tools > Board > ESP32 Dev Module
 *   4. Clique em Upload
 * ============================================================
 */

// --- Bibliotecas ---
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <mbedtls/md.h>       // HMAC-SHA256 nativo do ESP32
#include <mbedtls/sha256.h>
#include <time.h>             // NTP para timestamp confiável

// ============================================================
// CONFIGURAÇÕES — EDITE AQUI
// ============================================================

// Wi-Fi
#define WIFI_SSID       "SEU_WIFI_AQUI"
#define WIFI_PASSWORD   "SUA_SENHA_AQUI"

// MQTT Broker (em produção: IP do servidor com a API Python)
// Para testes: use broker público test.mosquitto.org
#define MQTT_BROKER     "test.mosquitto.org"
#define MQTT_PORT       1883          // 8883 para TLS em produção
#define MQTT_TOPIC_DATA "orbitshield/gs/brasilia01/sensors"
#define MQTT_TOPIC_ALERT "orbitshield/gs/brasilia01/alerts"
#define MQTT_CLIENT_ID  "ESP32-GS-BRASILIA-01"

// Identificação desta estação (deve coincidir com ground_stations no BD)
#define STATION_ID      "GS-BRASILIA-01"
#define FIRMWARE_VER    "v2.3.1"

// Chave secreta HMAC (em produção: armazenar em NVS criptografado)
// CONEXÃO CIBERSEGURANÇA: chave compartilhada com a API Python para
// validação de autenticidade do pacote (contramedida STRIDE #1)
#define HMAC_SECRET_KEY "orbit-shield-secret-2026-fiap"

// Intervalo de leitura dos sensores (milissegundos)
#define INTERVALO_LEITURA_MS  10000   // 10 segundos

// Threshold de anomalia local (pré-filtragem no edge)
#define TEMP_MAX_NORMAL       60.0f   // °C — acima disso: alerta local
#define PACOTES_MAX_NORMAL    500.0f  // pacotes/s — acima: possível DDoS
#define AUTH_MAX_NORMAL       10      // tentativas — acima: possível BruteForce

// ============================================================
// ESTRUTURAS DE DADOS
// ============================================================

/**
 * Struct que representa uma leitura completa de sensor.
 * Mapeada diretamente para a tabela sensor_readings do BD.
 * DECISÃO C/C++: uso de struct garante layout de memória
 * controlado e eficiente para sistemas embarcados.
 */
struct SensorReading {
  // Identificação
  char    station_id[32];
  char    firmware_ver[12];
  long    timestamp_unix;

  // Leituras físicas
  float   temperatura_cpu;      // °C
  float   sinal_rf_dbm;         // dBm
  float   consumo_energia_w;    // Watts

  // Métricas de rede (features do modelo ML)
  long    bytes_enviados;
  long    bytes_recebidos;
  float   pacotes_por_segundo;
  int     flags_tcp;
  int     tentativas_auth;
  int     portas_destino_unicas;
  float   intervalo_medio_pacotes;  // ms
  float   tamanho_medio_pacote;     // bytes

  // Segurança
  char    hash_hmac[65];            // HMAC-SHA256 em hex (64 chars + '\0')
  bool    integridade_ok;

  // Diagnóstico local
  bool    anomalia_local;           // Flag de anomalia detectada no edge
  char    tipo_anomalia[32];        // Descrição da anomalia detectada
};

// ============================================================
// VARIÁVEIS GLOBAIS
// ============================================================

WiFiClient        wifiClient;
PubSubClient      mqttClient(wifiClient);
SensorReading     ultimaLeitura;
unsigned long     ultimoEnvio        = 0;
unsigned long     contadorLeituras   = 0;
bool              modoSimulacaoAtaque = false;  // Para demonstração

// Buffer de média móvel para filtro de ruído (Pilar C/C++)
// DECISÃO: janela de 5 amostras — balanço entre suavização e latência
#define JANELA_MEDIA_MOVEL  5
float  bufferTemp[JANELA_MEDIA_MOVEL]     = {0};
float  bufferPacotes[JANELA_MEDIA_MOVEL]  = {0};
int    indiceBuffer = 0;

// ============================================================
// PROTÓTIPOS DE FUNÇÕES
// ============================================================
void     conectarWiFi();
void     conectarMQTT();
void     lerSensores(SensorReading* leitura);
float    lerTemperatura();
float    lerSinalRF();
float    lerConsumoEnergia();
void     simularMetricasRede(SensorReading* leitura);
void     aplicarFiltroMediaMovel(float* buffer, float novoValor, float* resultado);
bool     detectarAnomaliaLocal(SensorReading* leitura);
void     calcularHMAC(SensorReading* leitura);
void     publicarMQTT(SensorReading* leitura);
String   serializarJSON(SensorReading* leitura);
void     callbackMQTT(char* topic, byte* payload, unsigned int length);
void     sincronizarNTP();
void     imprimirStatusSerial(SensorReading* leitura);

// ============================================================
// SETUP — Executado uma vez na inicialização
// ============================================================
void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("============================================");
  Serial.println("  ORBIT-SHIELD | ESP32 Firmware " FIRMWARE_VER);
  Serial.println("  Ground Station: " STATION_ID);
  Serial.println("  Global Solution 2026.1 — FIAP");
  Serial.println("============================================");

  // Inicializar buffer de média móvel com zeros
  memset(bufferTemp,    0, sizeof(bufferTemp));
  memset(bufferPacotes, 0, sizeof(bufferPacotes));

  // Inicializar struct de leitura
  memset(&ultimaLeitura, 0, sizeof(SensorReading));
  strncpy(ultimaLeitura.station_id,   STATION_ID,   sizeof(ultimaLeitura.station_id)   - 1);
  strncpy(ultimaLeitura.firmware_ver, FIRMWARE_VER, sizeof(ultimaLeitura.firmware_ver) - 1);

  // Conectar ao Wi-Fi
  conectarWiFi();

  // Sincronizar relógio via NTP (timestamp confiável para os logs)
  sincronizarNTP();

  // Configurar MQTT
  mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
  mqttClient.setCallback(callbackMQTT);
  mqttClient.setBufferSize(1024);  // Buffer maior para JSON completo

  Serial.println("[SETUP] Inicialização concluída. Iniciando loop principal...\n");
}

// ============================================================
// LOOP PRINCIPAL — Executado continuamente
// ============================================================
void loop() {
  // Garantir conexão MQTT ativa
  if (!mqttClient.connected()) {
    conectarMQTT();
  }
  mqttClient.loop();

  // Verificar intervalo de leitura
  unsigned long agora = millis();
  if (agora - ultimoEnvio >= INTERVALO_LEITURA_MS) {
    ultimoEnvio = agora;
    contadorLeituras++;

    Serial.printf("\n[LOOP] === Leitura #%lu ===\n", contadorLeituras);

    // 1. Ler todos os sensores
    lerSensores(&ultimaLeitura);

    // 2. Detectar anomalias localmente (edge computing)
    //    DECISÃO: detectar no edge reduz latência do alerta
    //    e diminui tráfego desnecessário para a nuvem
    bool anomalia = detectarAnomaliaLocal(&ultimaLeitura);

    // 3. Calcular HMAC-SHA256 do payload (integridade + autenticidade)
    //    CONEXÃO CIBERSEGURANÇA: contramedida STRIDE #1 (Spoofing) e #2 (Tampering)
    calcularHMAC(&ultimaLeitura);

    // 4. Publicar via MQTT
    publicarMQTT(&ultimaLeitura);

    // 5. Imprimir status no Serial Monitor (debug)
    imprimirStatusSerial(&ultimaLeitura);

    // Alternar modo simulação a cada 8 leituras (para demonstração)
    // Em produção: REMOVER este bloco
    if (contadorLeituras % 8 == 0) {
      modoSimulacaoAtaque = !modoSimulacaoAtaque;
      if (modoSimulacaoAtaque) {
        Serial.println("[DEMO] ⚠️  Modo simulação de ataque ATIVADO (próximas leituras)");
      } else {
        Serial.println("[DEMO] ✅ Modo simulação de ataque DESATIVADO");
      }
    }
  }
}

// ============================================================
// FUNÇÕES DE CONECTIVIDADE
// ============================================================

/**
 * Conecta ao Wi-Fi com retry automático.
 * Bloqueia até conectar (adequado para setup()).
 */
void conectarWiFi() {
  Serial.printf("[WiFi] Conectando a '%s'", WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  int tentativas = 0;
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
    tentativas++;
    if (tentativas > 40) {
      Serial.println("\n[WiFi] ERRO: Timeout. Reiniciando ESP32...");
      ESP.restart();  // Reinicia o chip em caso de falha persistente
    }
  }

  Serial.printf("\n[WiFi] ✅ Conectado! IP: %s\n", WiFi.localIP().toString().c_str());
}

/**
 * Conecta ao broker MQTT com autenticação e retry.
 * CONEXÃO CIBERSEGURANÇA: client_id único previne session hijacking.
 */
void conectarMQTT() {
  int tentativas = 0;
  while (!mqttClient.connected() && tentativas < 5) {
    Serial.printf("[MQTT] Conectando ao broker %s...", MQTT_BROKER);

    // Em produção: incluir user/password do broker
    // mqttClient.connect(MQTT_CLIENT_ID, "usuario", "senha")
    if (mqttClient.connect(MQTT_CLIENT_ID)) {
      Serial.println(" ✅ Conectado!");
      // Subscrever ao tópico de comandos (para receber configs remotas)
      mqttClient.subscribe("orbitshield/gs/brasilia01/commands");
    } else {
      Serial.printf(" ❌ Falha (rc=%d). Tentativa %d/5\n",
                    mqttClient.state(), tentativas + 1);
      delay(3000);
      tentativas++;
    }
  }

  if (!mqttClient.connected()) {
    Serial.println("[MQTT] ERRO: Não foi possível conectar ao broker.");
  }
}

/**
 * Sincroniza o relógio interno via NTP.
 * Essencial para timestamps confiáveis nos logs de segurança.
 */
void sincronizarNTP() {
  Serial.print("[NTP] Sincronizando relógio...");
  configTime(-3 * 3600, 0, "pool.ntp.org", "time.nist.gov");  // UTC-3 (Brasília)

  struct tm timeinfo;
  int tentativas = 0;
  while (!getLocalTime(&timeinfo) && tentativas < 10) {
    delay(500);
    Serial.print(".");
    tentativas++;
  }

  if (tentativas < 10) {
    Serial.printf(" ✅ %02d/%02d/%04d %02d:%02d:%02d\n",
                  timeinfo.tm_mday, timeinfo.tm_mon + 1, timeinfo.tm_year + 1900,
                  timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
  } else {
    Serial.println(" ⚠️  NTP falhou — usando timestamp relativo.");
  }
}

// ============================================================
// FUNÇÕES DE LEITURA DE SENSORES
// ============================================================

/**
 * Orquestra a leitura de todos os sensores.
 * Preenche a struct SensorReading com os valores atuais.
 *
 * DECISÃO C/C++: ponteiro para struct evita cópia desnecessária
 * de dados na memória — crítico em sistemas embarcados.
 */
void lerSensores(SensorReading* leitura) {
  // Timestamp Unix atual
  leitura->timestamp_unix = time(nullptr);

  // Leituras físicas com filtro de ruído aplicado
  float tempBruta = lerTemperatura();
  aplicarFiltroMediaMovel(bufferTemp, tempBruta, &leitura->temperatura_cpu);

  leitura->sinal_rf_dbm     = lerSinalRF();
  leitura->consumo_energia_w = lerConsumoEnergia();

  // Métricas de rede simuladas (em hardware real: via driver de NIC)
  simularMetricasRede(leitura);

  // Estado de integridade (será validado após HMAC)
  leitura->integridade_ok = true;
}

/**
 * Simula leitura de temperatura da CPU do rack.
 * Em hardware real: sensor NTC via ADC ou sensor I2C (DS18B20, BME280).
 *
 * DECISÃO DE SIMULAÇÃO:
 * - Temperatura normal: 38-50°C (operação estável)
 * - Modo ataque: 62-75°C (CPU sobrecarregada por DDoS)
 */
float lerTemperatura() {
  if (modoSimulacaoAtaque) {
    // Sobrecarga de CPU durante ataque DDoS: temperatura elevada
    return 62.0f + (float)(random(0, 1300)) / 100.0f;
  }

  // Temperatura normal com ruído gaussiano simulado
  // random() retorna int — dividir por escala para float
  float base  = 44.0f;
  float ruido = (float)(random(-800, 800)) / 100.0f;  // ±8°C de variação
  return base + ruido;
}

/**
 * Simula leitura de intensidade do sinal RF.
 * Em hardware real: módulo RF com saída analógica ou RSSI do rádio.
 * Valores em dBm: quanto mais próximo de 0, mais forte o sinal.
 * Range normal para ground station: -50 a -70 dBm.
 */
float lerSinalRF() {
  if (modoSimulacaoAtaque) {
    return -78.0f + (float)(random(-500, 200)) / 100.0f;  // Sinal degradado
  }
  return -62.0f + (float)(random(-500, 500)) / 100.0f;
}

/**
 * Simula leitura de consumo energético via sensor de corrente.
 * Em hardware real: sensor ACS712 via ADC do ESP32.
 */
float lerConsumoEnergia() {
  if (modoSimulacaoAtaque) {
    return 680.0f + (float)(random(0, 5000)) / 100.0f;  // Consumo anormal
  }
  return 370.0f + (float)(random(-3000, 3000)) / 100.0f;
}

/**
 * Simula as métricas de rede da ground station.
 * Em hardware real: leitura via /proc/net/dev (Linux embarcado)
 * ou driver de interface de rede dedicado.
 *
 * FILTRO DE RUÍDO: Média móvel aplicada em pacotes_por_segundo
 * para evitar falsos positivos por picos momentâneos.
 */
void simularMetricasRede(SensorReading* leitura) {
  if (modoSimulacaoAtaque) {
    // Perfil de DDoS: alto volume de saída, baixo de entrada, taxa altíssima
    leitura->bytes_enviados          = 210000L + random(0, 20000);
    leitura->bytes_recebidos         = 3800L   + random(0, 500);
    float pacotesBrutos              = 4800.0f + (float)random(0, 500);
    aplicarFiltroMediaMovel(bufferPacotes, pacotesBrutos, &leitura->pacotes_por_segundo);
    leitura->flags_tcp               = 10 + random(0, 5);
    leitura->tentativas_auth         = 1;
    leitura->portas_destino_unicas   = 2;
    leitura->intervalo_medio_pacotes = 0.2f + (float)random(0, 10) / 100.0f;
    leitura->tamanho_medio_pacote    = 64.0f + (float)random(-500, 500) / 100.0f;
  } else {
    // Perfil normal
    leitura->bytes_enviados          = 48000L + random(0, 5000);
    leitura->bytes_recebidos         = 76000L + random(0, 8000);
    float pacotesBrutos              = 50.0f  + (float)random(-1000, 1000) / 100.0f;
    aplicarFiltroMediaMovel(bufferPacotes, pacotesBrutos, &leitura->pacotes_por_segundo);
    leitura->flags_tcp               = random(0, 3);
    leitura->tentativas_auth         = random(1, 3);
    leitura->portas_destino_unicas   = random(1, 5);
    leitura->intervalo_medio_pacotes = 19.0f + (float)random(-300, 300) / 100.0f;
    leitura->tamanho_medio_pacote    = 512.0f + (float)random(-6400, 6400) / 100.0f;
  }
}

// ============================================================
// FILTRO DE RUÍDO — MÉDIA MÓVEL
// ============================================================

/**
 * Aplica filtro de média móvel (Moving Average) sobre um buffer circular.
 *
 * DECISÃO C/C++: buffer circular com ponteiro de índice — implementação
 * clássica de DSP (Digital Signal Processing) para sistemas embarcados.
 * Complexidade O(1) por atualização — ideal para tempo real.
 *
 * @param buffer   Array circular de floats (tamanho JANELA_MEDIA_MOVEL)
 * @param novoValor  Nova amostra a inserir
 * @param resultado  Saída: média das últimas N amostras
 */
void aplicarFiltroMediaMovel(float* buffer, float novoValor, float* resultado) {
  // Inserir novo valor na posição atual do índice circular
  buffer[indiceBuffer % JANELA_MEDIA_MOVEL] = novoValor;

  // Calcular média de todas as posições do buffer
  float soma = 0.0f;
  for (int i = 0; i < JANELA_MEDIA_MOVEL; i++) {
    soma += buffer[i];
  }
  *resultado = soma / JANELA_MEDIA_MOVEL;

  // Avançar índice circular (volta ao início após JANELA_MEDIA_MOVEL)
  indiceBuffer = (indiceBuffer + 1) % JANELA_MEDIA_MOVEL;
}

// ============================================================
// DETECÇÃO DE ANOMALIA LOCAL (EDGE COMPUTING)
// ============================================================

/**
 * Detecta anomalias localmente no ESP32 antes de enviar ao servidor.
 *
 * DECISÃO DE ARQUITETURA (Edge Computing):
 * Detectar anomalias no edge reduz latência do alerta de segundos
 * para milissegundos, e diminui tráfego desnecessário à nuvem.
 * Esta é a primeira linha de defesa do ORBIT-SHIELD.
 *
 * CONEXÃO CIBERSEGURANÇA: implementa detecção local das ameaças
 * STRIDE #5 (DoS) e #3 (BruteForce) com regras simples e rápidas.
 *
 * @param leitura  Ponteiro para a leitura atual
 * @return true se anomalia detectada, false caso contrário
 */
bool detectarAnomaliaLocal(SensorReading* leitura) {
  leitura->anomalia_local = false;
  memset(leitura->tipo_anomalia, 0, sizeof(leitura->tipo_anomalia));

  // Regra 1: Temperatura anormal → possível sobrecarga (DDoS)
  if (leitura->temperatura_cpu > TEMP_MAX_NORMAL) {
    leitura->anomalia_local = true;
    strncpy(leitura->tipo_anomalia, "TEMP_ALTA_CPU",
            sizeof(leitura->tipo_anomalia) - 1);
    Serial.printf("[ANOMALIA LOCAL] 🌡️  Temperatura: %.1f°C > %.0f°C\n",
                  leitura->temperatura_cpu, TEMP_MAX_NORMAL);
  }

  // Regra 2: Taxa de pacotes anormal → possível DDoS
  if (leitura->pacotes_por_segundo > PACOTES_MAX_NORMAL) {
    leitura->anomalia_local = true;
    strncpy(leitura->tipo_anomalia, "DDOS_SUSPEITO",
            sizeof(leitura->tipo_anomalia) - 1);
    Serial.printf("[ANOMALIA LOCAL] 📦 Pacotes/s: %.0f > %.0f (limiar DDoS)\n",
                  leitura->pacotes_por_segundo, PACOTES_MAX_NORMAL);

    // Publicar alerta imediato no tópico de alertas (sem esperar próximo ciclo)
    String alerta = "{\"tipo\":\"DDOS_SUSPEITO\","
                    "\"station\":\"" STATION_ID "\","
                    "\"pacotes_por_seg\":" + String(leitura->pacotes_por_segundo) + "}";
    mqttClient.publish(MQTT_TOPIC_ALERT, alerta.c_str(), true);
  }

  // Regra 3: Excesso de tentativas de autenticação → BruteForce
  if (leitura->tentativas_auth > AUTH_MAX_NORMAL) {
    leitura->anomalia_local = true;
    strncpy(leitura->tipo_anomalia, "BRUTEFORCE_SUSPEITO",
            sizeof(leitura->tipo_anomalia) - 1);
    Serial.printf("[ANOMALIA LOCAL] 🔐 Auth attempts: %d > %d\n",
                  leitura->tentativas_auth, AUTH_MAX_NORMAL);
  }

  return leitura->anomalia_local;
}

// ============================================================
// SEGURANÇA — HMAC-SHA256
// ============================================================

/**
 * Calcula o HMAC-SHA256 do payload de dados e armazena em hash_hmac.
 *
 * CONEXÃO CIBERSEGURANÇA:
 *   - Contramedida STRIDE #1 (Spoofing): prova autenticidade do remetente
 *   - Contramedida STRIDE #2 (Tampering): qualquer alteração invalida o hash
 *
 * DECISÃO TÉCNICA:
 *   Usamos mbedTLS, biblioteca de criptografia embutida no ESP32-IDF.
 *   SHA256 produz digest de 32 bytes → representado como 64 hex chars.
 *
 *   O payload assinado inclui: station_id + timestamp + todas as métricas.
 *   A chave HMAC_SECRET_KEY é compartilhada com a API Python para validação.
 *
 * @param leitura  Ponteiro para a leitura — hash_hmac será preenchido
 */
void calcularHMAC(SensorReading* leitura) {
  // Montar string do payload que será assinada
  // Formato determinístico — mesma ordem sempre
  char payload[512];
  snprintf(payload, sizeof(payload),
    "%s|%ld|%.2f|%.2f|%.2f|%ld|%ld|%.2f|%d|%d|%d|%.2f|%.2f",
    leitura->station_id,
    leitura->timestamp_unix,
    leitura->temperatura_cpu,
    leitura->sinal_rf_dbm,
    leitura->consumo_energia_w,
    leitura->bytes_enviados,
    leitura->bytes_recebidos,
    leitura->pacotes_por_segundo,
    leitura->flags_tcp,
    leitura->tentativas_auth,
    leitura->portas_destino_unicas,
    leitura->intervalo_medio_pacotes,
    leitura->tamanho_medio_pacote
  );

  // Calcular HMAC-SHA256 usando mbedTLS
  unsigned char digest[32];  // SHA256 = 256 bits = 32 bytes
  const unsigned char* chave = (const unsigned char*)HMAC_SECRET_KEY;
  const unsigned char* msg   = (const unsigned char*)payload;

  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_md_hmac_starts(&ctx, chave, strlen(HMAC_SECRET_KEY));
  mbedtls_md_hmac_update(&ctx, msg, strlen(payload));
  mbedtls_md_hmac_finish(&ctx, digest);
  mbedtls_md_free(&ctx);

  // Converter bytes para string hexadecimal (64 caracteres)
  for (int i = 0; i < 32; i++) {
    sprintf(&leitura->hash_hmac[i * 2], "%02x", digest[i]);
  }
  leitura->hash_hmac[64] = '\0';
}

// ============================================================
// PUBLICAÇÃO MQTT
// ============================================================

/**
 * Serializa a leitura para JSON e publica no broker MQTT.
 *
 * DECISÃO: ArduinoJson usa alocação estática (StaticJsonDocument)
 * em vez de dinâmica — evita fragmentação de heap no ESP32.
 *
 * CONEXÃO BANCO DE DADOS: campos do JSON mapeiam 1:1 com
 * as colunas da tabela sensor_readings.
 */
void publicarMQTT(SensorReading* leitura) {
  if (!mqttClient.connected()) {
    Serial.println("[MQTT] ⚠️  Sem conexão — pulando publicação.");
    return;
  }

  String jsonPayload = serializarJSON(leitura);

  // Publicar no tópico de dados
  bool sucesso = mqttClient.publish(
    MQTT_TOPIC_DATA,
    jsonPayload.c_str(),
    false  // retain = false para dados de série temporal
  );

  if (sucesso) {
    Serial.printf("[MQTT] ✅ Publicado (%d bytes) no tópico: %s\n",
                  jsonPayload.length(), MQTT_TOPIC_DATA);
  } else {
    Serial.println("[MQTT] ❌ Falha na publicação — dado perdido.");
    // Em produção: implementar buffer local com SPIFFS para retry
  }
}

/**
 * Serializa a struct SensorReading para JSON usando ArduinoJson.
 * JSON resultante é enviado via MQTT e ingerido pela API Python.
 */
String serializarJSON(SensorReading* leitura) {
  // StaticJsonDocument: alocação na stack (mais seguro em embedded)
  // Tamanho calculado: ~600 bytes para todos os campos
  StaticJsonDocument<768> doc;

  // Identificação
  doc["station_id"]      = leitura->station_id;
  doc["firmware_ver"]    = leitura->firmware_ver;
  doc["timestamp_unix"]  = leitura->timestamp_unix;

  // Leituras físicas
  doc["temperatura_cpu"]      = serialized(String(leitura->temperatura_cpu,    2));
  doc["sinal_rf_dbm"]         = serialized(String(leitura->sinal_rf_dbm,       2));
  doc["consumo_energia_w"]    = serialized(String(leitura->consumo_energia_w,  2));

  // Métricas de rede
  doc["bytes_enviados"]          = leitura->bytes_enviados;
  doc["bytes_recebidos"]         = leitura->bytes_recebidos;
  doc["pacotes_por_segundo"]     = serialized(String(leitura->pacotes_por_segundo,     2));
  doc["flags_tcp"]               = leitura->flags_tcp;
  doc["tentativas_auth"]         = leitura->tentativas_auth;
  doc["portas_destino_unicas"]   = leitura->portas_destino_unicas;
  doc["intervalo_medio_pacotes"] = serialized(String(leitura->intervalo_medio_pacotes, 2));
  doc["tamanho_medio_pacote"]    = serialized(String(leitura->tamanho_medio_pacote,    2));

  // Segurança
  doc["hash_hmac"]        = leitura->hash_hmac;
  doc["integridade_ok"]   = leitura->integridade_ok;

  // Diagnóstico edge
  doc["anomalia_local"]   = leitura->anomalia_local;
  doc["tipo_anomalia"]    = leitura->tipo_anomalia;

  String output;
  serializeJson(doc, output);
  return output;
}

/**
 * Callback para mensagens MQTT recebidas (comandos remotos).
 * Permite reconfiguração remota do sensor sem reflash.
 */
void callbackMQTT(char* topic, byte* payload, unsigned int length) {
  // Converter payload para string
  char msg[256] = {0};
  memcpy(msg, payload, min(length, (unsigned int)255));

  Serial.printf("[MQTT] Comando recebido no tópico '%s': %s\n", topic, msg);

  // Parse do comando JSON
  StaticJsonDocument<128> cmd;
  if (deserializeJson(cmd, msg) == DeserializationError::Ok) {
    // Comando: ativar/desativar modo simulação
    if (cmd.containsKey("modo_simulacao")) {
      modoSimulacaoAtaque = cmd["modo_simulacao"].as<bool>();
      Serial.printf("[CMD] Modo simulação: %s\n",
                    modoSimulacaoAtaque ? "ATIVADO" : "DESATIVADO");
    }
  }
}

// ============================================================
// UTILITÁRIOS
// ============================================================

/**
 * Imprime status completo da leitura atual no Serial Monitor.
 * Útil para debug e demonstração no vídeo da GS.
 */
void imprimirStatusSerial(SensorReading* leitura) {
  Serial.println("┌─────────────────────────────────────────┐");
  Serial.printf( "│  ORBIT-SHIELD | Leitura #%-15lu│\n", contadorLeituras);
  Serial.println("├─────────────────────────────────────────┤");
  Serial.printf( "│  Estação:    %-27s│\n", leitura->station_id);
  Serial.printf( "│  Timestamp:  %-27ld│\n", leitura->timestamp_unix);
  Serial.println("├──────────── SENSORES FÍSICOS ───────────┤");
  Serial.printf( "│  Temperatura CPU: %6.2f °C              │\n", leitura->temperatura_cpu);
  Serial.printf( "│  Sinal RF:       %6.2f dBm             │\n", leitura->sinal_rf_dbm);
  Serial.printf( "│  Energia:        %6.2f W               │\n", leitura->consumo_energia_w);
  Serial.println("├──────────── MÉTRICAS DE REDE ───────────┤");
  Serial.printf( "│  Pacotes/s:      %8.2f               │\n", leitura->pacotes_por_segundo);
  Serial.printf( "│  Bytes enviados: %8ld               │\n", leitura->bytes_enviados);
  Serial.printf( "│  Flags TCP:      %8d               │\n", leitura->flags_tcp);
  Serial.printf( "│  Tent. Auth:     %8d               │\n", leitura->tentativas_auth);
  Serial.println("├──────────── SEGURANÇA ──────────────────┤");
  Serial.printf( "│  HMAC: %.32s...  │\n", leitura->hash_hmac);
  Serial.printf( "│  Integridade: %-26s│\n",
                 leitura->integridade_ok ? "✅ OK" : "❌ COMPROMETIDA");
  Serial.printf( "│  Anomalia local: %-23s│\n",
                 leitura->anomalia_local ? leitura->tipo_anomalia : "Nenhuma");
  Serial.println("└─────────────────────────────────────────┘");
}
