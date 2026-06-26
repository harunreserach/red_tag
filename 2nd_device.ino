#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <Preferences.h>
#include <SPI.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <time.h>
#include <SPIFFS.h>
#include <Update.h>
#include <Ethernet.h>
#include <vector>
#include <functional>

const size_t MAX_WEB_LOG_SIZE = 8192;
String webLogBuffer = "";

class WebSerialProxy : public Print {
public:
  size_t write(uint8_t c) override {
    if(webLogBuffer.length() >= MAX_WEB_LOG_SIZE) {
      webLogBuffer = webLogBuffer.substring(MAX_WEB_LOG_SIZE / 2);
    }
    webLogBuffer += (char)c;
    return Serial.write(c);
  }
  size_t write(const uint8_t *buffer, size_t size) override {
    for(size_t i = 0; i < size; i++) {
      webLogBuffer += (char)buffer[i];
    }
    if(webLogBuffer.length() > MAX_WEB_LOG_SIZE) {
      webLogBuffer = webLogBuffer.substring(webLogBuffer.length() - MAX_WEB_LOG_SIZE / 2);
    }
    return Serial.write(buffer, size);
  }
  void begin(unsigned long baud) { Serial.begin(baud); }
  int available() { return Serial.available(); }
  int read() { return Serial.read(); }
  operator bool() { return Serial; }
};

WebSerialProxy WebSerialObj;

#define Serial WebSerialObj

// =================================================================================
// HTTPS/SSL OVER W5500 ETHERNET OPTION
// =================================================================================
// Using ArduinoBearSSL wrapper for ESP32/W5500 HTTPS Support
// Install via Library Manager: "ArduinoBearSSL" by Arduino
#define USE_BEARSSL

#ifdef USE_BEARSSL
#include <ArduinoBearSSL.h>

// --- Let's Encrypt R13 Trust Anchor ---
static const unsigned char R13_DN[] = { 0x30,0x33,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x55,0x53,0x31,0x16,0x30,0x14,0x06,0x03,0x55,0x04,0x0a,0x13,0x0d,0x4c,0x65,0x74,0x27,0x73,0x20,0x45,0x6e,0x63,0x72,0x79,0x70,0x74,0x31,0x0c,0x30,0x0a,0x06,0x03,0x55,0x04,0x03,0x13,0x03,0x52,0x31,0x33 };
static const unsigned char R13_RSA_N[] = { 0xa5,0x67,0x70,0x8d,0xd0,0x56,0x81,0x64,0x15,0x17,0x61,0xcd,0xb9,0x06,0xd4,0xad,0x19,0x90,0x8c,0x26,0x50,0x37,0x98,0x16,0x63,0x92,0x54,0xdb,0xd9,0xcc,0x84,0x05,0x93,0xec,0xd3,0xec,0x08,0x1b,0xa0,0x60,0x51,0x43,0x48,0x7d,0x2b,0xc7,0x48,0x96,0x9e,0xb4,0x2d,0xda,0x9d,0xc8,0x27,0x3b,0x57,0xa1,0x9f,0xab,0xf0,0xd6,0x0e,0xd4,0x0e,0x30,0xca,0x6f,0x9b,0xb1,0xd1,0xd6,0xa4,0x9d,0x32,0x3e,0x58,0x4e,0x35,0x6f,0x45,0x58,0x68,0x71,0x17,0xfc,0x3e,0xd8,0x5d,0x82,0xa0,0x2f,0xb2,0x51,0x6c,0xb0,0x1a,0x5d,0xb8,0x59,0xce,0x35,0x65,0xc8,0x8b,0xa1,0xaf,0x10,0x37,0xff,0xe3,0x9c,0x5d,0xc2,0x49,0x17,0x34,0xff,0x8c,0x2b,0x8b,0x8d,0xf0,0xbc,0x71,0x2c,0x93,0x0c,0x1d,0x05,0xc4,0xba,0xc7,0xcd,0xaa,0xc9,0x5e,0x7c,0xd1,0xc9,0x01,0xf7,0x9c,0x03,0xf6,0xfc,0x0a,0x5d,0xf4,0xda,0x7b,0xe6,0xdb,0x76,0x42,0x70,0xeb,0xf4,0x4d,0x22,0xda,0x00,0x77,0x6f,0xd6,0xc9,0x5f,0x17,0xfd,0xda,0x75,0x2e,0xa5,0x57,0x0c,0xf6,0xea,0x5c,0xb6,0xe0,0x73,0xa5,0x68,0xcf,0xa1,0x74,0xe2,0x75,0x82,0x7e,0x10,0x9f,0xc1,0xf5,0xa2,0xeb,0x01,0xe9,0x38,0xb1,0x0a,0x44,0xcc,0xd3,0xc2,0x89,0xf5,0x49,0x35,0x82,0x0a,0x34,0xb3,0x1c,0xe9,0x88,0xc2,0x47,0x4e,0x82,0x0e,0x0a,0x36,0xf0,0x47,0x4f,0x8a,0xf1,0x29,0x04,0x75,0xda,0xcd,0xe1,0x9a,0x5c,0xff,0x5e,0x9d,0x98,0x95,0xba,0x9a,0x43,0xd0,0x4a,0xa2,0x17,0x05,0x01,0x04,0x30,0xd3,0x32,0xb3,0x8f };
static const unsigned char R13_RSA_E[] = { 0x01,0x00,0x01 };

static const br_x509_trust_anchor bearssl_TAs[1] = {
    {
        (unsigned char *)R13_DN, sizeof(R13_DN),
        BR_X509_TA_CA,
        {
            BR_KEYTYPE_RSA,
            { .rsa = {
                (unsigned char *)R13_RSA_N, sizeof(R13_RSA_N),
                (unsigned char *)R13_RSA_E, sizeof(R13_RSA_E),
            }}
        }
    }
};
#endif
// =================================================================================

SemaphoreHandle_t spiMutex = NULL;

class MyEthernetServer : public EthernetServer {
public:
  MyEthernetServer(uint16_t port) : EthernetServer(port) {}
  virtual void begin(uint16_t port = 0) override {
    (void)port;
    EthernetServer::begin();
  }
};

class EthWebServer {
public:
  struct Argument {
    String name;
    String value;
  };

  struct Handler {
    String path;
    std::function<void()> fn;
  };

  EthWebServer(int port) : _server(port) {}

  void begin() {
    _server.begin();
  }

  void on(const String& path, std::function<void()> fn) {
    Handler h = {path, fn};
    _handlers.push_back(h);
  }

  void on(const String& path, int method, std::function<void()> fn) {
    (void)method;
    on(path, fn);
  }

  void onNotFound(std::function<void()> fn) {
    _notFoundHandler = fn;
  }

  void handleClient() {
    EthernetClient client = _server.available();
    if (!client) return;

    _currentClient = &client;
    _currentArgs.clear();
    _authHeaderValue = "";

    unsigned long timeout = millis() + 2000;
    String reqLine = "";
    while (client.connected() && millis() < timeout) {
      if (client.available()) {
        reqLine = client.readStringUntil('\n');
        reqLine.trim();
        break;
      }
      delay(1);
    }

    if (reqLine.length() == 0) {
      client.stop();
      _currentClient = nullptr;
      return;
    }

    bool isBlank = false;
    while (client.connected() && !isBlank && millis() < timeout) {
      if (client.available()) {
        String line = client.readStringUntil('\n');
        line.trim();
        if (line.length() == 0) {
          isBlank = true;
          break;
        }
        String lineLower = line;
        lineLower.toLowerCase();
        int index = lineLower.indexOf("authorization: basic ");
        if (index != -1) {
          _authHeaderValue = line.substring(index + 21);
          _authHeaderValue.trim();
        }
      } else {
        delay(1);
      }
    }

    int firstSpace = reqLine.indexOf(' ');
    int secondSpace = reqLine.lastIndexOf(' ');
    if (firstSpace == -1 || secondSpace == -1 || secondSpace <= firstSpace) {
      client.stop();
      _currentClient = nullptr;
      return;
    }

    String pathAndParams = reqLine.substring(firstSpace + 1, secondSpace);
    int questionMark = pathAndParams.indexOf('?');
    String path = "";
    if (questionMark == -1) {
      path = pathAndParams;
    } else {
      path = pathAndParams.substring(0, questionMark);
      String params = pathAndParams.substring(questionMark + 1);

      int pos = 0;
      while (pos < params.length()) {
        int nextAmp = params.indexOf('&', pos);
        String pair = "";
        if (nextAmp == -1) {
          pair = params.substring(pos);
          pos = params.length();
        } else {
          pair = params.substring(pos, nextAmp);
          pos = nextAmp + 1;
        }

        int equalSign = pair.indexOf('=');
        if (equalSign != -1) {
          Argument arg;
          arg.name = pair.substring(0, equalSign);
          arg.value = urlDecode(pair.substring(equalSign + 1));
          _currentArgs.push_back(arg);
        } else if (pair.length() > 0) {
          Argument arg;
          arg.name = pair;
          arg.value = "";
          _currentArgs.push_back(arg);
        }
      }
    }

    bool found = false;
    for (const auto& h : _handlers) {
      if (h.path == path) {
        h.fn();
        found = true;
        break;
      }
    }

    if (!found && _notFoundHandler) {
      _notFoundHandler();
    }

    // Gracefully wait for transmission to finish and consume remaining bytes to prevent TCP RST
    if (client.connected()) {
      client.flush();
      delay(50); // Give client time to read data
      while (client.available()) {
        client.read();
      }
    }
    client.stop();
    _currentClient = nullptr;
  }

  bool authenticate(const char* username, const char* password) {
    if (_authHeaderValue.length() == 0) {
      Serial.println("[EthWebServer] No Authorization header was provided.");
      return false;
    }
    String expected = String(username) + ":" + String(password);
    String expectedBase64 = customBase64Encode(expected);
    expectedBase64.trim();
    if (_authHeaderValue == expectedBase64) {
      // Serial.println("[EthWebServer] Authentication succeeded!");
      return true;
    } else {
      Serial.print("[EthWebServer] Authentication failed. Expected Base64 key: '");
      Serial.print(expectedBase64);
      Serial.print("' but received: '");
      Serial.print(_authHeaderValue);
      Serial.println("'");
      return false;
    }
  }

  void requestAuthentication() {
    if (!_currentClient) return;
    _currentClient->println("HTTP/1.1 401 Unauthorized");
    _currentClient->println("WWW-Authenticate: Basic realm=\"Login Required\"");
    _currentClient->println("Content-Type: text/plain");
    _currentClient->println("Connection: close");
    _currentClient->println();
    _currentClient->println("401 Unauthorized");
  }

  void send(int code, const String& contentType, const String& content) {
    if (!_currentClient) return;
    _currentClient->print("HTTP/1.1 ");
    _currentClient->print(code);
    _currentClient->println(" OK");
    _currentClient->print("Content-Type: ");
    _currentClient->println(contentType);
    _currentClient->print("Content-Length: ");
    _currentClient->println(content.length());
    _currentClient->println("Connection: close");
    _currentClient->println();
    
    // Send in chunks of 1024 bytes to prevent W5500 TX buffer overflow
    int totalLen = content.length();
    int bytesSent = 0;
    while (bytesSent < totalLen && _currentClient->connected()) {
      int chunkSize = 1024;
      if (totalLen - bytesSent < chunkSize) {
        chunkSize = totalLen - bytesSent;
      }
      _currentClient->write((const uint8_t*)(content.c_str() + bytesSent), chunkSize);
      bytesSent += chunkSize;
      _currentClient->flush();
      delay(1);
    }
    /*
    Serial.print("[EthWebServer] Sent ");
    Serial.print(bytesSent);
    Serial.print(" of ");
    Serial.print(totalLen);
    Serial.println(" bytes successfully.");
    */
  }

  String arg(const String& name) {
    for (const auto& a : _currentArgs) {
      if (a.name == name) return a.value;
    }
    return "";
  }

  bool hasArg(const String& name) {
    for (const auto& a : _currentArgs) {
      if (a.name == name) return true;
    }
    return false;
  }

private:
  MyEthernetServer _server;
  std::vector<Handler> _handlers;
  std::function<void()> _notFoundHandler;
  EthernetClient* _currentClient = nullptr;
  std::vector<Argument> _currentArgs;
  String _authHeaderValue = "";

  String customBase64Encode(const String& input) {
    const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    String encoded = "";
    int length = input.length();
    for (int i = 0; i < length; i += 3) {
      int remaining = length - i;
      if (remaining >= 3) {
        uint32_t val = ((uint8_t)input[i] << 16) | ((uint8_t)input[i+1] << 8) | (uint8_t)input[i+2];
        encoded += b64_table[(val >> 18) & 0x3F];
        encoded += b64_table[(val >> 12) & 0x3F];
        encoded += b64_table[(val >> 6) & 0x3F];
        encoded += b64_table[val & 0x3F];
      } else if (remaining == 2) {
        uint32_t val = ((uint8_t)input[i] << 8) | (uint8_t)input[i+1];
        encoded += b64_table[(val >> 10) & 0x3F];
        encoded += b64_table[(val >> 4) & 0x3F];
        encoded += b64_table[(val << 2) & 0x3F];
        encoded += '=';
      } else if (remaining == 1) {
        uint32_t val = (uint8_t)input[i];
        encoded += b64_table[(val >> 2) & 0x3F];
        encoded += b64_table[(val << 4) & 0x3F];
        encoded += "==";
      }
    }
    return encoded;
  }

  String urlDecode(String str) {
    String decoded = "";
    char temp[] = "0x00";
    unsigned int len = str.length();
    unsigned int i = 0;
    while (i < len) {
      char decodedChar;
      char encodedChar = str.charAt(i);
      if (encodedChar == '%') {
        if (i + 2 < len) {
          temp[2] = str.charAt(i + 1);
          temp[3] = str.charAt(i + 2);
          decodedChar = (char)strtol(temp, NULL, 16);
          decoded += decodedChar;
          i += 3;
        } else {
          decoded += encodedChar;
          i++;
        }
      } else if (encodedChar == '+') {
        decoded += ' ';
        i++;
      } else {
        decoded += encodedChar;
        i++;
      }
    }
    return decoded;
  }
};

// --- ETHERNET MODULE SETTINGS ---
byte mac[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED};
String ethIpStr = "192.168.0.177";
String ethGatewayStr = "192.168.0.1";
String ethSubnetStr = "255.255.255.0";
String ethDnsStr = "8.8.8.8";
IPAddress ethIP(192, 168, 0, 177);
IPAddress ethGateway(192, 168, 0, 1);
IPAddress ethSubnet(255, 255, 255, 0);
IPAddress ethDNS(8, 8, 8, 8);
EthernetClient net;

bool isNetworkConnected() {
  bool wifiConnected = (WiFi.status() == WL_CONNECTED);
  bool ethConnected = false;
  if (spiMutex && xSemaphoreTake(spiMutex, portMAX_DELAY) == pdTRUE) {
    ethConnected = (Ethernet.localIP() != IPAddress(0, 0, 0, 0) && Ethernet.localIP() != IPAddress(255, 255, 255, 255));
    if (ethConnected) {
      ethConnected = (Ethernet.linkStatus() == LinkON);
    }
    xSemaphoreGive(spiMutex);
  }
  return wifiConnected || ethConnected;
}

// --- OTA SETTINGS ---
String CURRENT_VERSION = "Node-v4.1";
String otaAutoUrl = "http://app.harunurrashid.com/iot/firmware.bin";
String versionCheckUrl = "http://app.harunurrashid.com/iot/version.txt";
bool autoUpdateEnabled = false;
unsigned long lastUpdateCheck = 0;
const unsigned long UPDATE_CHECK_INTERVAL = 86400000; // 24 hours

// --- PINS (From your working code) ---
#define I2C_SDA    21
#define I2C_SCL    22
// --- NEW PINS FOR FACTORY USE CASE ---
#define STATUS_LED   14
#define STATUS_RELAY 15
/// new IO ///
#define THIRD_RELAY 21
#define SECOND_RELAY 22
#define FIRST_RELAY 26

#define RESET_BUTTON 25  // Physical reset button on pin 25
#define FIFTH_TAG_BUTTON 34 
#define FOURTH_TAG_BUTTON 35
/// new IO ///
#define THIRD_TAG_BUTTON 33
#define SECOND_TAG_BUTTON 27 // chnge 12 to 27 EXT1 Pin, as this pin creted problem
#define FIRST_TAG_BUTTON 13

// LED physical indicators for system status
#define STATUS_LED_1 16
#define STATUS_LED_2 17

// ACTIVE-LOW LED LOGIC FOR LED 1
#define LED_1_ON  LOW
#define LED_1_OFF HIGH

// --- SERVER SETTINGS (Defaults) ---
String serverUrl = "http://app.harunurrashid.com/iot/index.php";
String heartbeatUrl = "http://app.harunurrashid.com/iot/index.php";
String apiKey = "YourSecretAPIKey123";
String webUser = "admin";
String webPass = "admin123";
const char* NTP_SERVER = "pool.ntp.org";
const long  GMT_OFFSET_SEC = 6 * 3600; // Bangladesh UTC+6
const int   DAYLIGHT_OFFSET_SEC = 0;

// --- SETTINGS ---
const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 4, 1);
DNSServer dnsServer;
WebServer server(80);
EthWebServer ethServer(80);
Preferences preferences;

// --- INSTANCES ---
// MFRC522 and Display removed for 2nd project

// --- ASYNC TASKING ---
enum EventType {
  EVENT_CARD_AUTH,
  EVENT_CARD_UNAUTH,
  EVENT_CARD_LEARN,
  EVENT_HEARTBEAT,
  EVENT_WRITE_SUCCESS,
  EVENT_WRITE_FAILED,
  EVENT_READ_SUCCESS
};

struct SwipeEvent {
  EventType type;
  String uid;
  String line;
  String user;
  String tagType;
  String currentStatus;
  int status;
};

QueueHandle_t displayQueue;
QueueHandle_t networkQueue;
TaskHandle_t displayTaskHandle;
TaskHandle_t networkTaskHandle;

// --- VARIABLES ---
String ssid;
String pass;
String lastScannedUID = "None";
unsigned long lastScanTime = 0;
unsigned long lastNtpSync = 0;
const unsigned long NTP_SYNC_INTERVAL = 3600000; // Sync every 1 hour
unsigned long heartbeatInterval = 60000; // Default 1 minute
unsigned long syncInterval = 600000; // Default 10 minutes
bool timeSynced = false;
int operational_status = 0; // 0 = Resolved, 1 = Issue
int status_led_state = 0;
int status_relay_state = 0;
 /// new IO for 3 Relay ///
int third_relay_state = 0;
int second_relay_state = 0;
int first_relay_state = 0;
String authorizedCards = ""; // Comma separated UIDs
bool learnMode = false;
bool writeMode = false;
bool readMode = false;
bool cardManagementMode = false;
String writeLine = "";
String writeName = "";
String lastReadInfo = "";
String lastWriteStatus = "";
String deviceId = "DEV-001";
String deviceType = "red_tag";
String factoryName = "My Factory";
String setupDate = "2024-01-01";
String lineCode = "L-001";
String lastJSON = "{}";
String lastHbJSON = "{}";
String lastSwipeDate = "0000-00-00";
String lastSwipeTime = "00:00:00";
String lastSwipeUser = "None";
String lastSwipeLine = "None";
String msgIssue = "ISSUE REPORTED";
String msgResolved = "ISSUE RESOLVED";
bool displayReset = true;
unsigned long lastWebActivity = 0;
const unsigned long SESSION_TIMEOUT = 180000; // 3 minutes
unsigned long buttonHoldStart = 0;
bool resetting = false;
const char* LOG_FILE = "/offline.log";
bool isSyncing = false;
unsigned long lastHeartbeat = 0;
bool serverConnected = false;
bool systemReady = false;
bool configPortalActive = false;
bool triggerWifiConnect = false;
unsigned long triggerWifiConnectTime = 0;
String wifiConfigStatus = "IDLE";
String gotWiFiIP = "0.0.0.0";
int lastEthernetStatusCode = -1;
int lastFifthState = -1;
int lastFourthState = -1;

 /// new IO ///
int lastThirdState = -1;
int lastSecondState = -1;
int lastFirstState = -1;

// --- FUNCTION PROTOTYPES ---
void updateHardwareState();
void updateDisplay(String title, String line1, String line2);
void startConfigMode();
void startNormalMode();
void handleRootConfig();
void handleSave();
void handleRootNormal();
void syncTime();
String readCardData();
bool writeCardData(String line, String name);
bool isAuthorized(String uid);
void addAuthorizedCard(String uid);
bool postToServer(String uid, String cardLine, String cardUser, String tagType, String currentStatus, String eventDate = "", String eventTime = "", int eventStatus = -1);
void saveOfflineLog(String uid, String line, String user, String date, String time, int status, String tagType, String currentStatus);
void syncOfflineLogs();
void displayTask(void *pvParameters);
void networkTask(void *pvParameters);
void ledIndicatorTask(void *pvParameters);
void sendHeartbeat();

#ifdef USE_BEARSSL
unsigned long getBearSSLTime() {
  time_t now = time(nullptr);
  // If time is not set properly, return a dummy recent timestamp (e.g. roughly June 2026) -> 1782000000 
  // This bypasses ArduinoBearSSL returning 0 (which causes X509 cert validation rejection).
  if (now < 1700000000) {
     return 1782000000;
  }
  return now;
}
#endif

void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\n--- SYSTEM STARTING ---");
  
#ifdef USE_BEARSSL
  ArduinoBearSSL.onGetTime(getBearSSLTime);
#endif

  spiMutex = xSemaphoreCreateMutex();
  
  // Initialize Preferences to load Ethernet settings first
  preferences.begin("factory-app", false);
  ethIpStr = preferences.getString("eth_ip", "192.168.0.177");
  ethGatewayStr = preferences.getString("eth_gateway", "192.168.0.1");
  ethSubnetStr = preferences.getString("eth_subnet", "255.255.255.0");
  ethDnsStr = preferences.getString("eth_dns", "8.8.8.8");
  
  // Quick pre-load URLs from preferences to ensure they are trimmed
  serverUrl = preferences.getString("server_url", serverUrl);
  heartbeatUrl = preferences.getString("hb_url", heartbeatUrl);
  apiKey = preferences.getString("api_key", apiKey);
  serverUrl.trim();
  heartbeatUrl.trim();
  apiKey.trim();
  preferences.putString("server_url", serverUrl);
  preferences.putString("hb_url", heartbeatUrl);
  preferences.putString("api_key", apiKey);
  
  preferences.end();

  // Convert settings to IPAddress
  if (!ethIP.fromString(ethIpStr)) { ethIP = IPAddress(192, 168, 0, 177); ethIpStr = "192.168.0.177"; }
  if (!ethGateway.fromString(ethGatewayStr)) { ethGateway = IPAddress(192, 168, 0, 1); ethGatewayStr = "192.168.0.1"; }
  if (!ethSubnet.fromString(ethSubnetStr)) { ethSubnet = IPAddress(255, 255, 255, 0); ethSubnetStr = "255.255.255.0"; }
  if (!ethDNS.fromString(ethDnsStr)) { ethDNS = IPAddress(8, 8, 8, 8); ethDnsStr = "8.8.8.8"; }

  // Ethernet init add at the void setup()  section
  Ethernet.init(5); //CS pin IO33
  Ethernet.begin(mac, ethIP, ethDNS, ethGateway, ethSubnet);
  if (Ethernet.localIP() == ethIP){
    Serial.print("✓ Static IP: ");
    Serial.println(Ethernet.localIP());
  }else {
    Serial.print("✗ Failed. Local IP: ");
    Serial.println(Ethernet.localIP());
  }

  // Wait up to 3 seconds for physical link to establish to prevent early connection failures
  Serial.print("[Eth] Waiting for physical link to establish...");
  int linkChecks = 0;
  while (Ethernet.linkStatus() != LinkON && linkChecks < 30) {
    delay(100);
    linkChecks++;
  }
  if (Ethernet.linkStatus() == LinkON) {
    Serial.println(" Established! Link is UP.");
  } else {
    Serial.println(" Time out. Standard operation will proceed.");
  }
  
  // Initialize GPIOs
  pinMode(STATUS_LED, OUTPUT);
  pinMode(STATUS_RELAY, OUTPUT);
  pinMode(STATUS_LED_1, OUTPUT);
  pinMode(STATUS_LED_2, OUTPUT);
  digitalWrite(STATUS_LED_1, LED_1_OFF);
  
   /// new IO end for 3 relay ///
  pinMode(THIRD_RELAY, OUTPUT);
  pinMode(SECOND_RELAY, OUTPUT);
  pinMode(FIRST_RELAY, OUTPUT);

  pinMode(RESET_BUTTON, INPUT_PULLUP);
  pinMode(FIFTH_TAG_BUTTON, INPUT_PULLUP);
  pinMode(FOURTH_TAG_BUTTON, INPUT_PULLUP);
 /// new IO ///
  pinMode(THIRD_TAG_BUTTON, INPUT_PULLUP);
  pinMode(SECOND_TAG_BUTTON, INPUT_PULLUP);
  pinMode(FIRST_TAG_BUTTON, INPUT_PULLUP);
  
  if(!SPIFFS.begin(true)) {
    Serial.println("SPIFFS Mount Failed");
  }

  // Initialize Preferences
  preferences.begin("factory-app", false);
  ssid = preferences.getString("ssid", "");
  pass = preferences.getString("pass", "");
  authorizedCards = preferences.getString("auth_cards", "");
  operational_status = preferences.getInt("op_status", 0);
  status_relay_state = (preferences.getInt("fifth_state", digitalRead(FIFTH_TAG_BUTTON)) == HIGH) ? 1 : 0;
  status_led_state = (preferences.getInt("fourth_state", digitalRead(FOURTH_TAG_BUTTON)) == HIGH) ? 1 : 0;
 /// new IO for 3 relay ///
  third_relay_state = (preferences.getInt("third_state", digitalRead(THIRD_TAG_BUTTON)) == HIGH) ? 1 : 0;
  second_relay_state = (preferences.getInt("second_state", digitalRead(SECOND_TAG_BUTTON)) == HIGH) ? 1 : 0;
  first_relay_state = (preferences.getInt("first_state", digitalRead(FIRST_TAG_BUTTON)) == HIGH) ? 1 : 0;
  deviceId = preferences.getString("device_id", "DEV-001");
  deviceType = preferences.getString("device_type", "red_tag");
  factoryName = preferences.getString("factory_name", "My Factory");
  setupDate = preferences.getString("setup_date", "2024-01-01");
  lineCode = preferences.getString("line_code", "L-001");
  //msgIssue = preferences.getString("msg_issue", "ISSUE REPORTED");
  //msgResolved = preferences.getString("msg_resolved", "ISSUE RESOLVED");
  msgIssue = preferences.getString("msg_issue", "ISSUE"); // updated 09-06-26
  msgResolved = preferences.getString("msg_resolved", "RESOLVED"); // updated 09-06-26
  serverUrl = preferences.getString("server_url", "http://app.harunurrashid.com/iot/index.php");
  heartbeatUrl = preferences.getString("hb_url", serverUrl);
  heartbeatInterval = preferences.getULong("hb_interval", 60000);
  syncInterval = preferences.getULong("sync_interval", 600000);
  apiKey = preferences.getString("api_key", "YourSecretAPIKey123");
  webUser = preferences.getString("web_user", "admin");
  webPass = preferences.getString("web_pass", "admin123");
  otaAutoUrl = preferences.getString("ota_url", "http://app.harunurrashid.com/iot/firmware.bin");
  versionCheckUrl = preferences.getString("ver_url", "http://app.harunurrashid.com/iot/version.txt");
  autoUpdateEnabled = preferences.getBool("ota_auto", false);
  lastFifthState = preferences.getInt("fifth_state", digitalRead(FIFTH_TAG_BUTTON));
  lastFourthState = preferences.getInt("fourth_state", digitalRead(FOURTH_TAG_BUTTON));
 /// new IO ///
  lastThirdState = preferences.getInt("third_state", digitalRead(THIRD_TAG_BUTTON));
  lastSecondState = preferences.getInt("second_state", digitalRead(SECOND_TAG_BUTTON));
  lastFirstState = preferences.getInt("first_state", digitalRead(FIRST_TAG_BUTTON));

  preferences.end();
  
  updateHardwareState();

// --- ASYNC SETUP ---
  displayQueue = xQueueCreate(10, sizeof(SwipeEvent*));
  networkQueue = xQueueCreate(10, sizeof(SwipeEvent*));

  xTaskCreatePinnedToCore(displayTask, "DisplayTask", 4096, NULL, 2, &displayTaskHandle, 1);
  xTaskCreatePinnedToCore(networkTask, "NetworkTask", 32768, NULL, 1, &networkTaskHandle, 0);
  xTaskCreatePinnedToCore(ledIndicatorTask, "LedIndicatorTask", 2048, NULL, 1, NULL, 1);
  
  // -- ALWAYS START ETHERNET WEB SERVER ALWAYS ACCESSIBLE --
  registerNormalHandlers(ethServer);
  
  if (ssid == "") {
    startConfigMode();
    updateDisplay("SETUP MODE", "Connect to:", "IOT-Device");
  } else {
    WiFi.persistent(false);
    WiFi.disconnect(true);
    delay(200);
    WiFi.mode(WIFI_STA);
    WiFi.config(INADDR_NONE, INADDR_NONE, INADDR_NONE); // Force DHCP
    delay(200);
    WiFi.begin(ssid.c_str(), pass.c_str());
    WiFi.setSleep(false); // Optimize for active performance, prevent sleep disconnects
    
    updateDisplay("CONNECTING", ssid, "...");
    Serial.print("Connecting to: "); Serial.println(ssid);
    int counter = 0;
    while (WiFi.status() != WL_CONNECTED && counter < 60) {
      delay(500);
      Serial.print(".");
      counter++;
      // Show dynamic dots (1, 2, or 3 dots) on OLED
      String dots = "";
      for (int i = 0; i < (counter % 4); i++) dots += ".";
      if (dots == "") dots = ".";
      updateDisplay("CONNECTING", ssid, dots);
    }
    
    if (WiFi.status() != WL_CONNECTED) {
      Serial.println("\nWiFi Connection Failed at Boot. Starting fallback AP_STA mode so you can reconfigure...");
      configPortalActive = true;
      WiFi.mode(WIFI_AP_STA);
      WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
      WiFi.softAP("IOT-Device");
      dnsServer.start(DNS_PORT, "*", apIP);
      
      server.on("/", handleRootConfig);
      server.on("/save", HTTP_POST, handleSave);
      server.on("/save_status", HTTP_GET, handleSaveStatus);
      server.onNotFound([]() {
        server.sendHeader("Location", "http://192.168.4.1/", true);
        server.send(302, "text/plain", "");
      });
      server.begin();
      
      updateDisplay("AP Active:", "IOT-Device", "192.168.4.1");
      delay(5000);
      displayReset = true;
      lastScanTime = millis() - 5000;
    } else {
      Serial.println("\nWiFi Connected!");
      updateDisplay("GETTING IP", ssid, "Please wait...");
      
      // Wait for a valid IP address (DHCP assignment)
      int ip_wait_counter = 0;
      while (WiFi.localIP().toString() == "0.0.0.0" && ip_wait_counter < 30) {
        delay(500);
        Serial.print("o");
        ip_wait_counter++;
      }
      
      Serial.print("\nObtained IP Address: ");
      Serial.println(WiFi.localIP()); 
      
      startNormalMode();
      syncTime();
      updateDisplay("CONNECTED", ssid, WiFi.localIP().toString());
      
      // Keep showing connection details for 5 seconds
      lastScanTime = millis();
      displayReset = false;
      delay(5000);
      
      // Let it transition back to the default operational display
      displayReset = true;
      lastScanTime = millis() - 5000;
    }
  }
  systemReady = true;
}

void loop() {
  if (digitalRead(RESET_BUTTON) == LOW) {
    if (buttonHoldStart == 0) {
      buttonHoldStart = millis();
      resetting = false;
    }
    
    unsigned long holdTime = millis() - buttonHoldStart;
    
    // Provide visual feedback every 500ms while holding
    static unsigned long lastHoldFeedback = 0;
    if (millis() - lastHoldFeedback > 500 || lastHoldFeedback == 0) {
      lastHoldFeedback = millis();
      if (holdTime >= 6000) {
        //updateDisplay("RELEASE BUTTON", "FOR", "FACTORY RESET");
        updateDisplay("FACTORY", "RST", "");
        Serial.println("[BUTTON] Hold time >= 6s. Release for Factory Reset.");
      } else if (holdTime >= 3000) {
        //updateDisplay("RELEASE BUTTON", "FOR", "WIFI RESET");
        updateDisplay("Wi-Fi", "RST", "");
        Serial.println("[BUTTON] Hold time >= 3s. Release for WiFi Reset.");
      } else {
        int remaining = 3 - (holdTime / 1000);
        //updateDisplay("RESET BUTTON", "Hold " + String(remaining) + "s for", "WiFi Reset");
        updateDisplay("RESET BTN", "Hold " + String(remaining) + "s for", "WiFi Reset");
        Serial.println("[BUTTON] Holding reset button. Time: " + String(holdTime) + "ms");
      }
    }
    
    delay(50); // Debounce / polling delay
  } else {
    if (buttonHoldStart != 0) {
      unsigned long holdTime = millis() - buttonHoldStart;
      buttonHoldStart = 0;
      
      if (holdTime >= 6000) {
        // Factory Reset
        Serial.println("\n[SYSTEM] PHYSICAL FACTORY RESET INITIATED");
        updateDisplay("FACTORY RESET", "Wiping all memory", "Please wait...");
        preferences.begin("factory-app", false);
        preferences.clear();
        // Set default ethernet settings in memory on factory reset
        preferences.putString("eth_ip", "192.168.0.177");
        preferences.putString("eth_gateway", "192.168.0.1");
        preferences.putString("eth_subnet", "255.255.255.0");
        preferences.putString("eth_dns", "8.8.8.8");
        preferences.end();
        Serial.println("[SYSTEM] Preferences Cleared & Defaults Saved. Formatting SPIFFS...");
        SPIFFS.format();
        Serial.println("[SYSTEM] SPIFFS Formatted. Rebooting...");
        delay(2000);
        ESP.restart();
      } else if (holdTime >= 3000) {
        // WiFi Reset
        Serial.println("\n[SYSTEM] PHYSICAL WIFI RESET INITIATED");
        updateDisplay("WIFI RESET", "Clearing WiFi info", "Rebooting...");
        preferences.begin("factory-app", false);
        preferences.remove("ssid");
        preferences.remove("pass");
        preferences.end();
        delay(2000);
        ESP.restart();
      } else {
        // Release too early, go back to normal view
        Serial.println("[BUTTON] Released early. Hold longer for Reset.");
        displayReset = true;
        lastScanTime = millis() - 5000; // Trigger redraw in displayTask
      }
    }
  }

  // RFID scanning logic removed for 2nd project

  static unsigned long lastFifthDebounceTime = 0;
  static int lastFifthReading = digitalRead(FIFTH_TAG_BUTTON);
  int currentFifthReading = digitalRead(FIFTH_TAG_BUTTON);
  if (currentFifthReading != lastFifthReading) {
    lastFifthDebounceTime = millis();
  }
  if ((millis() - lastFifthDebounceTime) > 50) {
    if (currentFifthReading != lastFifthState) {
      lastFifthState = currentFifthReading;
      preferences.begin("factory-app", false);
      preferences.putInt("fifth_state", currentFifthReading);
      preferences.end();
      Serial.print("Fifth Tag Button Level Change: "); Serial.println(currentFifthReading == HIGH ? "HIGH" : "LOW");
      operational_status = (currentFifthReading == HIGH) ? 1 : 0; 
      status_relay_state = operational_status;
      updateHardwareState();
      SwipeEvent* event = new SwipeEvent();
      event->type = EVENT_CARD_AUTH; event->uid = "FIFTH_TAG_BTN"; event->line = "fifth_tag";
      //event->user = "Manual_Switch_5"; event->tagType = "fifth"; event->currentStatus = "online";
      event->user = "Tag_5"; event->tagType = "fifth"; event->currentStatus = "online"; // updated 09-06-26
      event->status = operational_status;
      SwipeEvent* dispEvent = new SwipeEvent(); *dispEvent = *event;
      xQueueSend(displayQueue, &dispEvent, 0); xQueueSend(networkQueue, &event, 0);
      lastScanTime = millis(); displayReset = false;
    }
  }
  lastFifthReading = currentFifthReading;

  static unsigned long lastFourthDebounceTime = 0;
  static int lastFourthReading = digitalRead(FOURTH_TAG_BUTTON);
  int currentFourthReading = digitalRead(FOURTH_TAG_BUTTON);
  if (currentFourthReading != lastFourthReading) {
    lastFourthDebounceTime = millis();
  }
  if ((millis() - lastFourthDebounceTime) > 50) {
    if (currentFourthReading != lastFourthState) {
      lastFourthState = currentFourthReading;
      preferences.begin("factory-app", false);
      preferences.putInt("fourth_state", currentFourthReading);
      preferences.end();
      Serial.print("Fourth Tag Button Level Change: "); Serial.println(currentFourthReading == HIGH ? "HIGH" : "LOW");
      operational_status = (currentFourthReading == HIGH) ? 1 : 0; 
      status_led_state = operational_status;
      updateHardwareState();
      SwipeEvent* event = new SwipeEvent();
      event->type = EVENT_CARD_AUTH; event->uid = "FOURTH_TAG_BTN"; event->line = "fourth_tag";
      //event->user = "Manual_Switch_4"; event->tagType = "fourth"; event->currentStatus = "online";
      event->user = "Tag_4"; event->tagType = "fourth"; event->currentStatus = "online"; // updated 09-06-26
      event->status = operational_status;
      SwipeEvent* dispEvent = new SwipeEvent(); *dispEvent = *event;
      xQueueSend(displayQueue, &dispEvent, 0); xQueueSend(networkQueue, &event, 0);
      lastScanTime = millis(); displayReset = false;
    }
  }
  lastFourthReading = currentFourthReading;

 /// new IO for 3 relay
  static unsigned long lastThirdDebounceTime = 0;
  static int lastThirdReading = digitalRead(THIRD_TAG_BUTTON);
  int currentThirdReading = digitalRead(THIRD_TAG_BUTTON);
  if (currentThirdReading != lastThirdReading) {
    lastThirdDebounceTime = millis();
  }
  if ((millis() - lastThirdDebounceTime) > 50) {
    if (currentThirdReading != lastThirdState) {
      lastThirdState = currentThirdReading;
      preferences.begin("factory-app", false);
      preferences.putInt("third_state", currentThirdReading);
      preferences.end();
      Serial.print("Third Tag Button Level Change: "); Serial.println(currentThirdReading == HIGH ? "HIGH" : "LOW");
      operational_status = (currentThirdReading == HIGH) ? 1 : 0; 
      third_relay_state = operational_status;///
      updateHardwareState();
      SwipeEvent* event = new SwipeEvent();
      event->type = EVENT_CARD_AUTH; event->uid = "Third_TAG_BTN"; event->line = "Third_tag";
      //event->user = "Manual_Switch_4"; event->tagType = "Third"; event->currentStatus = "online";
      event->user = "Tag_3"; event->tagType = "Third"; event->currentStatus = "online"; // updated 09-06-26
      event->status = operational_status;
      SwipeEvent* dispEvent = new SwipeEvent(); *dispEvent = *event;
      xQueueSend(displayQueue, &dispEvent, 0); xQueueSend(networkQueue, &event, 0);
      lastScanTime = millis(); displayReset = false;
    }
  }
  lastThirdReading = currentThirdReading;

 /// new IO end for THIRD_TAG ///

  /// new IO /// for Second_TAG
  static unsigned long lastSecondDebounceTime = 0;
  static int lastSecondReading = digitalRead(SECOND_TAG_BUTTON);
  int currentSecondReading = digitalRead(SECOND_TAG_BUTTON);
  if (currentSecondReading != lastSecondReading) {
    lastSecondDebounceTime = millis();
  }
  if ((millis() - lastSecondDebounceTime) > 50) {
    if (currentSecondReading != lastSecondState) {
      lastSecondState = currentSecondReading;
      preferences.begin("factory-app", false);
      preferences.putInt("second_state", currentSecondReading);
      preferences.end();
      Serial.print("Second Tag Button Level Change: "); Serial.println(currentSecondReading == HIGH ? "HIGH" : "LOW");
      operational_status = (currentSecondReading == HIGH) ? 1 : 0; 
      second_relay_state = operational_status;
      updateHardwareState();
      SwipeEvent* event = new SwipeEvent();
      event->type = EVENT_CARD_AUTH; event->uid = "Second_TAG_BTN"; event->line = "Second_tag";
      //event->user = "Manual_Switch_4"; event->tagType = "Second"; event->currentStatus = "online";
      event->user = "Tag_2"; event->tagType = "Second"; event->currentStatus = "online"; // updated 09-06-26
      event->status = operational_status;
      SwipeEvent* dispEvent = new SwipeEvent(); *dispEvent = *event;
      xQueueSend(displayQueue, &dispEvent, 0); xQueueSend(networkQueue, &event, 0);
      lastScanTime = millis(); displayReset = false;
    }
  }
  lastSecondReading = currentSecondReading;

 /// new IO end for SECOND_TAG ///
 
  /// new IO /// for First_TAG
  static unsigned long lastFirstDebounceTime = 0;
  static int lastFirstReading = digitalRead(FIRST_TAG_BUTTON);
  int currentFirstReading = digitalRead(FIRST_TAG_BUTTON);
  if (currentFirstReading != lastFirstReading) {
    lastFirstDebounceTime = millis();
  }
  if ((millis() - lastFirstDebounceTime) > 50) {
    if (currentFirstReading != lastFirstState) {
      lastFirstState = currentFirstReading;
      preferences.begin("factory-app", false);
      preferences.putInt("first_state", currentFirstReading);
      preferences.end();
      Serial.print("First Tag Button Level Change: "); Serial.println(currentFirstReading == HIGH ? "HIGH" : "LOW");
      operational_status = (currentFirstReading == HIGH) ? 1 : 0; 
      first_relay_state = operational_status;
      updateHardwareState();
      SwipeEvent* event = new SwipeEvent();
      event->type = EVENT_CARD_AUTH; event->uid = "First_TAG_BTN"; event->line = "First_tag";
      //event->user = "Manual_Switch_4"; event->tagType = "First"; event->currentStatus = "online";
      event->user = "Tag_1"; event->tagType = "First"; event->currentStatus = "online"; // updated 09-06-26
      event->status = operational_status;
      SwipeEvent* dispEvent = new SwipeEvent(); *dispEvent = *event;
      xQueueSend(displayQueue, &dispEvent, 0); xQueueSend(networkQueue, &event, 0);
      lastScanTime = millis(); displayReset = false;
    }
  }
  lastFirstReading = currentFirstReading;

 /// new IO end for FIRST_TAG ///

  if (millis() - lastScanTime > 5000 && !displayReset) displayReset = true;

  // Periodic OTA check
  if (autoUpdateEnabled && (millis() - lastUpdateCheck > UPDATE_CHECK_INTERVAL)) {
    lastUpdateCheck = millis();
    checkForUpdates();
  }
  
  delay(5);
}

String lastOtaStatus = "Idle";

String checkForUpdates() {
  if (WiFi.status() != WL_CONNECTED) {
    lastOtaStatus = "WiFi Disconnected (OTA requires WiFi)";
    return lastOtaStatus;
  }
  
  WiFiClient clientPlain;
  WiFiClientSecure clientSecure;
  clientSecure.setInsecure();
  HTTPClient http;
  http.setTimeout(10000); 
  
  Serial.println("[OTA] Checking: " + versionCheckUrl);
  lastOtaStatus = "Checking server...";
  bool beginSuccess = false;
  if(versionCheckUrl.startsWith("https")) {
    beginSuccess = http.begin(clientSecure, versionCheckUrl);
  } else {
    beginSuccess = http.begin(clientPlain, versionCheckUrl);
  }
  
  if (!beginSuccess) {
    lastOtaStatus = "Failed to begin HTTP client";
    return lastOtaStatus;
  }
  
  int httpCode = http.GET();
  
  if (httpCode == 200) {
    String newVersion = http.getString();
    newVersion.trim();
    
    if (newVersion != CURRENT_VERSION && newVersion.length() > 0) {
      Serial.println("[OTA] New version found: " + newVersion);
      lastOtaStatus = "Downloading " + newVersion + "...";
      updateDisplay("UPDATING", "To: " + newVersion, "... 0%");
      
      http.end();
      if(otaAutoUrl.startsWith("https")) {
        http.begin(clientSecure, otaAutoUrl);
      } else {
        http.begin(clientPlain, otaAutoUrl);
      }
      int binCode = http.GET();
      if (binCode == 200) {
        int contentLength = http.getSize();
        if (contentLength > 0) {
          if (Update.begin(contentLength)) {
            WiFiClient* stream = http.getStreamPtr();
            uint8_t buf[1024];
            size_t totalWritten = 0;
            while (http.connected() && totalWritten < contentLength) {
              size_t available = stream->available();
              if (available > 0) {
                size_t toRead = min(available, (size_t)sizeof(buf));
                size_t read = stream->readBytes(buf, toRead);
                if (read > 0) {
                  Update.write(buf, read);
                  totalWritten += read;
                  int progress = (totalWritten * 100) / contentLength;
                  if (totalWritten % 10240 == 0 || totalWritten == contentLength) { // Update every 10KB or at finish
                    updateDisplay("UPDATING", newVersion, "Progress: " + String(progress) + "%");
                    lastOtaStatus = "Downloading: " + String(progress) + "%";
                  }
                  yield();
                }
              }
              vTaskDelay(1); 
            }
            if (Update.end()) {
              if (Update.isFinished()) {
                lastOtaStatus = "Success! Rebooting...";
                Serial.println("[OTA] Success! Rebooting...");
                delay(1000);
                ESP.restart();
                return "Rebooting..."; // Never actually reaches here
              }
            }
            lastOtaStatus = "Update Failed: " + String(Update.getError());
            updateDisplay("OTA FAIL", "Error Code:", String(Update.getError()));
          } else {
            lastOtaStatus = "Not enough space";
          }
        } else {
          lastOtaStatus = "Binary empty";
        }
      } else {
        lastOtaStatus = "Binary Download Error: " + String(binCode);
      }
    } else {
      lastOtaStatus = "Up to date (" + CURRENT_VERSION + ")";
    }
  } else {
    lastOtaStatus = "Server Unreachable: " + String(httpCode);
  }
  http.end();
  return lastOtaStatus;
}

void displayTask(void *pvParameters) {
  for (;;) {
    if (buttonHoldStart != 0 || digitalRead(RESET_BUTTON) == LOW) {
      SwipeEvent* staleEvent;
      while (xQueueReceive(displayQueue, &staleEvent, 0) == pdPASS) {
        delete staleEvent;
      }
      vTaskDelay(50 / portTICK_PERIOD_MS);
      continue;
    }

    SwipeEvent* event;
    if (xQueueReceive(displayQueue, &event, 100 / portTICK_PERIOD_MS) == pdPASS) {
      //if (event->type == EVENT_CARD_AUTH) updateDisplay((event->status == 1) ? msgIssue : msgResolved, "User: " + event->user, "Line: " + event->line);
      if (event->type == EVENT_CARD_AUTH) updateDisplay((event->status == 1) ? msgIssue : msgResolved, "Event: " + event->user, ""); // updated 09-06-26 
      else if (event->type == EVENT_CARD_UNAUTH) updateDisplay("UNAUTHORIZED", "Access Denied", event->uid);
      else if (event->type == EVENT_CARD_LEARN) updateDisplay("CARD LEARNED", "Added UID:", event->uid);
      else if (event->type == EVENT_WRITE_SUCCESS) updateDisplay("WRITE SUCCESS", "Line: " + event->line, "User: " + event->user);
      else if (event->type == EVENT_WRITE_FAILED) updateDisplay("WRITE FAILED", "Check Serial", "Monitor");
      else if (event->type == EVENT_READ_SUCCESS) updateDisplay("READ SUCCESS", "Data Read", event->line);
      delete event;
    }
    if (displayReset && millis() - lastScanTime > 5000) {
      bool wifiConnected = (WiFi.status() == WL_CONNECTED);
      IPAddress ethIPVal(0, 0, 0, 0);
      bool ethConnected = false;
      if (spiMutex && xSemaphoreTake(spiMutex, portMAX_DELAY) == pdTRUE) {
        ethIPVal = Ethernet.localIP();
        ethConnected = (ethIPVal != IPAddress(0, 0, 0, 0) && ethIPVal != IPAddress(255, 255, 255, 255) && Ethernet.linkStatus() == LinkON);
        xSemaphoreGive(spiMutex);
      }
      
      if (ssid == "" && !wifiConnected) {
        if (ethConnected) {
          //updateDisplay("SETUP & ETH ON", "AP: IOT-Device", "Eth: " + ethIPVal.toString());
          updateDisplay("ETH ON", "AP: IOT-Device", "Eth: " + ethIPVal.toString());
        } else {
          updateDisplay("SETUP MODE", "Connect to:", "IOT-Device");
        }
      } else if (ethConnected || wifiConnected) {
        String ipStr = "";
        String label = (operational_status == 1) ? msgIssue : msgResolved;
        if (ethConnected && wifiConnected) {
          ipStr = "E:" + ethIPVal.toString() + " W:" + WiFi.localIP().toString();
        } else if (ethConnected) {
          ipStr = ethIPVal.toString();
        } else {
          ipStr = WiFi.localIP().toString();
        }
        updateDisplay(label, ssid != "" ? ssid : "Ethernet", ipStr);
      } else {
        if (ssid != "") {
          updateDisplay((operational_status == 1) ? msgIssue : msgResolved, ssid, "DISCONNECTED");
        } else {
          updateDisplay("SETUP MODE", "Connect to:", "IOT-Device");
        }
      }
      vTaskDelay(2000 / portTICK_PERIOD_MS);
    }
    vTaskDelay(50 / portTICK_PERIOD_MS);
  }
}

void networkTask(void *pvParameters) {
  for (;;) {
    if (triggerWifiConnect && (millis() - triggerWifiConnectTime > 1500)) {
      triggerWifiConnect = false;
      Serial.println("\n[WIFI] Applying saved credentials and connecting...");
      WiFi.disconnect();
      vTaskDelay(200 / portTICK_PERIOD_MS);
      WiFi.begin(ssid.c_str(), pass.c_str());
    }
    
    dnsServer.processNextRequest();
    server.handleClient();
    if (spiMutex && xSemaphoreTake(spiMutex, portMAX_DELAY) == pdTRUE) {
      ethServer.handleClient();
      xSemaphoreGive(spiMutex);
    }
    SwipeEvent* event;
    if (xQueueReceive(networkQueue, &event, 0) == pdPASS) {
      if (event->type == EVENT_CARD_AUTH) {
        struct tm ti; if (getLocalTime(&ti)) {
          char ds[11], ts[9]; strftime(ds, 11, "%Y-%m-%d", &ti); strftime(ts, 9, "%H:%M:%S", &ti);
          lastSwipeDate = String(ds); lastSwipeTime = String(ts);
        }
        preferences.begin("factory-app", false); preferences.putInt("op_status", event->status); preferences.end();
        lastScannedUID = event->uid; lastSwipeUser = event->user; lastSwipeLine = event->line;
        postToServer(event->uid, event->line, event->user, event->tagType, event->currentStatus, lastSwipeDate, lastSwipeTime, event->status);
      } else if (event->type == EVENT_HEARTBEAT) {
        sendHeartbeat();
      }
      delete event;
    }
    static unsigned long lastNtp = 0;
    static unsigned long lastSync = 0;
    static unsigned long lastHb = 0;
    static unsigned long lastWifiReconnectAttempt = 0;
    static bool initialNtpSynced = false;
    static bool initialHbSent = false;
    static bool initialOfflineSynced = false;
    
    static bool wasWifiConnected = false;
    bool isWifiReqConnected = (WiFi.status() == WL_CONNECTED);
    
    if (!wasWifiConnected && isWifiReqConnected) {
      wasWifiConnected = true;
      Serial.println("\n[WIFI] Wi-Fi Successfully Connected! IP: " + WiFi.localIP().toString());
      if (WiFi.getMode() == WIFI_AP_STA || WiFi.getMode() == WIFI_AP) {
        Serial.println("[WIFI] Running in AP Config mode, but connection succeeded. Mapping normal handlers.");
        startNormalMode();
        if ((millis() - triggerWifiConnectTime) > 15000) {
           Serial.println("[WIFI] Disabling Setup AP (Background connect complete).");
           WiFi.mode(WIFI_STA);
        }
      }
    } else if (wasWifiConnected && !isWifiReqConnected) {
      wasWifiConnected = false;
      Serial.println("\n[WIFI] Warning: Wi-Fi connection lost!");
    }
    
    if (isNetworkConnected()) {
      if (!initialNtpSynced) {
        Serial.println("[TIME] Network connection detected. Performing initial NTP sync...");
        syncTime();
        lastNtp = millis();
        initialNtpSynced = true;
      }
      if (!initialOfflineSynced) {
        bool hasOfflineLogs = false;
        File f = SPIFFS.open(LOG_FILE, "r");
        if (f) {
          if (f.size() > 0) {
            hasOfflineLogs = true;
          }
          f.close();
        }
        if (hasOfflineLogs) {
          Serial.println("[OFFLINE] Connection established! Found offline logs, syncing immediately...");
          syncOfflineLogs();
          lastSync = millis();
        } else {
          Serial.println("[OFFLINE] Connection established! No offline logs to sync.");
        }
        initialOfflineSynced = true;
      }
      if (millis() - lastNtp > NTP_SYNC_INTERVAL) { syncTime(); lastNtp = millis(); }
      if (millis() - lastSync > syncInterval) { syncOfflineLogs(); lastSync = millis(); }
      if (!initialHbSent) {
        Serial.println("[HEARTBEAT] Network connected. Sending initial heartbeat...");
        lastHb = millis();
        initialHbSent = true;
        SwipeEvent* hbEvent = new SwipeEvent(); hbEvent->type = EVENT_HEARTBEAT;
        xQueueSend(networkQueue, &hbEvent, 0);
      }
      if (millis() - lastHb > heartbeatInterval) { 
        lastHb = millis(); 
        SwipeEvent* hbEvent = new SwipeEvent(); hbEvent->type = EVENT_HEARTBEAT;
        xQueueSend(networkQueue, &hbEvent, 0);
      }
    } else {
      serverConnected = false;
      initialNtpSynced = false;
      initialHbSent = false;
      initialOfflineSynced = false;
    }

    if (systemReady && WiFi.status() != WL_CONNECTED && ssid != "") {
      if (lastWifiReconnectAttempt == 0) {
        lastWifiReconnectAttempt = millis();
      } else if (millis() - lastWifiReconnectAttempt > 60000) {
        lastWifiReconnectAttempt = millis();
        Serial.println("\n[WIFI] Status disconnected. Attempting background reconnect to SSID: " + ssid);
        WiFi.disconnect();
        // Keep AP active if we are in fallback AP or AP_STA mode
        if (WiFi.getMode() == WIFI_AP || WiFi.getMode() == WIFI_AP_STA) {
          WiFi.mode(WIFI_AP_STA);
        } else {
          WiFi.mode(WIFI_STA);
        }
        WiFi.begin(ssid.c_str(), pass.c_str());
        WiFi.setSleep(false);
      }
    }

    static unsigned long lastLinkCheck = 0;
    if (millis() - lastLinkCheck > 1000) {
      lastLinkCheck = millis();
      static int prevEthLinkStatus = -1;
      if (spiMutex && xSemaphoreTake(spiMutex, portMAX_DELAY) == pdTRUE) {
        int currentLink = (int)Ethernet.linkStatus();
        if (currentLink != prevEthLinkStatus) {
          if (prevEthLinkStatus != -1) {
            if (currentLink == (int)LinkON) {
              Serial.println("\n[Ethernet] Cable connected! Link is UP.");
              displayReset = true;
              lastScanTime = millis() - 5000;
            } else if (currentLink == (int)LinkOFF) {
              Serial.println("\n[Ethernet] Cable disconnected! Link is DOWN.");
              displayReset = true;
              lastScanTime = millis() - 5000; 
            }
          }
          prevEthLinkStatus = currentLink;
        }
        xSemaphoreGive(spiMutex);
      }
    }

    vTaskDelay(20 / portTICK_PERIOD_MS);
  }
}

void setSystemTimeFromHttpHeader(String dateHeader) {
  int idx = dateHeader.indexOf("Date: ");
  if (idx != -1) {
    dateHeader = dateHeader.substring(idx + 6);
  }
  dateHeader.trim();
  if (dateHeader.length() < 25) return;
  
  int commaIdx = dateHeader.indexOf(',');
  if (commaIdx == -1) return;
  
  String dayStr = dateHeader.substring(commaIdx + 2, commaIdx + 4);
  String monthStr = dateHeader.substring(commaIdx + 5, commaIdx + 8);
  String yearStr = dateHeader.substring(commaIdx + 9, commaIdx + 13);
  String hourStr = dateHeader.substring(commaIdx + 14, commaIdx + 16);
  String minStr = dateHeader.substring(commaIdx + 17, commaIdx + 19);
  String secStr = dateHeader.substring(commaIdx + 20, commaIdx + 22);
  
  int day = dayStr.toInt();
  int year = yearStr.toInt();
  int hour = hourStr.toInt();
  int min = minStr.toInt();
  int sec = secStr.toInt();
  
  int month = 0;
  String months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  for (int i = 0; i < 12; i++) {
    if (monthStr.equals(months[i])) {
      month = i;
      break;
    }
  }
  
  struct tm t_tm;
  t_tm.tm_sec = sec;
  t_tm.tm_min = min;
  t_tm.tm_hour = hour;
  t_tm.tm_mday = day;
  t_tm.tm_mon = month;
  t_tm.tm_year = year - 1900;
  t_tm.tm_isdst = -1;
  
  char *oldTz = getenv("TZ");
  String oldTzStr = oldTz ? String(oldTz) : "";
  setenv("TZ", "GMT0", 1);
  tzset();
  
  time_t utcEpoch = mktime(&t_tm);
  
  if (oldTzStr.length() > 0) {
    setenv("TZ", oldTzStr.c_str(), 1);
  } else {
    unsetenv("TZ");
  }
  tzset();
  
  if (utcEpoch > 0) {
    struct timeval tv = { .tv_sec = utcEpoch, .tv_usec = 0 };
    settimeofday(&tv, NULL);
    Serial.println("[TIME] System clock synced from HTTP Date header: " + dateHeader);
  }
}

bool postRawEthernet(String url, String json, String apiKey, String& responsePayload, String& dateHeader) {
  lastEthernetStatusCode = -1;
  String host = "";
  String path = "/";
  int port = 80;
  bool isHttps = false;
  
  String temp = url;
  if (temp.startsWith("http://")) {
    temp = temp.substring(7);
    port = 80;
  } else if (temp.startsWith("https://")) {
    temp = temp.substring(8);
    port = 443; // Set to 443 for HTTPS!
    isHttps = true;
  }
  
  int slashIdx = temp.indexOf('/');
  if (slashIdx != -1) {
    host = temp.substring(0, slashIdx);
    path = temp.substring(slashIdx);
  } else {
    host = temp;
  }
  
  int colonIdx = host.indexOf(':');
  if (colonIdx != -1) {
    port = host.substring(colonIdx + 1).toInt();
    host = host.substring(0, colonIdx);
  }
  
  Serial.println("\n--- Outgoing Ethernet Request ---");
  Serial.print("Target URL: "); Serial.println(url);
  Serial.print("Method: POST\n");
  Serial.print("Headers:\n");
  Serial.print("  Host: "); Serial.println(host);
  Serial.print("  Content-Type: application/json\n");
  Serial.print("  X-API-KEY: "); Serial.println(apiKey);
  Serial.print("Payload:\n");
  Serial.println(json);
  Serial.println("---------------------------------");
  
  Serial.print("[EthClient] Connecting HTTP to Host: "); Serial.print(host);
  Serial.print(" Port: "); Serial.print(port);
  Serial.print(" Path: "); Serial.println(path);
  
  EthernetClient _ethClientBase;
  Client* _ethClientPtr = &_ethClientBase;
#ifdef USE_BEARSSL
  BearSSLClient _sslClientBase(_ethClientBase, bearssl_TAs, 1);
  if (isHttps) {
    _sslClientBase.setInsecure(BearSSLClient::SNI::Insecure); // Bypass SNI / Cert check completely to isolate TCP vs SSL issue
    _ethClientPtr = &_sslClientBase;
    Serial.println("[EthClient] Using ArduinoBearSSL WRAPPER for HTTPS with Trust Anchors");
  }
#endif
#define ethClient (*_ethClientPtr)

  bool connected = false;
  if (spiMutex && xSemaphoreTake(spiMutex, portMAX_DELAY) == pdTRUE) {
    connected = ethClient.connect(host.c_str(), port);
    xSemaphoreGive(spiMutex);
  } else {
    connected = ethClient.connect(host.c_str(), port);
  }

  if (!connected) {
#ifdef USE_BEARSSL
    if (isHttps) {
      int err = _sslClientBase.errorCode();
      if (err != 0) {
         Serial.print("[EthClient] SSL Handshake Failed! BearSSL Error Code: ");
         Serial.println(err);
         return false;
      }
    }
#endif
    Serial.println("[EthClient] TCP Connection Failed! This usually means:");
    Serial.println("  1) The hostname or domain is invalid or could not be resolved (DNS lookup failure).");
    Serial.println("  2) The target IP address or server is unreachable from this private subnet range.");
    Serial.println("  3) The network firewall/gateway is blocking outbound TCP traffic on port " + String(port) + ".");
    return false;
  }
  
  if (spiMutex && xSemaphoreTake(spiMutex, portMAX_DELAY) == pdTRUE) {
    ethClient.print("POST " + path + " HTTP/1.1\r\n");
    ethClient.print("Host: " + host + "\r\n");
    ethClient.print("Content-Type: application/json\r\n");
    ethClient.print("Content-Length: " + String(json.length()) + "\r\n");
    ethClient.print("X-API-KEY: " + apiKey + "\r\n");
    ethClient.print("Connection: close\r\n\r\n");
    ethClient.print(json);
    xSemaphoreGive(spiMutex);
  } else {
    ethClient.print("POST " + path + " HTTP/1.1\r\n");
    ethClient.print("Host: " + host + "\r\n");
    ethClient.print("Content-Type: application/json\r\n");
    ethClient.print("Content-Length: " + String(json.length()) + "\r\n");
    ethClient.print("X-API-KEY: " + apiKey + "\r\n");
    ethClient.print("Connection: close\r\n\r\n");
    ethClient.print(json);
  }
  
  unsigned long timeout = millis();
  while (true) {
    bool hasData = false;
    if (spiMutex && xSemaphoreTake(spiMutex, portMAX_DELAY) == pdTRUE) {
      hasData = (ethClient.available() > 0);
      xSemaphoreGive(spiMutex);
    } else {
      hasData = (ethClient.available() > 0);
    }
    
    if (hasData) break;
    
    if (millis() - timeout > 5000) {
      Serial.println("[EthClient] Timeout waiting for server response!");
      if (spiMutex && xSemaphoreTake(spiMutex, portMAX_DELAY) == pdTRUE) {
        ethClient.stop();
        xSemaphoreGive(spiMutex);
      } else {
        ethClient.stop();
      }
      return false;
    }
    delay(10);
  }
  
  int statusCode = -1;
  bool headerEnd = false;
  responsePayload = "";
  dateHeader = "";
  unsigned long lastReadTime = millis();
  
  while (true) {
    bool hasData = false;
    bool isConnected = false;
    if (spiMutex && xSemaphoreTake(spiMutex, portMAX_DELAY) == pdTRUE) {
      hasData = (ethClient.available() > 0);
      isConnected = ethClient.connected();
      xSemaphoreGive(spiMutex);
    } else {
      hasData = (ethClient.available() > 0);
      isConnected = ethClient.connected();
    }
    
    if (hasData) {
      lastReadTime = millis(); // Reset idle timeout since we received data
    }
    
    if (!hasData && !isConnected) {
      break;
    }

    if (!hasData && isConnected) {
      if (millis() - lastReadTime > 5000) {
        Serial.println("[EthClient] Idle timeout waiting for response payload!");
        break;
      }
      delay(5);
      continue;
    }
    
    if (headerEnd) {
      if (spiMutex && xSemaphoreTake(spiMutex, portMAX_DELAY) == pdTRUE) {
        while (ethClient.available()) {
          char c = ethClient.read();
          responsePayload += c;
        }
        xSemaphoreGive(spiMutex);
      } else {
        while (ethClient.available()) {
          char c = ethClient.read();
          responsePayload += c;
        }
      }
    } else {
      String line = "";
      if (spiMutex && xSemaphoreTake(spiMutex, portMAX_DELAY) == pdTRUE) {
        line = ethClient.readStringUntil('\n');
        xSemaphoreGive(spiMutex);
      } else {
        line = ethClient.readStringUntil('\n');
      }
      line.trim();
      if (line.length() == 0) {
        headerEnd = true;
      } else {
        if (line.startsWith("HTTP/1.1 ")) {
          statusCode = line.substring(9, 12).toInt();
          lastEthernetStatusCode = statusCode;
        } else if (line.startsWith("Date: ") || line.startsWith("date: ")) {
          dateHeader = line.substring(6);
        }
      }
    }
  }
  
  if (spiMutex && xSemaphoreTake(spiMutex, portMAX_DELAY) == pdTRUE) {
    ethClient.stop();
    xSemaphoreGive(spiMutex);
  } else {
    ethClient.stop();
  }
  
  Serial.print("[EthClient] HTTP Status Code: "); Serial.println(statusCode);
  if (statusCode == 301 || statusCode == 302 || statusCode == 307 || statusCode == 308) {
    Serial.println("\n[WARNING] HTTP 301/302 Redirect (HTTPS Enforcement) Detected!");
    Serial.println("Your web hosting provider or server config is redirecting the HTTP request to HTTPS.");
    Serial.println("Standard 'EthernetClient' does not support encryption/SSL natively.");
    Serial.println(">>> TO FIX ETHERNET NOT SENDING DATA:");
    Serial.println("   - Disable \"Always Use HTTPS\" or Page Rules forcing HTTPS in Cloudflare for your domain.");
    Serial.println("   - Update your server's .htaccess to accept HTTP port 80 requests for /iot/ routes.\n");
  } else if (statusCode == 404) {
    Serial.println("[EthClient] ERROR: HTTP 404 Not Found! Please double-check if your server URL path or domain in settings is correct.");
  } else if (statusCode == 401 || statusCode == 403) {
    Serial.println("[EthClient] ERROR: HTTP " + String(statusCode) + " Unauthorized/Forbidden! Your server API Key (X-API-KEY) probably does not match.");
  }
#ifdef USE_BEARSSL
#undef ethClient
#endif
  return (statusCode >= 200 && statusCode < 300);
}

String testNetworkDiagnostics() {
  String result = "";
  
  bool wifiConnected = (WiFi.status() == WL_CONNECTED);
  bool ethConnected = (Ethernet.localIP() != IPAddress(0, 0, 0, 0) && Ethernet.localIP() != IPAddress(255, 255, 255, 255));
  
  result += "=== NETWORK DIAGNOSTICS ===\n";
  result += "WiFi Status: " + String(wifiConnected ? "CONNECTED" : "DISCONNECTED") + "\n";
  if (wifiConnected) {
    result += "  - WiFi IP: " + WiFi.localIP().toString() + "\n";
    result += "  - WiFi SSID: " + WiFi.SSID() + "\n";
  }
  
  result += "Ethernet Status: " + String(ethConnected ? "CONNECTED" : "DISCONNECTED") + "\n";
  if (ethConnected) {
    result += "  - Ethernet IP: " + Ethernet.localIP().toString() + "\n";
    result += "  - Gateway: " + Ethernet.gatewayIP().toString() + "\n";
    result += "  - Subnet: " + Ethernet.subnetMask().toString() + "\n";
    result += "  - DNS Server: " + Ethernet.dnsServerIP().toString() + "\n";
    
    String host = "";
    String temp = serverUrl;
    if (temp.startsWith("http://")) temp = temp.substring(7);
    else if (temp.startsWith("https://")) temp = temp.substring(8);
    int slashIdx = temp.indexOf('/');
    if (slashIdx != -1) host = temp.substring(0, slashIdx);
    else host = temp;
    int colonIdx = host.indexOf(':');
    if (colonIdx != -1) host = host.substring(0, colonIdx);
    
    result += "[DNS Check] Resolving server: " + host + " ...\n";
    
    EthernetClient testClient;
    unsigned long startConn = millis();
    result += "[TCP Check] Connecting to " + host + " on port 80...\n";
    if (testClient.connect(host.c_str(), 80)) {
      result += "  - TCP Connection SUCCESSFUL (connected in " + String(millis() - startConn) + "ms)\n";
      
      testClient.print("HEAD / HTTP/1.1\r\n");
      testClient.print("Host: " + host + "\r\n");
      testClient.print("Connection: close\r\n\r\n");
      
      unsigned long wStart = millis();
      while (testClient.available() == 0 && millis() - wStart < 3000) {
        delay(10);
      }
      
      if (testClient.available()) {
        String line = testClient.readStringUntil('\n');
        line.trim();
        result += "  - Server Response: " + line + "\n";
        
        String dateHeader = "";
        while (testClient.available()) {
          String hLine = testClient.readStringUntil('\n');
          hLine.trim();
          if (hLine.startsWith("Date: ") || hLine.startsWith("date: ")) {
            dateHeader = hLine.substring(6);
            break;
          }
        }
        if (dateHeader.length() > 0) {
          result += "  - Server Time (UTC): " + dateHeader + "\n";
          setSystemTimeFromHttpHeader(dateHeader);
          result += "  - SYSTEM CLOCK SYNCED SUCCESSFULLY!\n";
        }
      } else {
        result += "  - Server did not send a response in 3s (But TCP connection was open).\n";
      }
      testClient.stop();
    } else {
      result += "  - TCP Connection FAILED! (DNS failure or Server unreachable over port 80)\n";
      result += "  - Advice: Verify Ethernet DNS settings and check if Ethernet router has active Internet connection.\n";
    }
  } else {
    result += "Ethernet IP is not assigned or is invalid. Please check physical link of W5500 and router DHCP.\n";
  }
  
  return result;
}

bool postToServer(String uid, String cardLine, String cardUser, String tagType, String currentStatus, String eventDate, String eventTime, int eventStatus) {
  int opStatus = (eventStatus >= 0) ? eventStatus : operational_status;
  Serial.print("Posting to URL: "); Serial.println(serverUrl);
  if (!isNetworkConnected()) {
    Serial.println("Network Disconnected. Saving to Offline Log.");
    saveOfflineLog(uid, cardLine, cardUser, eventDate, eventTime, opStatus, tagType, "offline");
    serverConnected = false;
    return false;
  }

  bool wifiConnected = (WiFi.status() == WL_CONNECTED);
  
  if (wifiConnected) {
    WiFiClient clientPlain;
    WiFiClientSecure clientSecure;
    clientSecure.setInsecure();
    
    HTTPClient https; https.setTimeout(5000);
    bool beginSuccess = false;
    
    if (serverUrl.startsWith("https")) {
      beginSuccess = https.begin(clientSecure, serverUrl);
    } else {
      beginSuccess = https.begin(clientPlain, serverUrl);
    }
    
    if (beginSuccess) {
      https.setFollowRedirects(HTTPC_DISABLE_FOLLOW_REDIRECTS);
      https.setUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
      https.addHeader("Content-Type", "application/json");
      https.addHeader("X-API-KEY", apiKey);
      
      const char* headerKeys[] = {"Date"};
      https.collectHeaders(headerKeys, 1);
      
      String json = "{\"tag_type\":\"" + tagType + "\",\"device_uid\":\"" + deviceId + "\",\"line_code\":\"" + lineCode + "\",\"date\":\"" + eventDate + "\",\"time\":\"" + eventTime + "\",\"device_type\":\"" + deviceType + "\",\"current_status\":\"" + currentStatus + "\",\"card_user\":\"" + cardUser + "\",\"card_uid\":\"" + uid + "\",\"operational_status\":\"" + String(opStatus) + "\",\"interface\":\"WiFi\"}";
      lastJSON = json;
      
      Serial.println("\n--- Outgoing WiFi Request ---");
      Serial.print("Target URL: "); Serial.println(serverUrl);
      Serial.print("Method: POST\n");
      Serial.print("Headers:\n");
      Serial.print("  Content-Type: application/json\n");
      Serial.print("  X-API-KEY: "); Serial.println(apiKey);
      Serial.print("Payload:\n");
      Serial.println(json);
      Serial.println("-----------------------------");

      int code = https.POST(json); 
      Serial.print("POST Response Code: "); Serial.println(code);
      String payload = https.getString();
      if(payload.length() > 0) { Serial.print("Response Payload: "); Serial.println(payload.substring(0, 150)); }
      
      if (https.hasHeader("Date")) {
        setSystemTimeFromHttpHeader(https.header("Date"));
      }
      
      serverConnected = (code >= 200 && code < 300) && (payload.indexOf("<html") == -1) && (payload.indexOf("<HTML") == -1);
      https.end();
    } else {
      Serial.println("HTTP Begin Failed (Unreachable or Invalid URL)");
      serverConnected = false;
    }
  } else {
    String payload = "";
    String dateHeader = "";
    
    String json = "{";
    json += "\"tag_type\":\"" + tagType + "\",";
    json += "\"device_uid\":\"" + deviceId + "\",";
    json += "\"line_code\":\"" + lineCode + "\",";
    json += "\"date\":\"" + eventDate + "\",";
    json += "\"time\":\"" + eventTime + "\",";
    json += "\"device_type\":\"" + deviceType + "\",";
    json += "\"current_status\":\"" + currentStatus + "\",";
    json += "\"card_user\":\"" + cardUser + "\",";
    json += "\"card_uid\":\"" + uid + "\",";
    json += "\"operational_status\":\"" + String(opStatus) + "\",";
    json += "\"interface\":\"Ethernet\"";
    json += "}";
    lastJSON = json;
    
    serverConnected = postRawEthernet(serverUrl, json, apiKey, payload, dateHeader);
    if (payload.length() > 0) { Serial.print("[Eth] Response Payload: "); Serial.println(payload.substring(0, 150)); }
    
    if (dateHeader.length() > 0) {
      setSystemTimeFromHttpHeader(dateHeader);
    }
  }

  if (!serverConnected) {
    Serial.println("POST Failed. Saving to Offline Log.");
    saveOfflineLog(uid, cardLine, cardUser, eventDate, eventTime, opStatus, tagType, "offline");
  } else {
    Serial.println("POST Successful");
  }
  return serverConnected;
}

// void handleHeartbeatLedIndicator(int responseCode) removed

void sendHeartbeat() {
  if (!isNetworkConnected()) { 
    Serial.println("Heartbeat skipped: Network disconnected"); 
    serverConnected = false; 
    return; 
  }
  
  String hDate = "0000-00-00";
  String hTime = "00:00:00";
  struct tm ti;
  if (getLocalTime(&ti)) {
    char ds[11], ts[9];
    strftime(ds, 11, "%Y-%m-%d", &ti);
    strftime(ts, 9, "%H:%M:%S", &ti);
    hDate = String(ds);
    hTime = String(ts);
  }

  Serial.print("Sending Heartbeat to: "); Serial.println(heartbeatUrl);
  bool wifiConnected = (WiFi.status() == WL_CONNECTED);
  
  if (wifiConnected) {
    WiFiClient clientPlain;
    WiFiClientSecure clientSecure;
    clientSecure.setInsecure();
    
    HTTPClient https; https.setTimeout(5000);
    int code = -1;
    bool beginSuccess = false;
    if (heartbeatUrl.startsWith("https")) {
      beginSuccess = https.begin(clientSecure, heartbeatUrl);
    } else {
      beginSuccess = https.begin(clientPlain, heartbeatUrl);
    }
    
    if (beginSuccess) {
      https.setFollowRedirects(HTTPC_DISABLE_FOLLOW_REDIRECTS);
      https.setUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
      https.addHeader("Content-Type", "application/json");
      https.addHeader("X-API-KEY", apiKey);
      
      const char* headerKeys[] = {"Date"};
      https.collectHeaders(headerKeys, 1);
      
      String json = "{";
      json += "\"device_uid\":\"" + deviceId + "\",";
      json += "\"type\":\"heartbeat\",";
      json += "\"uptime\":" + String(millis() / 1000) + ",";
      json += "\"line_code\":\"" + lineCode + "\",";
      json += "\"device_type\":\"" + deviceType + "\",";
      json += "\"date\":\"" + hDate + "\",";
      json += "\"time\":\"" + hTime + "\",";
      json += "\"interface\":\"WiFi\"";
      json += "}";
      lastHbJSON = json;
      
      Serial.println("\n--- Outgoing WiFi Heartbeat ---");
      Serial.print("Target URL: "); Serial.println(heartbeatUrl);
      Serial.print("Method: POST\n");
      Serial.print("Headers:\n");
      Serial.print("  Content-Type: application/json\n");
      Serial.print("  X-API-KEY: "); Serial.println(apiKey);
      Serial.print("Payload:\n");
      Serial.println(json);
      Serial.println("-------------------------------");
      
      code = https.POST(json); 
      Serial.print("HB Response Code: "); Serial.println(code);
      String payload = https.getString();
      if(payload.length() > 0) { Serial.print("HB Payload: "); Serial.println(payload.substring(0, 150)); }
      
      if (https.hasHeader("Date")) {
        setSystemTimeFromHttpHeader(https.header("Date"));
      }
      
      serverConnected = (code >= 200 && code < 300) && (payload.indexOf("<html") == -1) && (payload.indexOf("<HTML") == -1);
      https.end();
    } else { Serial.println("Heartbeat Begin Failed"); serverConnected = false; }
  } else {
    String payload = "";
    String dateHeader = "";
    
    String json = "{";
    json += "\"device_uid\":\"" + deviceId + "\",";
    json += "\"type\":\"heartbeat\",";
    json += "\"uptime\":" + String(millis() / 1000) + ",";
    json += "\"line_code\":\"" + lineCode + "\",";
    json += "\"device_type\":\"" + deviceType + "\",";
    json += "\"date\":\"" + hDate + "\",";
    json += "\"time\":\"" + hTime + "\",";
    json += "\"interface\":\"Ethernet\"";
    json += "}";
    lastHbJSON = json;
    
    serverConnected = postRawEthernet(heartbeatUrl, json, apiKey, payload, dateHeader);
    if (payload.length() > 0) { Serial.print("[Eth HB] Response Payload: "); Serial.println(payload.substring(0, 150)); }
    
    if (dateHeader.length() > 0) {
      setSystemTimeFromHttpHeader(dateHeader);
    }
  }
}

void saveOfflineLog(String uid, String line, String user, String date, String time, int status, String tagType, String currentStatus) {
  File f = SPIFFS.open(LOG_FILE, "a");
  if (f) { f.println(uid + "," + line + "," + user + "," + date + "," + time + "," + String(status) + "," + tagType + "," + currentStatus); f.close(); }
}

void syncOfflineLogs() {
  if (!isNetworkConnected() || isSyncing) return;
  File f = SPIFFS.open(LOG_FILE, "r"); if (!f || f.size() == 0) { if(f) f.close(); return; }
  Serial.println("Syncing Offline Logs...");
  isSyncing = true; String content = f.readString(); f.close(); SPIFFS.remove(LOG_FILE);
  int start = 0; int end = content.indexOf('\n'); 
  int success = 0; int total = 0;
  while (end != -1) {
    String row = content.substring(start, end); row.trim();
    if(row.length() > 0) {
      int c1 = row.indexOf(','); int c2 = row.indexOf(',', c1+1); int c3 = row.indexOf(',', c2+1);
      int c4 = row.indexOf(',', c3+1); int c5 = row.indexOf(',', c4+1); int c6 = row.indexOf(',', c5+1);
      int c7 = row.indexOf(',', c6+1);
      if(c7 != -1) {
         String uid = row.substring(0, c1); String line = row.substring(c1+1, c2); String user = row.substring(c2+1, c3);
         String d = row.substring(c3+1, c4); String t = row.substring(c4+1, c5); String s = row.substring(c5+1, c6);
         String tt = row.substring(c6+1, c7); String cs = row.substring(c7+1);
         if (postToServer(uid, line, user, tt, cs, d, t, s.toInt())) success++;
         total++;
      }
    }
    start = end + 1; end = content.indexOf('\n', start);
  }
  isSyncing = false;
  Serial.print("Sync Finished. Sent: "); Serial.print(success); Serial.print("/"); Serial.println(total);
}

// Overload for web UI to get status message
String syncOfflineLogsWeb() {
  if (!isNetworkConnected()) return "Error: Network Disconnected";
  if (isSyncing) return "Error: Sync already in progress";
  File f = SPIFFS.open(LOG_FILE, "r"); if (!f || f.size() == 0) { if(f) f.close(); return "No logs to sync"; }
  
  Serial.println("Manual Sync Initiated...");
  isSyncing = true; String content = f.readString(); f.close(); SPIFFS.remove(LOG_FILE);
  int start = 0; int end = content.indexOf('\n'); 
  int success = 0; int total = 0;
  while (end != -1) {
    String row = content.substring(start, end); row.trim();
    if(row.length() > 0) {
      int c1 = row.indexOf(','); int c2 = row.indexOf(',', c1+1); int c3 = row.indexOf(',', c2+1);
      int c4 = row.indexOf(',', c3+1); int c5 = row.indexOf(',', c4+1); int c6 = row.indexOf(',', c5+1);
      int c7 = row.indexOf(',', c6+1);
      if(c7 != -1) {
         String uid = row.substring(0, c1); String line = row.substring(c1+1, c2); String user = row.substring(c2+1, c3);
         String d = row.substring(c3+1, c4); String t = row.substring(c4+1, c5); String s = row.substring(c5+1, c6);
         String tt = row.substring(c6+1, c7); String cs = row.substring(c7+1);
         if (postToServer(uid, line, user, tt, cs, d, t, s.toInt())) success++;
         total++;
      }
    }
    start = end + 1; end = content.indexOf('\n', start);
  }
  isSyncing = false;
  
  if (total == 0) return "No valid logs found to sync.";
  if (success == total) return "Sync Success: All " + String(total) + " logs sent successfully!";
  if (success == 0) return "Sync Failed: Server unreachable or rejected credentials (0/" + String(total) + " sent).";
  return "Sync Partial: " + String(success) + "/" + String(total) + " items sent (Check connectivity for others).";
}

void updateHardwareState() {
  digitalWrite(STATUS_LED, status_led_state);
  digitalWrite(STATUS_RELAY, status_relay_state);
  /// new IO for 3 relay ///
  digitalWrite(THIRD_RELAY, third_relay_state);
  digitalWrite(SECOND_RELAY, second_relay_state);
  digitalWrite(FIRST_RELAY, first_relay_state);
}

void updateDisplay(String title, String l1, String l2) {
  // OLED removed for 2nd project
}

bool isAuthorized(String uid) { return authorizedCards.indexOf(uid) != -1; }
void addAuthorizedCard(String uid) { if (!isAuthorized(uid)) { authorizedCards += (authorizedCards.length() ? "," : "") + uid; preferences.begin("factory-app", false); preferences.putString("auth_cards", authorizedCards); preferences.end(); } }
void syncTime() { configTime(GMT_OFFSET_SEC, DAYLIGHT_OFFSET_SEC, "pool.ntp.org"); }

String readCardData() {
  return "N/A | N/A";
}

bool writeCardData(String line, String name) {
  return false;
}

void startConfigMode() {
  configPortalActive = true;
  WiFi.persistent(false);
  WiFi.disconnect(true);
  delay(100);
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  WiFi.softAP("IOT-Device");
  dnsServer.start(DNS_PORT, "*", apIP);
  server.on("/", handleRootConfig);
  server.on("/save", HTTP_POST, handleSave);
  server.on("/save_status", HTTP_GET, handleSaveStatus);
  server.onNotFound([]() {
    server.sendHeader("Location", "http://192.168.4.1/", true);
    server.send(302, "text/plain", "");
  });
  server.begin();
}

template <typename ServerType>
void registerNormalHandlers(ServerType& s) {
  s.onNotFound([&s]() {
    s.send(404, "text/plain", "Not Found");
  });
  auto authorized = [&s]() -> bool { if (!s.authenticate(webUser.c_str(), webPass.c_str())) { s.requestAuthentication(); return false; } lastWebActivity = millis(); return true; };
  s.on("/", [authorized, &s]() { if (authorized()) handleRootNormalT(s); });
  s.on("/status", [authorized, &s]() {
    if(!authorized()) return;
    int count = 0; if (authorizedCards.length() > 0) { count = 1; for (int i = 0; i < authorizedCards.length(); i++) if (authorizedCards[i] == ',') count++; }
    int offCount = 0; File f = SPIFFS.open(LOG_FILE, "r"); if(f){ while(f.available()) if(f.read() == '\n') offCount++; f.close(); }
    String json = "{\"device_id\":\"" + deviceId + "\",\"device_type\":\"" + deviceType + "\",\"line_code\":\"" + lineCode + "\",\"op_status\":" + String(operational_status) + ",\"last_json\":" + lastJSON + ",\"last_hb\":" + lastHbJSON + ",\"count\":" + String(count) + ",\"offline_count\":" + String(offCount) + ",\"uid\":\"" + lastScannedUID + "\",\"last_user\":\"" + lastSwipeUser + "\",\"last_line\":\"" + lastSwipeLine + "\",\"time\":\"" + lastSwipeTime + "\",\"date\":\"" + lastSwipeDate + "\",\"server_connected\":\"" + String(serverConnected ? "1" : "0") + "\",\"auth\":\"" + authorizedCards + "\",\"learn\":\"" + String(learnMode ? "1" : "0") + "\",\"write\":\"" + String(writeMode ? "1" : "0") + "\",\"read\":\"" + String(readMode ? "1" : "0") + "\",\"write_status\":\"" + lastWriteStatus + "\",\"read_info\":\"" + lastReadInfo + "\",\"mgmt\":\"" + String(cardManagementMode ? "1" : "0") + "\",\"factory_name\":\"" + factoryName + "\",\"setup_date\":\"" + setupDate + "\",\"msg_issue\":\"" + msgIssue + "\",\"msg_resolved\":\"" + msgResolved + "\",\"hb_url\":\"" + heartbeatUrl + "\",\"hb_interval\":" + String(heartbeatInterval / 1000) + ",\"sync_interval\":" + String(syncInterval / 1000) + ",\"ota_url\":\"" + otaAutoUrl + "\",\"ver_url\":\"" + versionCheckUrl + "\",\"ota_auto\":\"" + String(autoUpdateEnabled ? "1" : "0") + "\",\"version\":\"" + CURRENT_VERSION + "\",\"ota_status\":\"" + lastOtaStatus + "\"}";
    s.send(200, "application/json", json);
  });
  s.on("/save_device", [authorized, &s]() {
    if(!authorized()) return;
    deviceId = s.arg("id"); deviceType = s.arg("type"); factoryName = s.arg("factory"); setupDate = s.arg("date"); lineCode = s.arg("line");
    Serial.println("Web Action: Saving Device Settings");
    preferences.begin("factory-app", false); preferences.putString("device_id", deviceId); preferences.putString("device_type", deviceType); preferences.putString("factory_name", factoryName); preferences.putString("setup_date", setupDate); preferences.putString("line_code", lineCode); preferences.end();
    s.send(200, "text/plain", "Saved");
  });
  s.on("/save_ethernet", [authorized, &s]() {
    if(!authorized()) return;
    ethIpStr = s.arg("ip"); ethGatewayStr = s.arg("gateway"); ethSubnetStr = s.arg("subnet"); ethDnsStr = s.arg("dns");
    Serial.println("Web Action: Saving Ethernet Settings");
    preferences.begin("factory-app", false);
    preferences.putString("eth_ip", ethIpStr);
    preferences.putString("eth_gateway", ethGatewayStr);
    preferences.putString("eth_subnet", ethSubnetStr);
    preferences.putString("eth_dns", ethDnsStr);
    preferences.end();
    s.send(200, "text/plain", "Ethernet Settings Saved! (Restart device to apply changes)");
  });
  s.on("/save_messages", [authorized, &s]() {
    if(!authorized()) return;
    msgIssue = s.arg("issue"); msgResolved = s.arg("resolved");
    Serial.println("Web Action: Saving Display Messages");
    preferences.begin("factory-app", false); preferences.putString("msg_issue", msgIssue); preferences.putString("msg_resolved", msgResolved); preferences.end();
    s.send(200, "text/plain", "Saved");
  });
  s.on("/save_heartbeat", [authorized, &s]() {
     if(!authorized()) return;
     heartbeatUrl = s.arg("url");
     heartbeatUrl.trim();
     heartbeatInterval = s.arg("interval").toInt() * 1000;
     Serial.print("Web Action: Saving Heartbeat URL: "); Serial.println(heartbeatUrl);
     Serial.print("Interval: "); Serial.println(heartbeatInterval);
     
     preferences.begin("factory-app", false); 
     preferences.putString("hb_url", heartbeatUrl); 
     preferences.putULong("hb_interval", heartbeatInterval); 
     preferences.end();
     
     // Trigger immediate check
     SwipeEvent* hbEvent = new SwipeEvent(); hbEvent->type = EVENT_HEARTBEAT; xQueueSend(networkQueue, &hbEvent, 0);
     s.send(200, "text/plain", "Saved and Checking Connection...");
  });
  s.on("/save_sync", [authorized, &s]() {
     if(!authorized()) return;
     syncInterval = s.arg("interval").toInt() * 1000;
     preferences.begin("factory-app", false); preferences.putULong("sync_interval", syncInterval); preferences.end();
     s.send(200, "text/plain", "Saved");
  });
  s.on("/manual_sync", [authorized, &s]() {
     if(!authorized()) return;
     String res = syncOfflineLogsWeb();
     s.send(200, "text/plain", res);
  });
  s.on("/save_security", [authorized, &s](){
     if(!authorized()) return;
     String oldServer = serverUrl;
     serverUrl = s.arg("url"); apiKey = s.arg("key"); webUser = s.arg("user"); webPass = s.arg("pass");
     serverUrl.trim(); apiKey.trim(); webUser.trim(); webPass.trim();
     
     Serial.print("Web Action: Saving Security Settings. New Server URL: "); Serial.println(serverUrl);
     
     preferences.begin("factory-app", false); 
     preferences.putString("server_url", serverUrl); 
     preferences.putString("api_key", apiKey); 
     preferences.putString("web_user", webUser); 
     preferences.putString("web_pass", webPass); 
     
     // If heartbeat was linked to server URL, keep it linked
     if (heartbeatUrl == oldServer || heartbeatUrl == "") {
        heartbeatUrl = serverUrl;
        preferences.putString("hb_url", heartbeatUrl);
        Serial.println("Note: Heartbeat URL also updated to match Server URL");
     }
     preferences.end();
     
     SwipeEvent* hbEvent = new SwipeEvent(); hbEvent->type = EVENT_HEARTBEAT; xQueueSend(networkQueue, &hbEvent, 0);
     s.send(200, "text/plain", "Saved and Checking Connection...");
  });
  s.on("/learn", [authorized, &s]() { if(!authorized()) return; Serial.println("Web Action: Learning Mode Enabled"); learnMode = true; s.send(200, "text/plain", "Mode Enabled"); });
  s.on("/clear_auth", [authorized, &s]() { if(!authorized()) return; Serial.println("Web Action: Authorized Cards Cleared"); authorizedCards = ""; preferences.begin("factory-app", false); preferences.putString("auth_cards", ""); preferences.end(); s.send(200, "text/plain", "Cleared"); });
  s.on("/set_write", [authorized, &s]() { if(!authorized()) return; writeLine = s.arg("line"); writeName = s.arg("name"); Serial.println("Web Action: Write Mode Prepared"); writeMode = true; cardManagementMode = true; s.send(200, "text/plain", "Write Ready"); });
  s.on("/set_read", [authorized, &s]() { if(!authorized()) return; Serial.println("Web Action: Read Mode Prepared"); readMode = true; cardManagementMode = true; s.send(200, "text/plain", "Read Ready"); });
  s.on("/set_mgmt", [authorized, &s]() { if(!authorized()) return; Serial.print("Web Action: Card Management Mode = "); Serial.println(s.arg("mode")); cardManagementMode = (s.arg("mode") == "1"); s.send(200, "text/plain", "Mode Set"); });
  s.on("/sync_time", [authorized, &s]() { if(!authorized()) return; Serial.println("Web Action: Syncing Time"); syncTime(); s.send(200, "text/plain", "Synced"); });
  s.on("/save_datetime", [authorized, &s]() {
    if(!authorized()) return;
    int year = s.arg("year").toInt();
    int month = s.arg("month").toInt();
    int day = s.arg("day").toInt();
    int hour = s.arg("hour").toInt();
    int min = s.arg("min").toInt();
    int sec = s.arg("sec").toInt();
    
    if (year >= 2000 && year <= 2100 && month >= 1 && month <= 12 && day >= 1 && day <= 31 &&
        hour >= 0 && hour <= 23 && min >= 0 && min <= 59 && sec >= 0 && sec <= 59) {
        
        struct tm t_tm;
        t_tm.tm_sec = sec;
        t_tm.tm_min = min;
        t_tm.tm_hour = hour;
        t_tm.tm_mday = day;
        t_tm.tm_mon = month - 1;
        t_tm.tm_year = year - 1900;
        t_tm.tm_isdst = -1;
        
        time_t epoch = mktime(&t_tm);
        if (epoch > 0) {
            struct timeval tv = { .tv_sec = epoch, .tv_usec = 0 };
            settimeofday(&tv, NULL);
            Serial.print("Manual RTC sync. Set time to: ");
            Serial.printf("%04d-%02d-%02d %02d:%02d:%02d\n", year, month, day, hour, min, sec);
            s.send(200, "text/plain", "Time updated successfully");
        } else {
            s.send(400, "text/plain", "Invalid time epoch conversion failed");
        }
    } else {
        s.send(400, "text/plain", "Invalid datetime field values");
    }
  });
  s.on("/test_internet", [authorized, &s]() {
    if(!authorized()) return;
    Serial.println("Web Action: Testing Internet Connectivity...");
    String res = testNetworkDiagnostics();
    res += "\n\n=== RECENT SERIAL LOGS ===\n";
    res += webLogBuffer;
    s.send(200, "text/plain", res);
  });
  s.on("/save_ota", [authorized, &s]() {
    if (!authorized()) return;
    otaAutoUrl = s.arg("ota_url");
    versionCheckUrl = s.arg("ver_url");
    otaAutoUrl.trim(); versionCheckUrl.trim();
    autoUpdateEnabled = (s.arg("auto") == "1");
    preferences.begin("factory-app", false);
    preferences.putString("ota_url", otaAutoUrl);
    preferences.putString("ver_url", versionCheckUrl);
    preferences.putBool("ota_auto", autoUpdateEnabled);
    preferences.end();
    s.send(200, "text/plain", "OTA Settings Saved");
  });
  s.on("/force_update", [authorized, &s]() {
    if (!authorized()) return;
    String res = checkForUpdates();
    s.send(200, "text/plain", res);
  });
  s.on("/reset_wifi", [authorized, &s]() {
    if(!authorized()) return;
    Serial.println("Web Action: WiFi Reset Initiated");
    preferences.begin("factory-app", false);
    preferences.remove("ssid");
    preferences.remove("pass");
    preferences.end();
    s.send(200, "text/plain", "WiFi Reset. Restarting to AP Mode...");
    delay(1000);
    ESP.restart();
  });
  s.on("/factory_reset", [authorized, &s]() {
    if(!authorized()) return;
    Serial.println("Web Action: Factory Reset Initiated");
    
    // Clear Preferences
    preferences.begin("factory-app", false);
    preferences.clear();
    // Set default ethernet settings in memory on factory reset
    preferences.putString("eth_ip", "192.168.0.177");
    preferences.putString("eth_gateway", "192.168.0.1");
    preferences.putString("eth_subnet", "255.255.255.0");
    preferences.putString("eth_dns", "8.8.8.8");
    preferences.end();
    Serial.println("Preferences Cleared & Defaults Saved.");

    // Format SPIFFS (Wipes all files including logs)
    Serial.println("Formatting SPIFFS...");
    SPIFFS.format();
    Serial.println("SPIFFS Formatted.");

    s.send(200, "text/plain", "Factory Reset Successful. ALL memory cleared. Restarting...");
    delay(2000);
    ESP.restart();
  });
  s.on("/restart", [authorized, &s]() { if(!authorized()) return; Serial.println("Web Action: Device Restart Initiated"); s.send(200, "text/plain", "Restarting"); delay(1000); ESP.restart(); });
  s.on("/logout", [&s]() { lastWebActivity = 0; s.send(401, "text/plain", "Logged Out"); });
  s.on("/get_serial_log", [authorized, &s]() {
    if(!authorized()) return;
    s.send(200, "text/plain", webLogBuffer);
  });
  s.on("/get_logs", [authorized, &s]() {
    if(!authorized()) return;
    File f = SPIFFS.open(LOG_FILE, "r"); if(!f) { s.send(200, "application/json", "[]"); return; }
    String json = "["; bool first = true;
    while(f.available()) {
      String l = f.readStringUntil('\n'); if(l.length() == 0) continue;
      if(!first) json += ","; first = false;
      int c1 = l.indexOf(','); int c2 = l.indexOf(',', c1+1); int c3 = l.indexOf(',', c2+1); int c4 = l.indexOf(',', c3+1); int c5 = l.indexOf(',', c4+1);
      if(c5 != -1) json += "{\"uid\":\"" + l.substring(0, c1) + "\",\"line\":\"" + l.substring(c1+1, c2) + "\",\"user\":\"" + l.substring(c2+1, c3) + "\",\"date\":\"" + l.substring(c3+1, c4) + "\",\"time\":\"" + l.substring(c4+1, c5) + "\",\"status\":" + l.substring(c5+1) + "}";
    }
    json += "]"; f.close(); s.send(200, "application/json", json);
  });
  s.on("/clear_logs", [authorized, &s]() { if(!authorized()) return; SPIFFS.remove(LOG_FILE); s.send(200, "text/plain", "Cleared"); });
  s.begin();
}

void startNormalMode() {
  configPortalActive = false;
  registerNormalHandlers(server);
}

void handleRootConfig() {
  if (!configPortalActive) {
    if (!server.authenticate(webUser.c_str(), webPass.c_str())) { return server.requestAuthentication(); }
    lastWebActivity = millis();
    handleRootNormalT(server);
    return;
  }
  
  String html = "<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1'>";
  html += "<style>";
  html += "body { background: #0f172a; color: #f8fafc; font-family: -apple-system, system-ui, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; }";
  html += ".card { background: #1e293b; padding: 30px; border-radius: 16px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3); width: 100%; max-width: 360px; box-sizing: border-box; }";
  html += "h2 { font-size: 24px; font-weight: 700; margin: 0 0 10px 0; color: #ffffff; text-align: center; }";
  html += "p { font-size: 14px; color: #94a3b8; margin: 0 0 20px 0; text-align: center; }";
  html += ".input-field { width: 100%; padding: 12px; background: #334155; border: 1px solid #475569; border-radius: 8px; color: #ffffff; font-size: 16px; margin-bottom: 16px; box-sizing: border-box; }";
  html += ".input-field::placeholder { color: #94a3b8; }";
  html += ".input-field:focus { outline: none; border-color: #3b82f6; box-shadow: 0 0 0 2px rgba(59,130,246,0.3); }";
  html += ".submit-btn { width: 100%; padding: 12px; background: #2563eb; color: #ffffff; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: background 0.2s; box-sizing: border-box; }";
  html += ".submit-btn:hover { background: #1d4ed8; }";
  html += "</style>";
  html += "</head><body>";
  html += "<div class='card'>";
  html += "<h2>WiFi Setup</h2>";
  html += "<p>Configure Wi-Fi details for your IOT Device</p>";
  html += "<form action='/save' method='POST'>";
  html += "<input name='ssid' placeholder='WiFi SSID' class='input-field' required>";
  html += "<input name='pass' type='password' placeholder='Password' class='input-field'>";
  html += "<button type='submit' class='submit-btn'>Save & Connect</button>";
  html += "</form></div></body></html>";
  server.send(200, "text/html", html);
}


void handleSave() {
  String s = server.arg("ssid");
  String p = server.arg("pass");
  
  if (s == "") {
    // Basic fallback if old form submitted or missing
    s = server.arg("ssid_custom");
    if (s == "") s = server.arg("ssid_select");
  }
  
  preferences.begin("factory-app", false);
  preferences.putString("ssid", s);
  preferences.putString("pass", p);
  preferences.end();
  
  ssid = s;
  pass = p;
  wifiConfigStatus = "CONNECTING";
  
  String html = "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width, initial-scale=1.0'><title>WiFi Status</title>";
  html += "<style>body { background: #0f172a; color: #f8fafc; font-family: -apple-system, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; text-align: center; }";
  html += ".card { background: #1e293b; padding: 30px; border-radius: 16px; width: 100%; max-width: 360px; box-shadow: 0 10px 25px rgba(0,0,0,0.3); }";
  html += "h2 { color: #ffffff; margin-bottom: 10px; }";
  html += ".loader { border: 4px solid #334155; border-top: 4px solid #3b82f6; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }";
  html += "@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }";
  html += ".btn { display: inline-block; padding: 12px 24px; background: #2563eb; color: #fff; text-decoration: none; border-radius: 8px; font-weight: bold; margin-top: 15px; width: 100%; box-sizing: border-box; }";
  html += ".btn-sec { background: #475569; }</style>";
  html += "<script>";
  html += "var checkCount = 0;";
  html += "function checkStatus() {";
  html += "  fetch('/save_status')";
  html += "    .then(r => r.json())";
  html += "    .then(data => {";
  html += "      if (data.status === 'CONNECTED') {";
  html += "        document.getElementById('msg').innerHTML = '🏆 <b>Connected!</b><br><br>Device IP is:<br><span style=\"color:#3b82f6;font-size:1.8rem;font-weight:bold;\">' + data.ip + '</span><br><br>Please connect your phone back to your home Wi-Fi network to access the device.<br><br>Redirecting...';";
  html += "        document.getElementById('loader').style.display = 'none';";
  html += "        setTimeout(() => { window.location.href = 'http://' + data.ip + '/'; }, 6000);";
  html += "      } else if (data.status === 'FAILED') {";
  html += "        document.getElementById('msg').innerText = 'Connection Failed. Please check the Wi-Fi password and try again.';";
  html += "        document.getElementById('loader').style.display = 'none';";
  html += "        document.getElementById('actions').innerHTML = '<a href=\"/\" class=\"btn btn-sec\">Try Again</a>';";
  html += "      } else {";
  html += "        checkCount++;";
  html += "        if (checkCount > 15) {";
  html += "          document.getElementById('msg').innerText = 'Connection is taking a while. You may need to reconnect to the IOT-Device Wi-Fi manually.';";
  html += "        }";
  html += "        setTimeout(checkStatus, 2000);";
  html += "      }";
  html += "    })";
  html += "    .catch(e => { setTimeout(checkStatus, 2000); });";
  html += "}";
  html += "window.onload = function() { setTimeout(checkStatus, 1500); };";
  html += "</script></head><body>";
  html += "<div class='card'>";
  html += "<h2>Connecting...</h2>";
  html += "<div id='loader' class='loader'></div>";
  html += "<p id='msg'>Configuring Wi-Fi details...<br>Testing connection to <b>" + s + "</b>.</p>";
  html += "<div id='actions'></div>";
  html += "</div></body></html>";
  
  server.send(200, "text/html", html);
  
  triggerWifiConnect = true;
  triggerWifiConnectTime = millis();
}

void handleSaveStatus() {
  String statusStr = "CONNECTING";
  if (WiFi.status() == WL_CONNECTED && WiFi.localIP().toString() != "0.0.0.0") {
    statusStr = "CONNECTED";
    gotWiFiIP = WiFi.localIP().toString();
  } else if (WiFi.status() == WL_NO_SSID_AVAIL || WiFi.status() == WL_CONNECT_FAILED) {
    statusStr = "FAILED";
  }
  String json = "{\"status\":\"" + statusStr + "\",\"ip\":\"" + WiFi.localIP().toString() + "\",\"ssid\":\"" + ssid + "\"}";
  server.send(200, "application/json", json);
  
  if (statusStr == "CONNECTED") {
    // Wait for the JSON response to be fully transmitted
    delay(1000);
    // Restarting drops the setup SoftAP, naturally pushing the user's phone back to their home network!
    ESP.restart();
  }
}


template <typename ServerType>
void handleRootNormalT(ServerType& s) {
  String html = "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>";
  html += "<title>ESP32 RFID Dashboard</title>";
  html += "<style>";
  html += ":root {";
  html += "  --bg-darker: #090d16; --bg-dark: #0f172a; --bg-card: #1e293b; --bg-input: #030712;";
  html += "  --primary: #3b82f6; --primary-hover: #1d4ed8; --text-main: #f8fafc; --text-muted: #94a3b8;";
  html += "  --border: #334155; --success: #10b981; --danger: #ef4444; --warning: #f59e0b;";
  html += "}";
  html += "* { box-sizing: border-box; margin: 0; padding: 0; }";
  html += "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: var(--bg-darker); color: var(--text-main); display: flex; min-height: 100vh; overflow: hidden; }";
  html += ".sidebar { width: 250px; background: var(--bg-dark); border-right: 1px solid var(--border); display: flex; flex-direction: column; flex-shrink: 0; transition: transform 0.25s ease-in-out; }";
  html += ".sidebar-header { padding: 20px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 10px; font-weight: bold; font-size: 1.1rem; }";
  html += ".sidebar-logo { width: 32px; height: 32px; background: var(--primary); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; }";
  html += ".sidebar-menu { flex: 1; padding: 10px; overflow-y: auto; display: flex; flex-direction: column; gap: 5px; }";
  html += ".menu-btn { width: 100%; background: transparent; border: none; color: var(--text-muted); padding: 12px 15px; border-radius: 8px; text-align: left; font-size: 0.95rem; cursor: pointer; display: flex; align-items: center; gap: 12px; transition: all 0.2s; font-weight: 500; }";
  html += ".menu-btn:hover { background: #1e293b; color: #fff; }";
  html += ".menu-btn.active-nav, .menu-btn.active { background: var(--primary); color: #fff; font-weight: 600; }";
  html += ".logout-btn { color: var(--danger); margin-top: 10px; }";
  html += ".logout-btn:hover { background: rgba(239, 68, 68, 0.1); }";
  html += ".sidebar-footer { padding: 15px; border-top: 1px solid var(--border); }";
  html += ".restart-btn { width: 100%; background: var(--bg-card); border: 1px solid var(--border); color: #fff; padding: 10px; border-radius: 8px; font-weight: 600; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 8px; transition: all 0.2s; }";
  html += ".restart-btn:hover { background: var(--border); }";
  html += ".mobile-header { display: none; width: 100%; background: var(--bg-dark); border-bottom: 1px solid var(--border); padding: 12px 20px; align-items: center; justify-content: space-between; position: fixed; top: 0; left: 0; z-index: 150; height: 56px; }";
  html += ".mobile-logo-group { display: flex; align-items: center; gap: 10px; font-weight: bold; font-size: 1.1rem; }";
  html += ".hamburger { background: transparent; border: none; color: #fff; cursor: pointer; padding: 5px; display: flex; align-items: center; }";
  html += ".main-wrapper { display: flex; flex: 1; width: 100%; height: 100vh; overflow: hidden; }";
  html += ".main-content { flex: 1; padding: 30px; overflow-y: auto; display: flex; flex-direction: column; margin-top: 0; }";
  html += ".section { display: none; animation: fadeIn 0.15s ease-out; }";
  html += ".section.active { display: block; }";
  html += "@keyframes fadeIn { from { opacity: 0; transform: translateY(3px); } to { opacity: 1; transform: translateY(0); } }";
  html += "h2 { font-size: 1.5rem; font-weight: 700; margin-bottom: 20px; color: #fff; }";
  html += "h3 { font-size: 1.1rem; font-weight: 600; margin-bottom: 15px; display: flex; align-items: center; gap: 8px; color: #fff; }";
  html += ".grid-stat { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 24px; }";
  html += ".grid-json { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; }";
  html += ".card { background: var(--bg-dark); border: 1px solid var(--border); border-radius: 12px; padding: 20px; }";
  html += ".card-stat { background: var(--bg-dark); border: 1px solid var(--border); border-radius: 12px; padding: 20px; display: flex; flex-direction: column; justify-content: center; }";
  html += ".stat-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; font-weight: 700; }";
  html += ".stat-value { font-size: 1.25rem; font-weight: 700; color: #fff; }";
  html += ".form-group { display: flex; flex-direction: column; gap: 6px; margin-bottom: 16px; }";
  html += ".input-label { font-size: 0.85rem; font-weight: 600; color: var(--text-muted); }";
  html += "input, select { width: 100%; padding: 10px 14px; background: var(--bg-input); border: 1px solid var(--border); border-radius: 8px; color: #fff; font-size: 0.95rem; transition: border-color 0.2s, box-shadow 0.2s; }";
  html += "input:focus, select:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 2px rgba(59,130,246,0.25); }";
  html += ".pwd-container { position: relative; }";
  html += ".pwd-toggle { position: absolute; right: 12px; top: 50%; transform: translateY(-50%); background: transparent; border: none; color: var(--text-muted); cursor: pointer; display: flex; align-items: center; }";
  html += ".btn { width: 100%; padding: 11px 18px; border-radius: 8px; font-size: 0.95rem; font-weight: 600; cursor: pointer; transition: background 0.2s, opacity 0.2s; display: inline-flex; align-items: center; justify-content: center; gap: 8px; border: none; text-align: center; }";
  html += ".btn:hover { opacity: 0.9; }";
  html += ".btn-primary { background: var(--primary); color: #fff; }";
  html += ".btn-success { background: var(--success); color: #fff; }";
  html += ".btn-danger { background: var(--danger); color: #fff; }";
  html += ".btn-warning { background: var(--warning); color: #000; }";
  html += ".btn-slate { background: var(--bg-card); color: #fff; border: 1px solid var(--border); }";
  html += ".btn-slate:hover { background: var(--border); }";
  html += ".flex-gap { display: flex; gap: 8px; }";
  html += ".space-y-4 > * + * { margin-top: 16px; }";
  html += "pre { background: var(--bg-input); border: 1px solid var(--border); padding: 15px; border-radius: 8px; color: #60a5fa; font-family: 'Courier New', Courier, monospace; font-size: 12px; overflow-x: auto; min-height: 150px; }";
  html += "#hb-json { color: #f87171; }";
  html += ".table-container { background: var(--bg-dark); border: 1px solid var(--border); border-radius: 12px; padding: 15px; overflow-x: auto; }";
  html += "table { width: 100%; border-collapse: collapse; text-align: left; }";
  html += "th, td { padding: 12px; border-bottom: 1px solid var(--border); font-size: 0.85rem; }";
  html += "th { color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }";
  html += "tr:last-child td { border-bottom: none; }";
  html += ".sidebar-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 90; }";
  html += ".sidebar-overlay.open { display: block; }";
  html += "@media (max-width: 768px) {";
  html += "  body { flex-direction: column; }";
  html += "  .mobile-header { display: flex; }";
  html += "  .main-wrapper { flex-direction: column; height: calc(100vh - 56px); margin-top: 56px; }";
  html += "  .sidebar { position: fixed; top: 56px; left: 0; bottom: 0; z-index: 100; transform: translateX(-100%); width: 280px; }";
  html += "  .sidebar.open { transform: translateX(0); }";
  html += "  .main-content { padding: 20px 15px; }";
  html += "}";
  html += "</style></head><body>";
  
  html += "<header class='mobile-header'>";
  html += "  <div class='mobile-logo-group'>";
  html += "    <div class='sidebar-logo'>🏷️</div>";
  html += "    <span>red tag Hub</span>";
  html += "  </div>";
  html += "  <button class='hamburger' onclick='toggleMenu()'>";
  html += "    <svg width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><line x1='3' y1='12' x2='21' y2='12'></line><line x1='3' y1='6' x2='21' y2='6'></line><line x1='3' y1='18' x2='21' y2='18'></line></svg>";
  html += "  </button>";
  html += "</header>";
  
  html += "<div id='sidebar-overlay' class='sidebar-overlay' onclick='toggleMenu()'></div>";
  
  html += "<div class='main-wrapper'>";
  
  html += "<nav id='sidebar' class='sidebar'>";
  html += "  <div class='sidebar-header'>";
  html += "    <div class='sidebar-logo'>🏷️</div>";
  html += "    <span>red tag Hub</span>";
  html += "  </div>";
  html += "  <div class='sidebar-menu'>";
  html += "    <button onclick=\"selectSection('dashboard')\" id='nav-dashboard' class='menu-btn active-nav'>📊 Dashboard</button>";
  html += "    <button onclick=\"selectSection('settings')\" id='nav-settings' class='menu-btn'>⚙️ Device Settings</button>";
  html += "    <button onclick=\"selectSection('ethernet')\" id='nav-ethernet' class='menu-btn'>🔌 Ethernet Settings</button>";
  html += "    <button onclick=\"selectSection('messages')\" id='nav-messages' class='menu-btn'>💬 Display Message</button>";
  html += "    <button onclick=\"selectSection('heartbeat')\" id='nav-heartbeat' class='menu-btn'>💓 Sync & Heartbeat</button>";
  html += "    <button onclick=\"selectSection('security')\" id='nav-security' class='menu-btn'>🛡️ Security Settings</button>";
  html += "    <button onclick=\"selectSection('system')\" id='nav-system' class='menu-btn'>🖥️ System Tools</button>";
  html += "    <button onclick=\"selectSection('json')\" id='nav-json' class='menu-btn'>📄 Last JSON</button>";
  html += "    <button onclick=\"selectSection('logs')\" id='nav-logs' class='menu-btn'>📜 Offline Logs</button>";
  html += "    <button onclick=\"selectSection('ota')\" id='nav-ota' class='menu-btn'>☁️ Firmware Update</button>";
  html += "    <button onclick=\"selectSection('about')\" id='nav-about' class='menu-btn'>ℹ️ About</button>";
  html += "    <button onclick=\"if(confirm('Logout?')) fetch('/logout').then(()=>location.reload())\" class='menu-btn logout-btn'>🚪 Logout</button>";
  html += "  </div>";
  html += "  <div class='sidebar-footer'>";
  html += "    <button onclick=\"if(confirm('Restart Device?')) fetch('/restart')\" class='restart-btn'>🔄 Restart</button>";
  html += "  </div>";
  html += "</nav>";
  
  html += "<main class='main-content'>";
  
  html += "<section id='dashboard' class='section active'>";
  html += "  <div class='grid-stat'>";
  html += "    <div class='card-stat'><span class='stat-label'>Machine Status</span><span id='status-text' class='stat-value'>Loading...</span></div>";
  html += "    <div class='card-stat'><span class='stat-label'>Network IP (WiFi / Eth)</span><span class='stat-value' style='color: #60a5fa; font-size: 1rem;'>" + WiFi.localIP().toString() + " / " + Ethernet.localIP().toString() + "</span></div>";
  html += "    <div class='card-stat'><span class='stat-label'>Server Connection</span><span id='server-text' class='stat-value'>Loading...</span></div>";
  html += "    <div class='card-stat'><span class='stat-label' style='color: #f59e0b;'>Local Logs</span>";
  html += "      <div style='display: flex; align-items: center; justify-content: space-between; margin-top: 4px;'>";
  html += "        <span id='offline-count' class='stat-value' style='color: #f59e0b; font-size: 1.5rem;'>0</span>";
  html += "        <div class='flex-gap'><button onclick='manualSync()' class='btn btn-warning' style='padding: 4px 10px; font-size: 0.75rem; width: auto;'>Sync</button><button onclick='clearLogs()' class='btn btn-danger' style='padding: 4px 10px; font-size: 0.75rem; width: auto;'>Clear</button></div>";
  html += "      </div>";
  html += "    </div>";
  html += "  </div>";
  html += "  <div class='grid-json'>";
  html += "    <div class='card'><h3>📊 Event JSON</h3><pre id='event-json'></pre></div>";
  html += "    <div class='card'><h3>💓 Heartbeat JSON</h3><pre id='hb-json'></pre></div>";
  html += "  </div>";
  html += "</section>";
  
  html += "<section id='settings' class='section'>";
  html += "  <h2>Device Settings</h2>";
  html += "  <div class='card space-y-4'>";
  html += "    <div class='form-group'><label class='input-label'>ID:</label><input id='s-id' value='" + deviceId + "'></div>";
  html += "    <div class='form-group'><label class='input-label'>Type:</label><input id='s-type' value='" + deviceType + "'></div>";
  html += "    <div class='form-group'><label class='input-label'>Line Code:</label><input id='s-line' value='" + lineCode + "'></div>";
  html += "    <div class='form-group'><label class='input-label'>Factory:</label><input id='s-fac' value='" + factoryName + "'></div>";
  html += "    <div class='form-group'><label class='input-label'>Date:</label><input id='s-date' type='date' value='" + setupDate + "'></div>";
  html += "    <button onclick='saveDevice()' class='btn btn-primary'>Save Device Settings</button>";
  html += "  </div>";
  html += "</section>";
  
  html += "<section id='ethernet' class='section'>";
  html += "  <h2>Ethernet Settings</h2>";
  html += "  <div class='card space-y-4'>";
  html += "    <div class='form-group'><label class='input-label'>Ethernet IP:</label><input id='eth-ip' value='" + ethIpStr + "'></div>";
  html += "    <div class='form-group'><label class='input-label'>Ethernet Gateway:</label><input id='eth-gateway' value='" + ethGatewayStr + "'></div>";
  html += "    <div class='form-group'><label class='input-label'>Ethernet Subnet Mask:</label><input id='eth-subnet' value='" + ethSubnetStr + "'></div>";
  html += "    <div class='form-group'><label class='input-label'>Ethernet DNS:</label><input id='eth-dns' value='" + ethDnsStr + "'></div>";
  html += "    <button onclick='saveEthernet()' class='btn btn-primary'>Save Ethernet Settings</button>";
  html += "  </div>";
  html += "</section>";
  
  html += "<section id='messages' class='section'>";
  html += "  <h2>Display Message Configuration</h2>";
  html += "  <div class='card space-y-4'>";
  html += "    <div class='form-group'><label class='input-label'>Issue Message:</label><input id='m-issue' value='" + msgIssue + "'></div>";
  html += "    <div class='form-group'><label class='input-label'>Resolved Message:</label><input id='m-resolved' value='" + msgResolved + "'></div>";
  html += "    <button onclick='saveMessages()' class='btn btn-primary'>Save Display Messages</button>";
  html += "  </div>";
  html += "</section>";
  
  html += "<section id='heartbeat' class='section'>";
  html += "  <h2>Sync & Heartbeat Configuration</h2>";
  html += "  <div class='grid-json' style='grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));'>";
  html += "    <div class='card space-y-4'><h3>💔 Heartbeat</h3>";
  html += "      <div class='form-group'><label class='input-label'>Heartbeat URL:</label><input id='h-url' value='" + heartbeatUrl + "'></div>";
  html += "      <div class='form-group'><label class='input-label'>Interval (Seconds):</label><input id='h-int' type='number' value='" + String(heartbeatInterval / 1000) + "'></div>";
  html += "      <button onclick='saveHb()' class='btn btn-primary'>Save Heartbeat Settings</button>";
  html += "    </div>";
  html += "    <div class='card space-y-4'><h3>⏳ Offline Log Sync</h3>";
  html += "      <div class='form-group'><label class='input-label'>Sync Interval (Seconds):</label><input id='sync-int' type='number' value='" + String(syncInterval / 1000) + "'></div>";
  html += "      <button onclick='saveSync()' class='btn btn-warning'>Save Sync Interval</button>";
  html += "      <div style='padding-top: 10px; border-top: 1px solid var(--border);'><button onclick='manualSync()' class='btn btn-slate'>Manual Sync Now</button></div>";
  html += "    </div>";
  html += "  </div>";
  html += "</section>";
  
  html += "<section id='security' class='section'>";
  html += "  <h2>Security Configuration</h2>";
  html += "  <div class='card space-y-4'>";
  html += "    <div class='form-group'><label class='input-label'>Server Endpoint URL:</label><input id='sec-url' value='" + serverUrl + "'></div>";
  html += "    <div class='form-group'><label class='input-label'>X-API-KEY Key:</label>";
  html += "      <div class='pwd-container'><input id='sec-key' type='password' value='" + apiKey + "'><button onclick=\"togglePass('sec-key')\" class='pwd-toggle' type='button'>👁️</button></div>";
  html += "    </div>";
  html += "    <div class='form-group'><label class='input-label'>Web Dashboard Username:</label><input id='sec-user' value='" + webUser + "'></div>";
  html += "    <div class='form-group'><label class='input-label'>Web Dashboard Password:</label>";
  html += "      <div class='pwd-container'><input id='sec-pass' type='password' value='" + webPass + "'><button onclick=\"togglePass('sec-pass')\" class='pwd-toggle' type='button'>👁️</button></div>";
  html += "    </div>";
  html += "    <button onclick='saveSec()' class='btn btn-primary' style='margin-top: 10px;'>Save Security Credentials</button>";
  html += "  </div>";
  html += "</section>";
  
  html += "<section id='system' class='section'>";
  html += "  <h2>System Tools</h2>";
  html += "  <div class='card space-y-4'>";
  html += "    <button onclick='testInternet()' class='btn btn-success' style='padding: 16px; font-weight: bold;'>📊 Test Internet Connection (WiFi/Eth)</button>";
  html += "    <button onclick='syncT()' class='btn btn-slate' style='padding: 16px;'>Sync Time (NTP)</button>";
  html += "    <button onclick='resetWifi()' class='btn btn-warning' style='padding: 16px;'>Reset Wi-Fi Settings</button>";
  html += "    <button onclick='factoryR()' class='btn btn-danger' style='padding: 16px;'>Factory Reset Device</button>";
  html += "  </div>";
  html += "  <div class='card space-y-4' style='margin-top: 20px;'>";
  html += "    <h3>📅 Manual Date & Time Setup</h3>";
  html += "    <div class='form-group'><label class='input-label'>Select Date & Time (Local Device Time):</label><input id='manual-dt' type='datetime-local'></div>";
  html += "    <button onclick='saveManualDT()' class='btn btn-primary' style='padding: 14px; font-weight: bold;'>Set Manual Time</button>";
  html += "  </div>";
  html += "  <div class='card' style='margin-top: 20px;'>";
  html += "    <h3>Diagnostics Output</h3>";
  html += "    <pre id='diag-output' style='min-height: 120px; max-height: 400px; overflow-y: auto; overflow-x: hidden; color: #10b981; font-family: monospace; white-space: pre-wrap; word-break: break-all;'>Click Button Above to Run Test...</pre>";
  html += "  </div>";
  html += "</section>";
  
  html += "<section id='json' class='section'>";
  html += "  <h2>Last Known JSON Payloads</h2>";
  html += "  <div class='card'><pre id='json-display'></pre></div>";
  html += "</section>";
  
  html += "<section id='logs' class='section'>";
  html += "  <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;'>";
  html += "    <h2>Offline Saved Logs</h2>";
  html += "    <button onclick='clearLogs()' class='btn btn-danger' style='padding: 6px 12px; font-size: 0.85rem; width: auto;'>Clear All Logs</button>";
  html += "  </div>";
  html += "  <div class='table-container'>";
  html += "    <table>";
  html += "      <thead><tr><th>Time</th><th>User</th><th>Status</th></tr></thead>";
  html += "      <tbody id='logs-body'></tbody>";
  html += "    </table>";
  html += "  </div>";
  html += "</section>";
  
  html += "<section id='about' class='section'>";
  html += "  <h2>About Node Device</h2>";
  html += "  <div class='card space-y-4'>";
  html += "    <p><strong>Device ID:</strong> " + deviceId + "</p>";
  html += "    <p><strong>Hardware Model:</strong> Red Tag v4.1 </p>";
  html += "    <p><strong>Firmware Version:</strong> " + CURRENT_VERSION + "</p>";
  html += "    <p><strong>Status:</strong> Active / Production Ready</p>";
  html += "  </div>";
  html += "</section>";
  
  html += "<section id='ota' class='section'>";
  html += "  <h2>Firmware Update Configuration</h2>";
  html += "  <div class='card space-y-4'>";
  html += "    <div class='text-sm' style='color: var(--text-muted);'>Current Version: <strong style='color: var(--primary);'>" + CURRENT_VERSION + "</strong> | Status: <strong id='ota-status' style='color: var(--success);'>Idle</strong></div>";
  html += "    <input type='hidden' id='ota-url'><input type='hidden' id='ver-url'>";
  html += "    <div style='display: flex; align-items: center; gap: 10px; padding: 10px 0;'>";
  html += "      <input type='checkbox' id='ota-auto' style='width: 18px; height: 18px; cursor: pointer;'>";
  html += "      <label for='ota-auto' style='cursor: pointer; font-size: 0.95rem;'>Enable Auto-Update (Check server every 24 hours)</label>";
  html += "    </div>";
  html += "    <button onclick='saveOta()' class='btn btn-primary'>Save OTA Settings</button>";
  html += "    <div style='padding-top: 15px; border-top: 1px solid var(--border); margin-top: 15px;'>";
  html += "      <button onclick='checkUpdate()' class='btn btn-success'>Check & Pull Update Now</button>";
  html += "    </div>";
  html += "  </div>";
  html += "</section>";
  
  html += "</main>";
  html += "</div>";
  
  html += "<script>";
  html += "function toggleMenu(){";
  html += "  const sidebar = document.getElementById('sidebar');";
  html += "  const overlay = document.getElementById('sidebar-overlay');";
  html += "  sidebar.classList.toggle('open');";
  html += "  overlay.classList.toggle('open');";
  html += "}";
  html += "function selectSection(id){";
  html += "  document.querySelectorAll('.section').forEach(s=>s.classList.remove('active'));";
  html += "  document.getElementById(id).classList.add('active');";
  html += "  document.querySelectorAll('.menu-btn').forEach(b=>b.classList.remove('active-nav'));";
  html += "  document.getElementById('nav-'+id).classList.add('active-nav');";
  html += "  if(id==='logs') updateLogs();";
  html += "  if(window.innerWidth <= 768){ toggleMenu(); }";
  html += "}";
  html += "function updateStatus(){";
  html += "  fetch('/status').then(r=>r.json()).then(d=>{";
  html += "    document.getElementById('status-text').innerText = (d.op_status == 1 ? d.msg_issue : d.msg_resolved).toUpperCase();";
  html += "    document.getElementById('status-text').style.color = (d.op_status == 1 ? 'var(--danger)' : 'var(--success)');";
  html += "    document.getElementById('server-text').innerText = (d.server_connected == '1' ? 'ONLINE' : 'OFFLINE');";
  html += "    document.getElementById('server-text').style.color = (d.server_connected == '1' ? 'var(--success)' : 'var(--danger)');";
  html += "    document.getElementById('offline-count').innerText = d.offline_count;";
  html += "    document.getElementById('event-json').innerText = JSON.stringify(d.last_json, null, 2);";
  html += "    document.getElementById('hb-json').innerText = d.last_hb ? JSON.stringify(d.last_hb, null, 2) : '{}';";
  html += "    document.getElementById('json-display').innerText = JSON.stringify({last_event: d.last_json, last_heartbeat: d.last_hb}, null, 2);";
  html += "    document.getElementById('ota-status').innerText = d.ota_status;";
  html += "    if(document.getElementById('ota-url') && !document.getElementById('ota-url').dataset.init){";
  html += "      document.getElementById('ota-url').value = d.ota_url;";
  html += "      document.getElementById('ver-url').value = d.ver_url;";
  html += "      document.getElementById('ota-auto').checked = (d.ota_auto == '1');";
  html += "      document.getElementById('ota-url').dataset.init = 'true';";
  html += "    }";
  html += "  }).catch(err=>console.error('Status fetch failed:', err));";
  html += "}";
  html += "function saveOta(){";
  html += "  const u=document.getElementById('ota-url').value;";
  html += "  const v=document.getElementById('ver-url').value;";
  html += "  const a=document.getElementById('ota-auto').checked ? '1' : '0';";
  html += "  fetch(`/save_ota?ota_url=${encodeURIComponent(u)}&ver_url=${encodeURIComponent(v)}&auto=${a}`).then(r=>r.text()).then(t=>alert(t));";
  html += "}";
  html += "function checkUpdate(){";
  html += "  if(confirm('Check for updates and potentially reboot?')){";
  html += "    fetch('/force_update').then(r=>r.text()).then(t=>alert(t));";
  html += "  }";
  html += "}";
  html += "function saveDevice(){";
  html += "  const id=document.getElementById('s-id').value;";
  html += "  const type=document.getElementById('s-type').value;";
  html += "  const lin=document.getElementById('s-line').value;";
  html += "  const fac=document.getElementById('s-fac').value;";
  html += "  const dat=document.getElementById('s-date').value;";
  html += "  fetch(`/save_device?id=${id}&type=${type}&line=${lin}&factory=${fac}&date=${dat}`).then(r=>r.text()).then(t=>alert(t));";
  html += "}";
  html += "function saveEthernet(){";
  html += "  const ip=document.getElementById('eth-ip').value;";
  html += "  const gw=document.getElementById('eth-gateway').value;";
  html += "  const sub=document.getElementById('eth-subnet').value;";
  html += "  const dns=document.getElementById('eth-dns').value;";
  html += "  fetch(`/save_ethernet?ip=${ip}&gateway=${gw}&subnet=${sub}&dns=${dns}`).then(r=>r.text()).then(t=>alert(t));";
  html += "}";
  html += "function saveMessages(){";
  html += "  const i=document.getElementById('m-issue').value;";
  html += "  const r=document.getElementById('m-resolved').value;";
  html += "  fetch(`/save_messages?issue=${i}&resolved=${r}`).then(r=>r.text()).then(t=>alert(t));";
  html += "}";
  html += "function saveHb(){";
  html += "  const u=document.getElementById('h-url').value;";
  html += "  const i=document.getElementById('h-int').value;";
  html += "  fetch(`/save_heartbeat?url=${encodeURIComponent(u)}&interval=${i}`).then(r=>r.text()).then(t=>alert(t));";
  html += "}";
  html += "function saveSync(){";
  html += "  const i=document.getElementById('sync-int').value;";
  html += "  fetch(`/save_sync?interval=${i}`).then(r=>r.text()).then(t=>alert(t));";
  html += "}";
  html += "function manualSync(){";
  html += "  fetch('/manual_sync').then(r=>r.text()).then(t=>{ alert(t); updateStatus(); });";
  html += "}";
  html += "function togglePass(id){";
  html += "  const i=document.getElementById(id);";
  html += "  const btn=i.parentElement.querySelector('button');";
  html += "  if(i.type==='password'){ i.type='text'; btn.innerText='🙈'; }";
  html += "  else { i.type='password'; btn.innerText='👁️'; }";
  html += "}";
  html += "function saveSec(){";
  html += "  const u=document.getElementById('sec-url').value;";
  html += "  const k=document.getElementById('sec-key').value;";
  html += "  const us=document.getElementById('sec-user').value;";
  html += "  const p=document.getElementById('sec-pass').value;";
  html += "  fetch(`/save_security?url=${encodeURIComponent(u)}&key=${k}&user=${us}&pass=${p}`).then(r=>r.text()).then(t=>alert(t));";
  html += "}";
  html += "function updateLogs(){";
  html += "  fetch('/get_logs').then(r=>r.json()).then(data=>{";
  html += "    const b=document.getElementById('logs-body');";
  html += "    b.innerHTML='';";
  html += "    if(data.length === 0){ b.innerHTML = '<tr><td colspan=\"3\" style=\"text-align:center;color:var(--text-muted);\">No offline logs recorded</td></tr>'; return; }";
  html += "    data.forEach(l=>{";
  html += "      b.innerHTML += '<tr><td>'+l.date+' '+l.time+'</td><td>'+l.user+'</td><td><span style=\"color:'+(l.status==1?'var(--danger)':'var(--success)')+'\">'+(l.status==1?'ISSUE':'OK')+'</span></td></tr>';";
  html += "    });";
  html += "  }).catch(err=>console.error('Failed to get logs:', err));";
  html += "}";
  html += "function clearLogs(){";
  html += "  fetch('/clear_logs').then(r=>r.text()).then(t=>{ alert(t); updateLogs(); updateStatus(); });";
  html += "}";
  html += "function syncT(){ fetch('/sync_time').then(r=>r.text()).then(t=>alert(t)); }";
  html += "function saveManualDT(){";
  html += "  const val=document.getElementById('manual-dt').value;";
  html += "  if(!val){ alert('Please select date and time first!'); return; }";
  html += "  const dt=new Date(val);";
  html += "  const y=dt.getFullYear();";
  html += "  const m=dt.getMonth()+1;";
  html += "  const d=dt.getDate();";
  html += "  const h=dt.getHours();";
  html += "  const mn=dt.getMinutes();";
  html += "  const s=dt.getSeconds() || 0;";
  html += "  fetch(`/save_datetime?year=${y}&month=${m}&day=${d}&hour=${h}&min=${mn}&sec=${s}`).then(r=>r.text()).then(t=>alert(t));";
  html += "}";
  html += "function testInternet(){";
  html += "  const o=document.getElementById('diag-output');";
  html += "  o.innerText='Running network diagnostics... Please wait (takes 2-5s)...';";
  html += "  fetch('/test_internet').then(r=>r.text()).then(t=>{";
  html += "    o.innerText=t;";
  html += "  }).catch(err=>{";
  html += "    o.innerText='Error running diagnostics: '+err;";
  html += "  });";
  html += "}";
  html += "function factoryR(){";
  html += "  if(confirm('Factory Reset? This will clear ALL settings!')){";
  html += "    fetch('/factory_reset').then(r=>r.text()).then(t=>{ alert(t); location.reload(); });";
  html += "  }";
  html += "}";
  html += "function resetWifi(){";
  html += "  if(confirm('Reset WiFi settings and go to Setup mode?')){";
  html += "    fetch('/reset_wifi').then(r=>r.text()).then(t=>{ alert(t); location.reload(); });";
  html += "  }";
  html += "}";
  html += "setInterval(updateStatus, 2000);";
  html += "updateStatus();";
  html += "</script></body></html>";

  s.send(200, "text/html", html);
}

void handleRootNormal() {
  handleRootNormalT(server);
}

void handleRootNormalEth() {
  handleRootNormalT(ethServer);
}

// LED Status Indicator Task
void ledIndicatorTask(void *pvParameters) {
  Serial.println("[SYSTEM-LED] Starting up: Initializing LED 1 & LED 2 indicator task...");
  // 1. Double-blink power-on starting sequence
  Serial.println("[SYSTEM-LED] LED Boot Sequence... Alternating LEDs");
  for (int i = 0; i < 10; i++) {
    digitalWrite(STATUS_LED_1, LED_1_ON);
    digitalWrite(STATUS_LED_2, LOW);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    digitalWrite(STATUS_LED_1, LED_1_OFF);
    digitalWrite(STATUS_LED_2, HIGH);
    vTaskDelay(100 / portTICK_PERIOD_MS);
  }
  digitalWrite(STATUS_LED_1, LED_1_OFF);
  digitalWrite(STATUS_LED_2, LOW);
  vTaskDelay(100 / portTICK_PERIOD_MS);
  Serial.println("[SYSTEM-LED] Boot Sequence completed. Monitoring system status...");

  int lastNetworkState = -1; // 0=Disconnected, 1=No Server, 2=Fully Connected
  int lastResetState = 0;    // 0=None, 1=Holding, 2=WiFi Reset, 3=Factory Reset

  for (;;) {
    unsigned long now = millis();
    bool inResetHold = false;
    unsigned long holdTime = 0;
    int currentResetState = 0;
    int currentNetworkState = 0;

    // Check Reset Button first (highest override priority)
    if (digitalRead(RESET_BUTTON) == LOW && buttonHoldStart != 0) {
      inResetHold = true;
      holdTime = now - buttonHoldStart;
      if (holdTime >= 6000) {
        // Factory Reset configuration (Ultra-fast strobe blinking)
        bool flash = (now % 100 < 50);
        digitalWrite(STATUS_LED_1, flash ? LED_1_ON : LED_1_OFF);
        digitalWrite(STATUS_LED_2, flash ? HIGH : LOW);
        currentResetState = 3;
      } else if (holdTime >= 3000) {
        // WiFi Reset pattern (Medium synchronized blinking)
        bool flash = (now % 400 < 200);
        digitalWrite(STATUS_LED_1, flash ? LED_1_ON : LED_1_OFF);
        digitalWrite(STATUS_LED_2, flash ? HIGH : LOW);
        currentResetState = 2;
      } else {
        // Solid ON for holding reset initial stage
        digitalWrite(STATUS_LED_1, LED_1_ON);
        digitalWrite(STATUS_LED_2, HIGH);
        currentResetState = 1;
      }
    } else {
      // Normal operational indications

      // --- LED 1: System Heartbeat & Health Check ---
      // Flashes briefly (100ms) once every 2 seconds
      bool led1Flash = (now % 2000 < 100);
      digitalWrite(STATUS_LED_1, led1Flash ? LED_1_ON : LED_1_OFF);

      // --- LED 2: Network & Server link status ---
      bool netOK = isNetworkConnected();
      if (!netOK) {
        digitalWrite(STATUS_LED_2, LOW); // Network fully disconnected -> OFF
        currentNetworkState = 0;
      } else if (!serverConnected) {
        // Network has LINK/IP, but Server is disconnected -> Slow blinking 1Hz (500ms ON / 500ms OFF)
        bool flash = (now % 1000 < 500);
        digitalWrite(STATUS_LED_2, flash ? HIGH : LOW);
        currentNetworkState = 1;
      } else {
        digitalWrite(STATUS_LED_2, HIGH); // Fully connected -> SOLID ON
        currentNetworkState = 2;
      }
    }

    // Print only on actual semantic state changes
    if (currentResetState != lastResetState) {
      lastResetState = currentResetState;
      if (currentResetState == 1) Serial.println("[SYSTEM-LED] Reset Button Pressed. LEDs Solid ON.");
      else if (currentResetState == 2) Serial.println("[SYSTEM-LED] Hold >= 3s. Medium Blink (WiFi Reset Ready).");
      else if (currentResetState == 3) Serial.println("[SYSTEM-LED] Hold >= 6s. Fast Blink (Factory Reset Ready).");
      else Serial.println("[SYSTEM-LED] Reset Button Released.");
    }
    
    if (currentNetworkState != lastNetworkState && !inResetHold) {
      lastNetworkState = currentNetworkState;
      if (currentNetworkState == 0)      Serial.println("[SYSTEM-LED] LED 2 OFF -> Network fully disconnected.");
      else if (currentNetworkState == 1) Serial.println("[SYSTEM-LED] LED 2 SLOW BLINK -> IP obtained, Server unreachable.");
      else if (currentNetworkState == 2) Serial.println("[SYSTEM-LED] LED 2 SOLID ON -> Fully connected to Central Server.");
    }

    vTaskDelay(20 / portTICK_PERIOD_MS); // fast responsiveness check at 50Hz
  }
}
