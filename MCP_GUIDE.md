# GSS4 MCP (Model Context Protocol) Server Kılavuzu

GSS4, yapay zeka asistanlarının (Claude, Gemini, Cursor, Antigravity vb.) doğrudan fonksiyon çağrıları (Tool Call) yaparak Unity IL2CPP oyunlarından offset çıkarmasını, dump dosyalarını taramasını, aşamaları tek tek denetlemesini, logları okumasını ve profilleri yönetmesini sağlayan tam bir **Model Context Protocol (MCP)** sunucusu içerir.

---

## 🛠️ Sunulan MCP Araçları (Tools)

| Araç Adı | Açıklama | Örnek Parametreler |
|---|---|---|
| `run_pipeline` | 1'den 7'ye kadar tüm pipeline'ı veya belirli bir aşamayı çalıştırır. | `{"profile": "royale", "apply": true}` |
| `run_stage` | İstenen tek bir aşamayı (1..7) izole olarak çalıştırır. | `{"stage_id": 3, "workspace": "build/royale"}` |
| `run_stage_tests` | Belirli veya tüm aşamaların birim testlerini koşturur. | `{"stage_id": 1}` veya `{}` |
| `get_stage_info` | Aşamanın amacını, geliştirme noktalarını ve hata çözüm rehberini getirir. | `{"stage_id": 6}` |
| `get_stage_logs` | Bir aşamanın çalışma loglarını (son N satır) getirir. | `{"stage_id": 4, "profile": "royale", "tail_lines": 50}` |
| `list_stage_plugins` | 3. (Decrypt) veya 6. (Generator) aşamadaki tak-çıkar eklentileri listeler. | `{"stage_id": 3}` |
| `list_profiles` | Mevcut tüm oyun/uygulama profillerini listeler. | *Parametresiz* |
| `get_profile` | İstenen profilin JSON ayarlarını döner. | `{"name": "royale"}` |
| `save_profile` | Yeni bir oyun profili kaydeder veya günceller. | `{"name": "yeni_oyun", "config": {...}}` |
| `inspect_dump` | 70 MB'lık `dump.cs` dosyasını belleğe yüklemeden anahtar kelimeye göre arama yapar. | `{"query": "CharacterManager", "search_type": "class"}` |
| `get_offsets` | Çıkarılan son offsetleri JSON veya C++ header olarak getirir. | `{"format": "json"}` |
| `diff_offsets` | İki header arasındaki RVA ve alan değişimlerini diff raporu olarak sunar. | `{"old_header": "...", "new_header": "..."}` |
| `decompile_symbol` | Hedef fonksiyonu / sembolü Ghidra veya REA ile C++/ARM64 olarak decompile eder. | `{"rva": "0x100004", "engine": "ghidra"}` |
| `search_native_xrefs` | Native binary içinde string veya sembol referanslarını (XREF) tarar. | `{"needle": "libswappywrapper", "engine": "auto"}` |
| `inspect_metadata_rea` | IL2CPP `global-metadata.dat` dosyasını REA motoruyla analiz eder. | `{"metadata": "build/royale/bin/global-metadata.dat"}` |
| `get_learned_knowledge` | Öğrenilen stratejileri, alias eşlemelerini, drift paternlerini ve dersleri döner. | `{"query": "CharacterManager", "category": "aliases"}` |
| `record_learned_lesson` | Dışarıdan veya ajandan gelen tecrübe ve arıza çözümlerini kalıcı bilgi tabanına kaydeder. | `{"topic": "anticheat", "problem": "ERR_X", "solution": "Y"}` |
| `suggest_adaptation` | Hata veya drift anında geçmiş tecrübelerden adaptif çözüm önerir. | `{"package": "net.f8games.royale", "error_code": "ERR_DECRYPTION_FAILED"}` |

---

## 📦 Sunulan MCP Kaynakları (Resources)

- `offsets://current`: Projede aktif olan `src/core/offsets.h` içeriğini canlı döner.
- `profiles://list`: Kayıtlı profillerin JSON listesini döner.

---

## 🛡️ Hata Yönetimi ve Loglama Sistemi

Her aşama `core.errors` modülündeki yapılandırılmış özel exception sınıflarını (`DevicePullError`, `ExtractionError`, `DecryptionError`, `DumperError`, `NativeAnalysisError`, `OffsetParseError`, `VerificationGateError`) kullanır.

- **Hata Kodları:** `ERR_STAGE_01_PULL`, `ERR_MISSING_IL2CPP`, `ERR_DECRYPTION_FAILED` vb.
- **Çözüm Tavsiyeleri:** Hata fırlatıldığında kullanıcıya ve yapay zekaya anında uygulanabilir kurtarma adımları sunulur.
- **Log Konumları:** Her aşamanın detaylı timestampli logları `workspace/logs/stage_{id}_{name}.log` ve `workspace/logs/pipeline.log` dosyalarına yazılır.
- **MCP Erişimi:** Asistanlar `get_stage_logs(stage_id=N)` çağrısı yaparak logları inceleyebilir ve arızaları teşhis edebilir.

---

## 🤖 MCP İstemcisine Nasıl Eklenir?

### 1. Claude Desktop
`%APPDATA%\Claude\claude_desktop_config.json` dosyasına ekleyin:
```json
{
  "mcpServers": {
    "gss4-offset-pipeline": {
      "command": "python",
      "args": [
        "C:\\Users\\MonsterTesla\\Desktop\\gss4\\mcp_server.py"
      ],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

### 2. Antigravity / Cursor
Antigravity ayarlarındaki MCP sunucuları bölümüne `gss4-offset-pipeline` adıyla ekleyin:
- **Komut:** `python`
- **Argümanlar:** `C:\Users\MonsterTesla\Desktop\gss4\mcp_server.py`
