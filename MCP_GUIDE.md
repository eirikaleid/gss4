# GSS4 MCP (Model Context Protocol) Server Kılavuzu

GSS4, yapay zeka asistanlarının (Claude, Gemini, Cursor, Antigravity vb.) doğrudan fonksiyon çağrıları (Tool Call) yaparak Unity IL2CPP oyunlarından offset çıkarmasını, dump dosyalarını taramasını ve profilleri yönetmesini sağlayan tam bir **Model Context Protocol (MCP)** sunucusu içerir.

---

## 🛠️ Sunulan MCP Araçları (Tools)

| Araç Adı | Açıklama | Örnek Parametreler |
|---|---|---|
| `run_pipeline` | 1'den 7'ye kadar tüm pipeline'ı veya belirli bir aşamayı çalıştırır. | `{"profile": "royale", "apply": true}` |
| `list_profiles` | Mevcut tüm oyun/uygulama profillerini listeler. | *Parametresiz* |
| `get_profile` | İstenen profilin JSON ayarlarını döner. | `{"name": "royale"}` |
| `save_profile` | Yeni bir oyun profili kaydeder veya günceller. | `{"name": "yeni_oyun", "config": {...}}` |
| `inspect_dump` | 70 MB'lık `dump.cs` dosyasını belleğe yüklemeden anahtar kelimeye göre arama yapar. | `{"query": "PlayerController", "search_type": "class"}` |
| `get_offsets` | Çıkarılan son offsetleri JSON veya C++ header olarak getirir. | `{"format": "json"}` |
| `diff_offsets` | İki header arasındaki RVA ve alan değişimlerini diff raporu olarak sunar. | `{"old_header": "...", "new_header": "..."}` |

---

## 📦 Sunulan MCP Kaynakları (Resources)

- `offsets://current`: Projede aktif olan [`src/core/offsets.h`](file:///C:/Users/MonsterTesla/Desktop/gss4/src/core/offsets.h) içeriğini canlı döner.
- `profiles://list`: Kayıtlı profillerin JSON listesini döner.

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
