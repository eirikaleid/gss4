# 📜 Stage 6: Parse Offsets (Ofset Ayrıştırıcı ve Kod Üretici)

GSS4 pipeline'ının altıncı aşamasıdır. `Il2CppDumper` çıktısı olan metin dosyalarını ayrıştırarak C++, JSON, Rust ve C# dillerinde doğrudan derlenebilir bağlayıcılar (bindings) üretir.

---

## 🎯 Ne İşe Yarar? (Amaç ve Çalışma Prensibi)
`dump.cs` dosyası yüz binlerce satırdan oluşur. Bu aşama:
1. **Profil Odaklı Sınıf Ayrıştırma:** Yalnızca projenin ihtiyaç duyduğu öncelikli sınıfları (`CharacterManager`, `GamePlayer`, `Actor` vb.) ve bu sınıflara ait metotları seçer.
2. **Alan Ofsetleri (Field Offsets):** Sınıf üyelerinin bellek uzaklıklarını (`0x...`) okur ve C++ constexpr sabitlerine dönüştürür.
3. **TypeInfo Adres Çözümü:** `script.json` ve ELF `PT_LOAD` segmentlerini kullanarak runtime'da lazy-init olan `Il2CppClass*` göstericilerinin dosya ve VA ofsetlerini çözer.
4. **Çoklu Dil Üretimi (`generators/`):**
   - `cpp_gen.py` -> C++ `offsets.h`
   - `rust_gen.py` -> Rust `offsets.rs`
   - `csharp_gen.py` -> C# `Offsets.cs`
   - `json` -> `offsets.json`

---

## 🚀 Neler Yapılabilir? (Geliştirme ve Genişletme Fırsatları)
Bu dal üzerinde şu yeni yetenekler eklenebilir:
- **Yeni Dil Jeneratörleri Eklemek:** `generators/` klasörüne `python_gen.py`, `go_gen.py` veya `typescript_gen.py` ekleyerek istenen dilde binding üretme:
  ```python
  def generate_python(data: dict) -> str:
      # Kod üretimi...
      return py_code
  ```
- **AST Tabanlı C# Ayrıştırıcı:** Regex yerine doğrudan soyut sözdizim ağacı (AST) ile generics (`List<T>`, `Dictionary<K,V>`) ve iç içe enum yapılarını kusursuz çözme.
- **Obfuscation (İsim Karıştırma) Çözücü:** İsimleri harf dizisine (`a`, `b1`, `\u0001`) dönüştürülmüş sınıfları metot parametre sayısı ve string referanslarıyla eşleme.
- **AOB / Opcode Pattern Generator:** Metot RVA'larının ilk 16 baytını okuyarak dinamik bellek taraması (Array of Bytes scanning) için maske ve imza üretme.
- **Sanal Fonksiyon Vtable Slot Hesabı:** Sanal metotların vtable indekslerini çıkararak C++ vptr çağırma ofsetlerini oluşturma.

---

## 🛡️ Hata Yönetimi ve Loglama (Error Handling & Logging)

### Hata Kodları ve Çözüm Rehberi
| Hata Kodu | Olası Sebep | Çözüm Önerisi |
|---|---|---|
| `ERR_DUMP_CS_MISSING` | dump.cs dosyası mevcut değil | Stage 4'ün (dump) başarıyla tamamlandığını doğrulayın. |
| `ERR_SCRIPT_JSON_MISSING` | script.json dosyası mevcut değil | Stage 4 çıktısını kontrol edin. |
| `ERR_STAGE_06_PARSE` | Profildeki sınıf adları dump'ta bulunamadı | Profil JSON dosyasındaki sınıf isimlerini dump.cs ile karşılaştırın. |

### Log Dosyaları
- **Aşama Özel Logu:** `workspace/logs/stage_06_06_parse_offsets.log`
- **Genel Pipeline Logu:** `workspace/logs/pipeline.log`

---

## 💻 Bağımsız Çalıştırma Örneği
```powershell
python 06_parse_offsets/parse_offsets.py --dump ./workspace/dump/dump.cs --script ./workspace/dump/script.json --so ./workspace/bin/libil2cpp.so --profile ./profiles/royale.json --out ./workspace/offsets.h
```
