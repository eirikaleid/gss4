# GSS4 Aşamaları Bağımsız Geliştirme Kılavuzu (Stage Development Guide)

GSS4 mimarisinde 7 aşamanın her biri **tamamen izole, kendi birim testine (`test_stage.py`) ve tak-çıkar eklenti sistemine sahip** bağımsız birer modüldür. Bir aşamayı geliştirmek için diğer aşamaları ya da ana pipeline'ı değiştirmeniz gerekmez.

---

## 🏗️ Temel Mimari: `core.stage_base.BaseStage`

Her aşama `core.stage_base.BaseStage` sınıfından türetilmiştir ve şu yaşam döngüsünü takip eder:

```
validate_inputs(ws, config) ──> before_run hooks ──> execute(ws, config) ──> validate_outputs(ws, config) ──> after_run hooks
```

İstediğiniz bir aşamaya kodunun içine girmeden hook bağlayabilirsiniz:
```python
stage = Stage3Decrypt()

@stage.before_run
def log_start(ws, cfg):
    print("Deşifre başlıyor...")

result = stage.run_stage("./workspace")
```

---

## 🧩 Aşamaları Kendi İçinde Geliştirme Rehberi

### Aşama 1: `01_apk_pull/` (APK Çekme)
- **Dosya:** [`01_apk_pull/pull.py`](file:///C:/Users/MonsterTesla/Desktop/gss4/01_apk_pull/pull.py)
- **Birim Testi:** `python 01_apk_pull/test_stage.py`
- **Geliştirme Önerisi:** Cihazdan çekme (`ADB`) ve yerel kopyalama haricinde, doğrudan APKPure / QooApp veya HTTP API'den APK indiren bir kaynak (`sources/`) eklenebilir.

### Aşama 2: `02_extract/` (Ayıklama)
- **Dosya:** [`02_extract/extract.py`](file:///C:/Users/MonsterTesla/Desktop/gss4/02_extract/extract.py)
- **Birim Testi:** `python 02_extract/test_stage.py`
- **Geliştirme Önerisi:** Yalnızca zip değil; XAPK, APKS, split-zip veya Unity AssetBundle arşivlerini açan yeni çıkartıcılar eklenebilir.

### Aşama 3: `03_decrypt_metadata/` (Şifre Çözücü Eklentileri)
- **Dosya:** [`03_decrypt_metadata/decrypt.py`](file:///C:/Users/MonsterTesla/Desktop/gss4/03_decrypt_metadata/decrypt.py)
- **Eklenti Dizini:** `03_decrypt_metadata/strategies/`
- **Birim Testi:** `python 03_decrypt_metadata/test_stage.py`
- **Geliştirme Şekli (Tak-Çıkar):**
  `strategies/` klasörüne `yeni_anticheat.py` adında yeni bir dosya ekleyip içine:
  ```python
  def run(in_path: str, out_path: str, **kwargs) -> dict:
      # Şifre çözme algoritmanız...
      return {"status": "success", "size": ...}
  ```
  yazmanız yeterlidir! `decrypt.py` veya pipeline dosyalarında **tek bir satır kod bile değiştirmeden** yeni strateji otomatik olarak sisteme ve MCP'ye eklenir (`--strategy yeni_anticheat`).

### Aşama 4: `04_il2cpp_dump/` (Dumper Koşturucu)
- **Dosya:** [`04_il2cpp_dump/dump.py`](file:///C:/Users/MonsterTesla/Desktop/gss4/04_il2cpp_dump/dump.py)
- **Birim Testi:** `python 04_il2cpp_dump/test_stage.py`
- **Geliştirme Önerisi:** `Il2CppDumper` haricinde alternatif olarak `Il2CppInspector` veya bellekten Frida dumper motorları entegre edilebilir.

### Aşama 5: `05_native_analysis/` (Native ELF Analizi)
- **Dosya:** [`05_native_analysis/analyze_native.py`](file:///C:/Users/MonsterTesla/Desktop/gss4/05_native_analysis/analyze_native.py)
- **Birim Testi:** `python 05_native_analysis/test_stage.py`
- **Geliştirme Önerisi:** `libunity.so` dışındaki diğer native kütüphaneler (`libmain.so`, `libanogs.so` vb.) için yeni GOT relocation veya string regex kuralları yazılabilir.

### Aşama 6: `06_parse_offsets/` (Kod Üreticileri)
- **Dosya:** [`06_parse_offsets/parse_offsets.py`](file:///C:/Users/MonsterTesla/Desktop/gss4/06_parse_offsets/parse_offsets.py)
- **Üretici Eklentileri:** `06_parse_offsets/generators/`
- **Birim Testi:** `python 06_parse_offsets/test_stage.py`
- **Hazır Diller:**
  - `cpp_gen.py` -> C++ `offsets.h`
  - `rust_gen.py` -> Rust `offsets.rs`
  - `csharp_gen.py` -> C# `Offsets.cs`
  - `json` -> `offsets.json`
- **Yeni Dil Eklemek:** `generators/` içine `python_gen.py` veya `go_gen.py` ekleyerek istediğiniz programlama dilinde struct/offset kodları üretebilirsiniz!

### Aşama 7: `07_verify_diff/` (Doğrulama ve Diff)
- **Dosya:** [`07_verify_diff/verify_diff.py`](file:///C:/Users/MonsterTesla/Desktop/gss4/07_verify_diff/verify_diff.py)
- **Birim Testi:** `python 07_verify_diff/test_stage.py`
- **Geliştirme Önerisi:** Bellek sınırları, ARM64 alignment testleri ve kaynak koddaki tanımsız sembol kontrollerine ek olarak özel derleyici assert kuralları tanımlanabilir.

---

## ⚡ Hızlı Test Koşucusu

Tüm aşamaların birim testlerini 2 saniyede topluca test etmek için:
```powershell
python test_all_stages.py
```
Çıktı:
```
[PASS] Stage 1: APK Pull
[PASS] Stage 2: Extraction
[PASS] Stage 3: Decrypt Metadata
[PASS] Stage 4: Il2CppDump
[PASS] Stage 5: Native Analysis
[PASS] Stage 6: Parse Offsets
[PASS] Stage 7: Verify & Diff
[ALL PASSED] 7/7 stage test suites passed!
```
