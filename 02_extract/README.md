# 📦 Stage 2: Extract (Evrensel İkili Dosya, Paket ve Metadata Ayıklayıcı)

GSS4 pipeline'ının ikinci aşamasıdır. Temin edilen APK, XAPK, APKS ve OBB arşivlerinin içinden hedef oyun motorunun (Unity IL2CPP, Unity Mono, Unreal Engine, Godot veya Generic Native ELF) kritik ikili kütüphanelerini, metadata tablolarını ve paketlerini ayıklar ve bütünlüklerini denetler.

---

## 🎯 Ne İşe Yarar? (Amaç ve Desteklenen Motorlar)

GSS4 Aşama 2, mobil tersine mühendisliğin ihtiyaç duyduğu tüm paket formatlarını ve oyun motoru kalıplarını tek bir modüler arayüzde destekler:

### 1. Unity IL2CPP Motoru
- **`libil2cpp.so`:** Tüm C# oyun kodunun native C++ makine koduna (ARM64/ARM32) dönüştürüldüğü ana kütüphane (`lib/<arch>/libil2cpp.so`).
- **`global-metadata.dat`:** Sınıf, alan, metot isimlerini, string literallerini ve TypeDef indekslerini barındıran metadata tablosu (`assets/bin/Data/Managed/Metadata/`).
- **`libunity.so`:** SwapBuffers, render döngüsü ve motor fonksiyonlarını içeren kütüphane.

### 2. Unity Mono Motoru (.NET Assembly)
- **`Managed/*.dll`:** `Assembly-CSharp.dll`, `UnityEngine.dll` gibi CIL/MSIL bytecode içeren managed kütüphaneler (`assets/bin/Data/Managed/*.dll`).
- **`libmonosgen-2.0.so` / `libmono.so`:** Mono sanal makinesi runtime paylaşımlı kütüphanesi.

### 3. Unreal Engine 4 / 5
- **`libUE4.so` / `libUnreal.so`:** Unreal Engine native çekirdeği ve oyun mantığı ikilisi.
- **`*.pak`:** `assets/` veya `Content/Paks/` altındaki oyun varlık ve şifreli veri paketleri (`bin/paks/` dizinine aktarılır).

### 4. Godot Engine
- **`libgodot_android.so` / `libgodot.so`:** Godot Engine Android runtime kütüphanesi.
- **`*.pck`:** GDScript bytecode, sahne (.tscn) ve kaynak verilerini içeren paket (`bin/main.pck`).

### 5. XAPK & APKS Evrensel Desteği
- **XAPK Çözümleme:** İç içe geçmiş split APK'ları (`com.game.apk`, `config.arm64_v8a.apk`) ve `Android/obb/<package>/*.obb` dosyalarını tek seferde çözerek `bin/obb/` dizinine yerleştirir.
- **APKS (Bundletool / SAI) Çözümleme:** Split APK arşivlerini açarak tüm mimari ve konfigürasyon parçalarını otomatik tarar.

---

## 🛡️ İkili Bütünlük Doğrulaması (Binary Integrity Verification)

Aşama 2, ayıklanan tüm dosyaları disk seviyesinde sihirli bayt (magic byte) kontrolünden geçirir:
- **ELF Magic Kontrolü (`0x7F 'E' 'L' 'F'`):** Tüm `.so` kütüphanelerinin geçerli ELF başlığı taşıdığı, hedef mimari (`arm64-v8a`) için 64-bit (`ELFCLASS64`, `EI_CLASS=2`) ve Little-Endian (`ELFDATA2LSB`, `EI_DATA=1`) olduğu anında doğrulanır.
- **PE/COFF Magic Kontrolü (`'MZ'`):** Unity Mono managed `.dll` dosyalarının geçerli DOS/PE başlığı taşıdığı kontrol edilir.
- **Godot PCK Magic Kontrolü (`'GDPC'`):** `.pck` dosyalarının geçerli Godot paket başlığı teyit edilir.
- **Unreal PAK Magic Kontrolü (`0x5A6F12E1`):** `.pak` arşivlerinin Unreal paket sonlandırıcı (footer) sihirli baytları taranır.
- **IL2CPP Metadata Şifre Tespiti (`0xFAB11BAF`):** `global-metadata.dat` dosyasının standart mı yoksa şifreli mi olduğu belirlenir. Şifreli ise pipeline kırılmaz; Aşama 3 (03_decrypt_metadata) için bayrak bırakılır.

---

## 🚀 Neler Yapılabilir? (Geliştirme ve Genişletme Noktaları)

- **Unity AssetBundle Çıkarıcı:** `UnityPy` kütüphanesi bağlanarak doku, ses ve 3D modellerin doğrudan çıkarılması.
- **Otomatik Mimari Fallback:** İstenen mimari (`arm64-v8a`) pakette yoksa otomatik olarak `armeabi-v7a` mimarisine geçiş yapılması.
- **Bellek Eşlemeli (mmap) Hızlı Ayıklama:** 2-4 GB büyüklüğündeki devasa oyun arşivlerinde disk I/O hızının optimize edilmesi.
- **Frida Live In-Memory Dumper Entegrasyonu:** Bellekte deşifre edilmiş metadata veya packed ELF'i doğrudan çalışan işlemden dump alma.

---

## 🛡️ Hata Yönetimi ve Loglama

### Hata Kodları Tablosu
| Hata Kodu | Olası Sebep | Çözüm Önerisi |
|---|---|---|
| `ERR_ZIP_CORRUPT` | APK, XAPK veya APKS dosyası bozulmuş | Arşivi yeniden indirin veya bütünlüğünü test edin. |
| `ERR_MISSING_IL2CPP` | `libil2cpp.so` aranan mimaride yok | Split APK kullanılıyorsa `split_config.arm64_v8a.apk` dosyasını ekleyin. |
| `ERR_MISSING_METADATA` | `global-metadata.dat` arşivde bulunamadı | `base.apk` dosyasının sağlandığını doğrulayın. |
| `ERR_MISSING_MONO_TARGET`| Unity Mono için Managed DLL'ler yok | APK'nın `assets/bin/Data/Managed/` dizinini içerdiğini kontrol edin. |
| `ERR_MISSING_UNREAL_TARGET`| Unreal için `libUE4.so` veya `.pak` yok | Unreal mimari kütüphanesinin pakette yer aldığını doğrulayın. |
| `ERR_MISSING_GODOT_TARGET` | Godot için `libgodot.so` veya `.pck` yok | Godot kütüphanesi veya paketinin varlığını denetleyin. |
| `ERR_INVALID_ELF_MAGIC` | Çıkarılan `.so` geçerli bir ELF değil | Bozuk indirmeyi yenileyin veya 32/64-bit mimari uyuşmazlığını düzeltin. |

### Log Dosyaları
- **Aşama Özel Logu:** `workspace/logs/stage_02_02_extract.log`
- **Genel Pipeline Logu:** `workspace/logs/pipeline.log`

---

## 💻 Bağımsız Çalıştırma Örnekleri

### 1. Standart Unity IL2CPP APK'sı Ayıklama:
```powershell
python 02_extract/extract.py --apk ./workspace/apk/base.apk ./workspace/apk/split_config.arm64_v8a.apk --out ./workspace/bin --arch arm64-v8a
```

### 2. XAPK Paketini Tek Hamlede Çözme (OBB Dahil):
```powershell
python 02_extract/extract.py --apk ./downloads/game.xapk --out ./workspace/bin --arch arm64-v8a
```

### 3. Unity Mono (.NET Managed DLL'ler) Ayıklama:
```powershell
python 02_extract/extract.py --apk ./workspace/apk/game.apk --out ./workspace/bin --engine unity_mono
```

### 4. Unreal Engine veya Godot Otomatik Algılama ile Ayıklama:
```powershell
python 02_extract/extract.py --apk ./workspace/apk/game.apk --out ./workspace/bin --engine auto
```

### 5. Manifest Dosyası Üzerinden Pipeline Entegrasyonu:
```powershell
python 02_extract/extract.py --manifest ./workspace/apk/apk_manifest.json --out ./workspace/bin
```
