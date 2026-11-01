# 📦 Stage 2: Extract (İkili Dosya ve Metadata Ayıklayıcı)

GSS4 pipeline'ının ikinci aşamasıdır. Temin edilen APK arşivlerinin içinden tersine mühendislik için gerekli olan ikili kütüphaneleri ve metadata dosyasını ayıklar.

---

## 🎯 Ne İşe Yarar? (Amaç ve Çalışma Prensibi)
Unity IL2CPP ile derlenmiş bir Android oyununda oyun mantığı C# yerine C++ makine koduna dönüştürülmüştür. Bu aşama:
1. **`libil2cpp.so`:** Oyunun tüm derlenmiş fonksiyonlarını barındıran ARM64/ARM32 paylaşımlı kütüphanesini çıkarır (`lib/<arch>/libil2cpp.so`).
2. **`global-metadata.dat`:** İl2Cpp motorunun sınıf isimlerini, metot tanımlarını ve string literallerini barındıran metadata dosyasını çıkartır (`assets/bin/Data/Managed/Metadata/`).
3. **`libunity.so`:** SwapBuffers, render döngüsü ve motor fonksiyonlarını içeren Unity motor ikilisini çıkartır.
4. **İsteğe Bağlı Ek Kütüphaneler:** Profilde tanımlanan diğer native modülleri (örn: `libanogs.so`, `libmain.so`) çıkartır.

---

## 🚀 Neler Yapılabilir? (Geliştirme ve Genişletme Fırsatları)
Bu dal üzerinde şu yeni yetenekler eklenebilir:
- **XAPK / APKS / APKM Evrensel Çözücü:** Farklı mağaza formatlarındaki arşivleri tek hamlede çözen çoklu arşiv motoru.
- **Unity AssetBundle Çıkarıcı:** `UnityPy` veya `AssetStudio` kütüphanelerini bağlayarak oyunun 3D modellerini, seslerini ve UI dokularını ayıklama.
- **Dinamik Mimari Fallback:** İstenen mimari (`arm64-v8a`) APK içinde yoksa otomatik olarak `armeabi-v7a` mimarisine geçiş yapma.
- **Hızlı Bellek Eşlemeli Okuma (`mmap`):** 2-3 GB büyüklüğündeki modern oyun APK'larında ayıklama süresini minimuma indirme.
- **ELF Magic Kontrolü:** Çıkarılan dosyaların gerçekten geçerli bir ELF (`0x7F 'E' 'L' 'F'`) olduğunu anında doğrulama.

---

## 🛡️ Hata Yönetimi ve Loglama (Error Handling & Logging)

### Hata Kodları ve Çözüm Rehberi
| Hata Kodu | Olası Sebep | Çözüm Önerisi |
|---|---|---|
| `ERR_ZIP_CORRUPT` | APK dosyası bozulmuş veya eksik inmiş | APK dosyasını tekrar indirin veya bütünlüğünü test edin. |
| `ERR_MISSING_IL2CPP` | `libil2cpp.so` aranan mimaride yok | Split APK kullanılıyorsa `split_config.arm64_v8a.apk` dosyasını ekleyin. |
| `ERR_MISSING_METADATA` | `global-metadata.dat` arşivde bulunamadı | `base.apk` dosyasının sağlandığını doğrulayın. |
| `ERR_EXTRACTION_IO` | Dosya yazma veya okuma izni hatası | Hedef dizinin yazma izinlerini kontrol edin. |

### Log Dosyaları
- **Aşama Özel Logu:** `workspace/logs/stage_02_02_extract.log`
- **Genel Pipeline Logu:** `workspace/logs/pipeline.log`

---

## 💻 Bağımsız Çalıştırma Örneği
```powershell
python 02_extract/extract.py --apk ./workspace/apk/base.apk ./workspace/apk/split_config.arm64_v8a.apk --out ./workspace/bin --arch arm64-v8a
```
