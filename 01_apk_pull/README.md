# 📥 Stage 1: APK Pull (APK Temin Etme Modülü)

GSS4 pipeline'ının ilk aşamasıdır. Hedef Android uygulamasının çalıştırılabilir APK dosyalarını temin eder.

---

## 🎯 Ne İşe Yarar? (Amaç ve Çalışma Prensibi)
Bu aşama, analiz edilecek Android oyununun veya uygulamasının paket dosyalarını iki farklı yöntemle çalışma alanına aktarır:
1. **ADB İle Cihazdan Çekme:** Bağlı Android emülatöründen (MuMu, LDPlayer, Nox) veya fiziksel cihazdan `pm path <paket>` komutuyla APK konumlarını bulur. Base APK ve hedeflenen işlemci mimarisine (`arm64-v8a`) ait split APK'ları seçerek yerel ortama çeker.
2. **Yerel Dosyadan Kopyalama:** İnternetten önceden indirilmiş (`.apk`) dosyalarını doğrudan çalışma dizinine aktarır.

Sonuçta bir sonraki aşamanın (Stage 2) okuyabileceği `apk/apk_manifest.json` dosyasını üretir.

---

## 🚀 Neler Yapılabilir? (Geliştirme ve Genişletme Fırsatları)
Bu dal üzerinde şu yeni yetenekler eklenebilir:
- **Web İndirici Eklentisi (APKPure / QooApp):** Cihaz bağlamaya gerek kalmadan yalnızca paket adı verilerek APKPure veya QooApp API'si üzerinden güncel APK'yı otomatik indiren bir modül.
- **Split Merge Aracı:** Google Play split APK'larını (base.apk + split_config.arm64.apk) tek bir bağımsız APK'da birleştiren otomatik `apk-editor` aracı.
- **OBB / Asset İndiricisi:** Büyük boyutlu oyunların ek verilerini (`/sdcard/Android/obb/<paket>`) otomatik çekme desteği.
- **Kablosuz ADB Keşfi (Auto-Discovery):** Yerel ağdaki emülatör veya cihaz portlarını (5555, 7555, 5554) otomatik tarayıp bağlanma.

---

## 🛡️ Hata Yönetimi ve Loglama (Error Handling & Logging)

### Hata Kodları ve Çözüm Rehberi
| Hata Kodu | Olası Sebep | Çözüm Önerisi |
|---|---|---|
| `ERR_ADB_NO_DEVICE` | Emülatör kapalı veya ADB çevrimdışı | Emülatörü açın ve `adb connect 127.0.0.1:7555` çalıştırın. |
| `ERR_PACKAGE_NOT_INSTALLED` | Uygulama cihazda yüklü değil | Cihaza oyunu kurun veya `--apk-path` ile yerel dosya verin. |
| `ERR_LOCAL_APK_NOT_FOUND` | Belirtilen dosya yolu yanlış | APK dosyasının disk yolunu kontrol edin. |
| `ERR_ADB_PULL_FAILED` | İzin veya disk alanı sorunu | Cihazda ve hedef diskte yeterli boş alan olduğunu doğrulayın. |

### Log Dosyaları
- **Aşama Özel Logu:** `workspace/logs/stage_01_01_apk_pull.log`
- **Genel Pipeline Logu:** `workspace/logs/pipeline.log`

---

## 💻 Bağımsız Çalıştırma Örneği
```powershell
# Cihazdan çekme:
python 01_apk_pull/pull.py --package net.f8games.royale --out ./workspace/apk --device 127.0.0.1:7555

# Yerel dosyadan kopyalama:
python 01_apk_pull/pull.py --apk-path C:\Downloads\base.apk --out ./workspace/apk
```
