# 🛡️ Stage 7: Verify & Diff (Doğrulama ve Diff Güvenlik Kapısı)

GSS4 pipeline'ının son aşamasıdır. Üretilen ofsetlerin fiziksel ve mantıksal tutarlılığını doğrular, önceki sürüm ile farkları raporlar ve onaylıysa projeye uygular.

---

## 🎯 Ne İşe Yarar? (Amaç ve Çalışma Prensibi)
Yeni bir oyun sürümü geldiğinde ofsetlerin hatalı çıkması oyunun doğrudan çökmesine (SIGSEGV / crash) neden olur. Bu aşama bir güvenlik kapısı (sanity gate) olarak çalışır:
1. **ARM64 Komut Hizalama Testi:** Tüm fonksiyon RVA'larının 4 bayt sınırına oturduğunu (`RVA % 4 == 0`) test eder.
2. **Bellek Sınır Testi:** Metot adreslerinin `libil2cpp.so` dosya boyutunu aşmadığını ve sınıf alanı ofsetlerinin makul olduğunu (`< 0x10000`) kontrol eder.
3. **Kaynak Kod Bütünlüğü:** `src/` dizinindeki C++ kodlarında kullanılan `Offsets::...` sembollerini regex ile tarar; yeni header'da eksik bir sembol varsa işlemi durdurur.
4. **Diff Raporlama:** Eski header ile yeni header arasındaki farkları (eklenen, silinen, değişen ofsetler ve kayma miktarı) hesaplayıp `verify_report.txt` dosyasına yazar.
5. **Otomatik Yedekleme ve Uygulama:** `--apply` parametresi verildiğinde mevcut `offsets.h` dosyasını `backups/offsets_YYYYMMDD_HHMMSS.h` olarak yedekler ve yenisini `src/core/offsets.h` dosyasına kopyalar.

---

## 🚀 Neler Yapılabilir? (Geliştirme ve Genişletme Fırsatları)
Bu dal üzerinde şu yeni yetenekler eklenebilir:
- **Canlı Bellek Doğrulama Kapısı (Live Memory Assertion):** Emülatörde açık olan oyunun belleğine bağlanıp (`/proc/pid/mem`) TypeInfo adreslerinin geçerli bir `Il2CppClass*` olup olmadığını teyit etme.
- **Otomatik Test Derleyicisi (Clang/GCC Test-Compile):** Yeni header üretildiğinde `src/` kodlarının hatasız derlenip derlenmediğini arka planda anında test etme.
- **CI/CD Webhook & Diff Bildirici:** Değişen ofset tablosunu Markdown formatında GitHub PR'ına veya Discord/Telegram bildirim kanalına gönderme.
- **Snapshot & Rollback Yöneticisi:** Eğer oyun enjekte edildikten sonra çökerse tek bir komutla önceki çalışan sürüme ve ofsetlere geri dönme.
- **İstatistiksel Anomali Tespiti:** Önceki 10 sürümdeki ofset kaymalarını takip ederek olağandışı sapmaları anında tespit etme.

---

## 🛡️ Hata Yönetimi ve Loglama (Error Handling & Logging)

### Hata Kodları ve Çözüm Rehberi
| Hata Kodu | Olası Sebep | Çözüm Önerisi |
|---|---|---|
| `ERR_NEW_HEADER_MISSING` | Doğrulanacak offsets.h dosyası yok | Stage 6'nın çalıştığından emin olun. |
| `ERR_STAGE_07_VERIFY` | Tanımsız sembol veya aşırı kayma | `verify_report.txt` raporunu inceleyerek eksik sembolleri tamamlayın. |
| `ERR_UNALIGNED_INSTRUCTION` | ARM64 4-bayt komut hizalaması bozuk | Metot RVA adresinin geçerliliğini kontrol edin. |

### Log Dosyaları
- **Doğrulama ve Diff Raporu:** `workspace/verify_report.txt`
- **Aşama Özel Logu:** `workspace/logs/stage_07_07_verify_diff.log`
- **Genel Pipeline Logu:** `workspace/logs/pipeline.log`

---

## 💻 Bağımsız Çalıştırma Örneği
```powershell
# Sadece doğrula ve diff raporu çıkar:
python 07_verify_diff/verify_diff.py --new ./workspace/offsets.h --old ./src/core/offsets.h --so ./workspace/bin/libil2cpp.so --src ./src

# Doğrulamadan sonra projeye uygula:
python 07_verify_diff/verify_diff.py --new ./workspace/offsets.h --old ./src/core/offsets.h --apply-to ./src/core/offsets.h
```
