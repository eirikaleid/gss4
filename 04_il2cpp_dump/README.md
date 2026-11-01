# 🔨 Stage 4: Il2CppDump (Sembol ve Kod Dumper Modülü)

GSS4 pipeline'ının dördüncü aşamasıdır. Deşifre edilmiş metadata ile native kütüphaneyi bir araya getirerek C# sembol haritasını ve bellek ofsetlerini döker.

---

## 🎯 Ne İşe Yarar? (Amaç ve Çalışma Prensibi)
`Il2CppDumper.exe` aracını arka planda (headless) koşturur. Bu sayede:
1. **`dump.cs` (~70-100 MB):** Oyunun bütün C# sınıfları, değişkenleri, değişken ofsetleri (`// 0x...`), fonksiyon adları ve RVA adresleri temiz bir C# sözdizimiyle çıkarılır.
2. **`script.json`:** IDA Pro ve Ghidra gibi decompiler araçlarının sembolleri ve fonksiyon adlarını otomatik adlandırmasını sağlayan JSON eşleme veritabanı.
3. **`il2cpp.h`:** C++ hook projelerinde veya inject dll'lerinde doğrudan include edilebilen Unity tip tanımları.
4. **Çıktı Tazelik Kontrolü:** Önceki sürümlerden kalma eski dump dosyalarının karışmasını engellemek için her çalıştırmada çıktıları sıfırlar ve boyut bütünlüğünü test eder.

---

## 🚀 Neler Yapılabilir? (Geliştirme ve Genişletme Fırsatları)
Bu dal üzerinde şu yeni yetenekler eklenebilir:
- **Alternatif Dumper Entegrasyonu:** `Il2CppInspector` veya bellekten doğrudan dump alan Frida betiklerini tak-çıkar motor olarak bağlama.
- **Konfigürasyon Optimizasyonu:** `config.json` dosyasındaki struct üretim ve dummy DLL oluşturma ayarlarını ihtiyaca göre dinamik açıp kapama.
- **Incremental Cache (Artımlı Önbellek):** Metadata ve binary hash'i değişmemişse 70 MB'lık dump işlemini tekrar yapmayarak 15-20 saniye kazanma.
- **Çökme İzolasyonu (Crash Recovery):** Eğer dumper tek bir bozuk TypeDef yüzünden çöküyorsa o sınıfı izole edip dump sürecini kurtarma.

---

## 🛡️ Hata Yönetimi ve Loglama (Error Handling & Logging)

### Hata Kodları ve Çözüm Rehberi
| Hata Kodu | Olası Sebep | Çözüm Önerisi |
|---|---|---|
| `ERR_DUMPER_EXE_NOT_FOUND` | `tools/Il2CppDumper/` içinde exe yok | Il2CppDumper.exe dosyasının dizinde olduğunu veya antivirüs tarafından silinmediğini kontrol edin. |
| `ERR_DUMPER_EXECUTION_FAILED` | Metadata geçersiz veya bozuk | Stage 3 deşifre çıktısının `0xFAB11BAF` ile başladığını teyit edin. |
| `ERR_DUMPER_TIMEOUT` | İşlem 180 saniyeyi aştı | Sistem disk ve bellek durumunu kontrol edin. |
| `ERR_DUMPER_OUTPUT_TRUNCATED` | dump.cs 1 KB'dan küçük oluştu | Metadata veya binary eşleşmesini kontrol edin. |

### Log Dosyaları
- **Dumper Özel Çıktı Logu:** `workspace/dump/il2cppdumper.log`
- **Aşama Özel Logu:** `workspace/logs/stage_04_04_il2cpp_dump.log`
- **Genel Pipeline Logu:** `workspace/logs/pipeline.log`

---

## 💻 Bağımsız Çalıştırma Örneği
```powershell
python 04_il2cpp_dump/dump.py --so ./workspace/bin/libil2cpp.so --meta ./workspace/bin/global-metadata.dec.dat --out ./workspace/dump
```
