# 🔓 Stage 3: Decrypt Metadata (Metadata Şifre Çözücü)

GSS4 pipeline'ının üçüncü aşamasıdır. Şifrelenmiş veya tahrif edilmiş `global-metadata.dat` dosyasını `Il2CppDumper` aracının okuyabileceği standart biçime dönüştürür.

---

## 🎯 Ne İşe Yarar? (Amaç ve Çalışma Prensibi)
Çoğu popüler Unity mobil oyunu, tersine mühendisleri engellemek için metadata dosyasının başlığını (header) bozar veya gövde bölümlerini XOR rampa gibi algoritmalarla şifreler (örneğin GUPS koruması).
Bu aşama:
1. **Otomatik Algılama (`auto`):** Dosya başlığını okur; eğer standart `0xFAB11BAF` IL2CPP magic değeri varsa şifresiz olduğunu anlayıp `passthrough` stratejisini seçer. Başlık şifreliyse uygun koruma çözücüyü (örn: `gups`) devreye sokar.
2. **Tak-Çıkar Strateji Desteği:** `strategies/` klasöründeki bağımsız modülleri otomatik keşfeder.
3. **Çıktı Üretimi:** `global-metadata.dec.dat` (temiz dosya) ve hangi tabloların nasıl çözüldüğünü gösteren `gups_report.json` raporunu üretir.

---

## 🚀 Neler Yapılabilir? (Geliştirme ve Genişletme Fırsatları)
Bu dal üzerinde şu yeni yetenekler eklenebilir:
- **Yeni Koruma Stratejileri Eklemek:** `strategies/` klasörüne `yeni_koruma.py` ekleyerek kod değiştirmeden sisteme yeni deşifre motoru ekleme:
  ```python
  def run(in_path: str, out_path: str, **kwargs) -> dict:
      # Özel algoritmanız...
      return {"status": "success"}
  ```
- **Shannon Entropi Analizi:** Dosyayı blok blok inceleyip yüksek entropili (şifreli/sıkıştırılmış) ve düşük entropili (düz metin) alanları ısı haritasıyla çıkaran otomatik haritalayıcı.
- **Canlı Bellek (Live Memory) Fallback'ı:** Statik kırılamayan korumalarda oyunu emülatörde açıp `/proc/pid/mem` üzerinden belleğe yüklenen deşifre edilmiş metadata'yı canlı çekme.
- **Çok İş Parçacıklı (Multiprocessing) Brute-Force:** Karmaşık XOR / rotasyon anahtarlarını tüm CPU çekirdeklerine dağıtarak saniyeler içinde çözme.

---

## 🛡️ Hata Yönetimi ve Loglama (Error Handling & Logging)

### Hata Kodları ve Çözüm Rehberi
| Hata Kodu | Olası Sebep | Çözüm Önerisi |
|---|---|---|
| `ERR_INPUT_METADATA_NOT_FOUND` | Girdi dosyası mevcut değil | Stage 2'nin (extract) çalıştığından emin olun. |
| `ERR_UNKNOWN_STRATEGY` | Belirtilen strateji `strategies/` içinde yok | `strategies/` klasöründeki modül adını kontrol edin. |
| `ERR_DECRYPTION_FAILED` | XOR parametreleri veya section layout değişmiş | Yeni versiyon güncellemesinde değişen header/body delta değerlerini analiz edin. |

### Log Dosyaları
- **Aşama Özel Logu:** `workspace/logs/stage_03_03_decrypt_metadata.log`
- **Genel Pipeline Logu:** `workspace/logs/pipeline.log`

---

## 💻 Bağımsız Çalıştırma Örneği
```powershell
python 03_decrypt_metadata/decrypt.py --in ./workspace/bin/global-metadata.dat --out ./workspace/bin/global-metadata.dec.dat --strategy auto
```
