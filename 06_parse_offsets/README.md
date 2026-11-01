# Stage 6: Offset Parsing & Header Generation

Bu aşama `dump.cs` ve `script.json` dosyalarını belirtilen uygulama profili (`profile.json`) doğrultusunda ayrıştırır.

## Yetenekler
- **Profile Dayalı Sembol Seçimi**: Öncelikli sınıflar, izlenecek struct/field alanları, aranacak method anahtar kelimeleri ve TypeInfo regex kalıpları profilden okunur. Hiçbir sınıf ismi script içine hardcode edilmez.
- **Güvenli Sınıf Ayrıştırma**: C# nested sınıfları (`Outer.Inner`), interface'ler, enum'lar ve struct'lar birbirine karışmadan doğru namespace altında toplanır.
- **TypeInfo Sanal Adres -> Dosya Ofseti Çevirisi**: `script.json` içerisindeki TypeInfo VA (Virtual Address) adreslerini `libil2cpp.so` dosyasının `PT_LOAD` segmentlerini tarayarak gerçek dosya ofsetlerine dönüştürür.
- **Çift Çıktı**: Hem C++ `#pragma once` başlık dosyası (`offsets.h`) hem de makine tarafından okunabilir JSON (`offsets.json`) üretir.

## Parametreler
- `--dump`: `dump.cs` dosya yolu.
- `--script`: `script.json` dosya yolu.
- `--so`: `libil2cpp.so` dosya yolu.
- `--profile`: JSON profil dosyası (ör: `profiles/royale.json`).
- `--out`: Çıktı `offsets.h` yolu.
- `--out-json`: Çıktı `offsets.json` yolu.
- `--native-json`: 5. aşamadan gelen `native.json` (opsiyonel).

## Bağımsız Çalıştırma Örneği
```bash
python 06_parse_offsets/parse_offsets.py --dump ./workspace/dump/dump.cs --script ./workspace/dump/script.json --so ./workspace/bin/libil2cpp.so --profile ./profiles/royale.json --out ./workspace/offsets.h --native-json ./workspace/native.json
```
