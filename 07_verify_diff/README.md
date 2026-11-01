# Stage 7: Verification & Diff Gate

Bu aşama üretilen `offsets.h` dosyasının sağlığını denetler, kaynak kodla (`src/`) uyumunu kontrol eder ve eski header ile diff raporu basar.

## Kontroller
1. **Sanity Gates:**
   - Method RVA'larının 4 byte hizalı (ARM64 direktif kuralı) ve binary dosya boyutu içinde olması.
   - TypeInfo göstericilerinin 8 byte hizalı ve dosya boyutu içinde olması.
   - Field ofsetlerinin makul aralıkta (`0 < off < 0x10000`) olması.
2. **Kaynak Kod Uyumu (Zero Undefined Symbols):**
   - `src/` klasöründeki C++ dosyaları taranır. Kodda çağrılan tüm `Offsets::...` sembollerinin yeni header'da tanımlı olduğu doğrulanır. Tanımsız kalan sembol varsa derleme hatasını önlemek için işlem durdurulur.
3. **Diff Raporu:**
   - Eski `offsets.h` ile karşılaştırılarak değişen (`~`), yeni eklenen (`+`) ve silinen (`-`) semboller listelenir.
4. **Güvenli Uygulama (`--apply-to`):**
   - Yeni header hedef dosyaya kopyalanmadan önce eski dosya otomatik olarak tarih etiketiyle `backups/` altına yedeklenir.

## Bağımsız Çalıştırma Örneği
```bash
python 07_verify_diff/verify_diff.py --new ./workspace/offsets.h --old ./src/core/offsets.h --src ./src --apply-to ./src/core/offsets.h
```
