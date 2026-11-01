# Stage 4: IL2CPP Dumper

Bu aşama `Il2CppDumper.exe` aracını çalıştırarak deşifre edilmiş metadata ile `libil2cpp.so`'yu analiz eder.

## Üretilen Çıktılar
- `dump.cs`: Tüm C# sınıfları, method RVA'ları, field ofsetleri ve struct tanımları.
- `script.json`: Ghidra/IDA/Python scriptleri için method, string ve TypeInfo sanal adreslerini (VA) içeren harita.
- `il2cpp.h`: C++ struct ve type tanımları.
- `stringliteral.json`: String literal sabitleri tablosu.
- `dump_manifest.json`: Çıktı dosya boyutlarını ve işlem süresini içeren özet rapor.

## Parametreler
- `--so`: Hedef `libil2cpp.so` dosyası.
- `--metadata`: Deşifre edilmiş `global-metadata.dec.dat` dosyası.
- `--out`: Dump çıktılarının yazılacağı dizin.
- `--dumper`: `Il2CppDumper.exe` yolu (varsayılan: `../tools/Il2CppDumper/Il2CppDumper.exe`).

## Bağımsız Çalıştırma Örneği
```bash
python 04_il2cpp_dump/dump.py --so ./workspace/bin/libil2cpp.so --metadata ./workspace/bin/global-metadata.dec.dat --out ./workspace/dump
```
