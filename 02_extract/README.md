# Stage 2: Binary & Metadata Extraction

Bu aşama APK paket(ler)inin içini Python'ın `zipfile` modülü ile tarar. Harici Java ya da `apktool` gerektirmeden son derece hızlı bir şekilde native kütüphaneleri ve IL2CPP metadata dosyasını ayıklar.

## Çıkarılan Dosyalar
- `libil2cpp.so`: Hedef mimarinin (`arm64-v8a`, `armeabi-v7a` vb.) ana IL2CPP native kütüphanesi.
- `global-metadata.dat`: Unity C# metadata veri tabanı.
- `libunity.so`: Varsa Unity engine kütüphanesi (native analiz aşamasında kullanılır).

## Parametreler
- `--apks`: APK dosya yolları.
- `--manifest`: 1. aşamanın ürettiği `apk_manifest.json` dosyası.
- `--out`: Çıkarılan dosyaların kaydedileceği klasör.
- `--arch`: Hedef ABI (varsayılan: `arm64-v8a`).
- `--extra-libs`: Çıkarılmak istenen ek shared library isimleri.

## Bağımsız Çalıştırma Örneği
```bash
python 02_extract/extract.py --manifest ./workspace/apk/apk_manifest.json --out ./workspace/bin --arch arm64-v8a
```
