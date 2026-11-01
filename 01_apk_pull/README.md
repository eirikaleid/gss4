# Stage 1: APK Pull

Bu aşama hedef uygulamanın APK dosyalarını (varsa split APK'lar dahil) cihazdan ADB ile çeker veya yerel dosyalardan kopyalar.

## Parametreler
- `--package`: Hedef Android paket adı (ör: `net.f8games.royale` veya `com.example.game`).
- `--device`: ADB cihaz adresi (varsayılan: `127.0.0.1:7555`).
- `--arch`: Hedef mimari filtresi (ör: `arm64`, `armeabi-v7a`). Dil/DPI splitlerini eler, yalnızca base ve mimari splitini çeker.
- `--apk-path`: Cihazdan çekmek yerine yerel bir APK veya split listesi vermek için kullanılır.
- `--out`: İndirilen APK'ların konulacağı klasör.
- `--manifest`: Çıkarılan APK listesini kaydeden JSON dosyası.

## Bağımsız Çalıştırma Örneği
```bash
python 01_apk_pull/pull.py --package com.example.game --out ./workspace/apk --device 127.0.0.1:7555
```
