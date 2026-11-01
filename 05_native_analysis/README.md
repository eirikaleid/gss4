# Stage 5: Native Binary Analysis

Bu aşama Unity oyunlarının native kütüphanelerini (`libunity.so` vb.) saf Python tabanlı bir ELF64 parser ile tarar. Harici bağımlılık gerektirmeden GOT (Global Offset Table) slotlarını ve `.rodata` string ofsetlerini çözer.

## Analiz Edilen Örnek Değerler
- `EGL_SWAP_GOT_FILEOFF`: `eglSwapBuffers` fonksiyonunun `.rela.plt` / GOT tablosundaki dosya ofseti (FPS/Render hook'ları için).
- `SWAPPY_NAME_FILEOFF`: `libswappywrapper` string literalinin dosya ofseti.
- Kurallar (`rules`) ile istenen herhangi bir sembol ya da string ofseti de otomatik olarak çözülebilir.

## Parametreler
- `--lib`: Analiz edilecek ELF dosyası (`libunity.so`).
- `--json`: Çıktı `native.json` dosya yolu.
- `--rules`: Analiz kurallarını içeren JSON (veya profil üzerinden aktarılır).

## Bağımsız Çalıştırma Örneği
```bash
python 05_native_analysis/analyze_native.py --lib ./workspace/bin/libunity.so --json ./workspace/native.json --rules '{"egl_swap_got": true, "swappy_string": "libswappywrapper"}'
```
