# 🔬 Stage 5: Native Analysis (ELF GOT ve Rodata Analizcisi)

GSS4 pipeline'ının beşinci aşamasıdır. Doğrudan ELF paylaşımlı kütüphanelerini (`libunity.so` vb.) ikili düzeyde inceleyerek Global Offset Table (GOT) ve rodata dizgi ofsetlerini çıkarır.

---

## 🎯 Ne İşe Yarar? (Amaç ve Çalışma Prensibi)
Android üzerinde çalışan oyun modüllerinde ekrana ImGui çizmek veya render döngüsünü yakalamak için `eglSwapBuffers` fonksiyonuna hook atılır. Ayrıca modern Unity sürümlerinde Vulkan Swappy motoru çizimleri bozabilmektedir.
Bu aşama saf Python ELF64 motoruyla:
1. **ELF Başlık ve Segment Analizi:** Program başlıklarını (`PT_LOAD`, `PT_DYNAMIC`) ve relocation tablolarını (`DT_JMPREL`, `SHT_RELA`) tarar.
2. **GOT Slotu Dosya Ofseti:** `eglSwapBuffers` fonksiyonunun dinamik linkleme için ayrılmış GOT slotunun disk dosya ofsetini hesaplar.
3. **Rodata String Taraması:** Bellekte Swappy'yi devredışı bırakmak (data-patching) için `libswappywrapper` stringinin disk adresini saptar.
4. **`native.json` Üretimi:** C++ hook projelerinin doğrudan kullanabileceği yapılandırılmış JSON çıktısı sunar.

---

## 🚀 Neler Yapılabilir? (Geliştirme ve Genişletme Fırsatları)
Bu dal üzerinde şu yeni yetenekler eklenebilir:
- **Çoklu Native Kütüphane Taraması:** Yalnızca `libunity.so` değil, `libmain.so`, `libanogs.so` ve `libGLESv2.so` gibi modülleri de eşzamanlı tarama.
- **ARM64 Gadget / Trampoline Bulucu:** Bellek kancaları ve koruma bypass'ları için uygun ARM64 makine kodu dizilimlerini (`BLR x8`, `RET`, `LDR`) otomatik bulma.
- **Ghidra Headless Decompiler & XREF Bridge:** `05_native_analysis/ghidra/ghidra_bridge.py` ile Ghidra headless analyzer üzerinden C++ pseudocode, string XREF ve vtable çıkarma (veya otomatik yüksek doğruluklu mock fallback).
- **Hex Patch Üreticisi:** Vulkan Swappy'yi bellekte tek komutla kapatmak için hazır hex patch betiği oluşturma.
- **DWARF Debug Sembolleri:** Debug sürümü kütüphanelerde sınıf ve yerel değişken hiyerarşisini doğrudan ELF'ten okuma.

---

## 🛡️ Hata Yönetimi ve Loglama (Error Handling & Logging)

### Hata Kodları ve Çözüm Rehberi
| Hata Kodu | Olası Sebep | Çözüm Önerisi |
|---|---|---|
| `ERR_UNITY_SO_MISSING` | libunity.so dosyası mevcut değil | Stage 2'nin (extract) çalıştığından emin olun. |
| `ERR_ELF_NOT_64BIT` | 32-bit (armeabi-v7a) kütüphane verilmiş | Projede `arm64-v8a` mimarisinin hedeflendiğini teyit edin. |
| `ERR_INVALID_ELF_MAGIC` | Dosya başlığı `0x7F 'E' 'L' 'F'` değil | Dosyanın bozulup bozulmadığını kontrol edin. |

### Log Dosyaları
- **Aşama Özel Logu:** `workspace/logs/stage_05_05_native_analysis.log`
- **Genel Pipeline Logu:** `workspace/logs/pipeline.log`

---

## 💻 Bağımsız Çalıştırma Örneği
```powershell
python 05_native_analysis/analyze_native.py --so ./workspace/bin/libunity.so --out ./workspace/native.json
```
