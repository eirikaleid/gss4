# GSS4 Universal Offset Extraction Pipeline

GSS4, Unity IL2CPP oyun ve uygulamaları için tersine mühendislik (Reverse Engineering) offset çıkarma süreçlerini tamamen otomatikleştiren, modüler ve profile dayalı evrensel bir pipeline sistemidir.

Herhangi bir Unity IL2CPP uygulamasından (şifreli/anti-cheat korumalı olsun veya olmasın) method RVAlarını, field ofsetlerini, TypeInfo göstericilerini ve native sembolleri otomatik olarak çeker, doğrular ve C++ header / JSON çıktıları üretir.

---

## 📁 Mimari ve Klasör Yapısı

Her aşama bağımsız bir klasör içinde izole edilmiştir. Tek başlarına CLI ile çalıştırılabilir veya `run_pipeline.py` üzerinden uçtan uca koşturulabilir:

```
C:\Users\MonsterTesla\Desktop\gss4\
├── 01_apk_pull/               # 1. Aşama: ADB üzerinden veya yerel dosyalardan APK çekme
│   ├── pull.py
│   └── README.md
├── 02_extract/                # 2. Aşama: ZipFile ile libil2cpp, libunity ve metadata ayıklama
│   ├── extract.py
│   └── README.md
├── 03_decrypt_metadata/       # 3. Aşama: Modüler şifre çözücü (GUPS, passthrough, custom)
│   ├── decrypt.py
│   ├── strategies/
│   │   ├── gups.py            # GUPS XOR brute-force & section layout solver
│   │   └── passthrough.py     # Standart plaintext metadata aktarıcı
│   └── README.md
├── 04_il2cpp_dump/            # 4. Aşama: Il2CppDumper koşturucu & çıktı tazeliği kontrolü
│   ├── dump.py
│   └── README.md
├── 05_native_analysis/        # 5. Aşama: libunity / ELF GOT slotları ve rodata string analizi
│   ├── analyze_native.py
│   └── README.md
├── 06_parse_offsets/          # 6. Aşama: Profil odaklı dump.cs & script.json parser -> offsets.h
│   ├── parse_offsets.py
│   └── README.md
├── 07_verify_diff/            # 7. Aşama: Sanity gate, src/ tanımsız sembol kontrolü, diff & backup
│   ├── verify_diff.py
│   └── README.md
├── profiles/                  # Uygulama Profilleri (JSON)
│   ├── royale.json            # Royale / Mobware hazır profili
│   └── template_generic.json  # Yeni oyunlar için şablon profil
├── tools/                     # Taşınabilir araçlar
│   └── Il2CppDumper/
│       ├── Il2CppDumper.exe
│       └── config.json        (RequireAnyKey: false - headless)
├── src/                       # Hedef kod klasörü
│   └── core/
│       └── offsets.h          (Üretilen C++ başlık dosyası)
├── run_pipeline.py            # Ana Python Orchestrator (Cross-Platform)
├── run.ps1                    # Windows PowerShell Wrapper
└── README.md
```

---

## 🚀 Hızlı Başlangıç

### 1. Varsayılan Uygulama (Royale) ile Çalıştırma
```powershell
# Sadece test et ve diff raporunu incele (src/core/offsets.h değişmez):
python run_pipeline.py --profile royale

# Doğrulamadan sonra projeye uygula (otomatik yedek alarak):
python run_pipeline.py --profile royale --apply
```
Veya PowerShell wrapper ile:
```powershell
.\run.ps1 -Profile royale -Apply
```

### 2. Yerel APK Dosyası Kullanarak Çalıştırma (ADB Olmadan)
```powershell
python run_pipeline.py --profile royale --apk C:\Downloads\base.apk C:\Downloads\split_config.arm64_v8a.apk
```

### 3. Belirli Bir Aşamayı Bağımsız Çalıştırma
Tüm pipeline'ı baştan başlatmak yerine sadece ilgilendiğiniz aşamayı koşturabilirsiniz:
```powershell
# Yalnızca 6. aşamayı (parse) çalıştır:
python run_pipeline.py --profile royale --stage 6

# 4. aşamadan (dump) sonrasını çalıştır:
python run_pipeline.py --profile royale --from-stage 4
```

---

## 🎮 Yeni Bir Uygulama / Oyun Eklemek

Farklı bir oyun veya uygulama için tek yapmanız gereken `profiles/` klasörüne yeni bir JSON profili eklemektir:

1. `profiles/template_generic.json` dosyasını kopyalayıp `profiles/oyun_adi.json` yapın.
2. Paket adını, mimariyi ve ilgilendiğiniz sınıfları tanımlayın:
   ```json
   {
     "name": "yeni_oyun",
     "package": "com.developer.game",
     "arch": "arm64-v8a",
     "decrypt_strategy": "passthrough",
     "priority_classes": {
       "PlayerController": { "Update": 0, "get_transform": 0 },
       "EnemyManager": { "get_Instance": 0 }
     },
     "field_classes": [ "PlayerController", "EnemyManager" ],
     "typeinfo_required": [ "PlayerController", "EnemyManager" ]
   }
   ```
3. Pipeline'ı yeni profille başlatın:
   ```powershell
   python run_pipeline.py --profile yeni_oyun --apply
   ```

---

## 🔒 Güvenlik & Yedekleme Garantisi
- **Zero Undefined Symbols:** 7. aşama, `src/` klasöründeki C++ kodlarını otomatik tarar. Eğer projede kullanılan herhangi bir `Offsets::...` sabiti yeni header'da eksikse işlemi derhal durdurur ve derleme hatasını engeller.
- **Tarihli Yedek:** `--apply` bayrağı verildiğinde mevcut `offsets.h` üzerine yazılmadan önce `backups/offsets.h.<tarih_saat>` şeklinde tam yedek alınır.
