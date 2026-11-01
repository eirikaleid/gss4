# Stage 3: Metadata Decryption

Unity IL2CPP oyunlarında `global-metadata.dat` dosyası kimi zaman doğrudan plaintext (standart `0xFAB11BAF` magic), kimi zaman ise anti-cheat korumaları (örneğin GUPS) tarafından şifrelenmiştir.

Bu aşama modüler bir strateji mimarisi (`strategies/`) kullanır:
1. `auto`: Dosya başlığını analiz eder. Düz metin ise doğrudan aktarır (`passthrough`). Şifreli ise GUPS brute-force ve section solver (`gups`) devreye sokar.
2. `passthrough`: Korumasız standart Unity oyunları için doğrudan doğrulayıp kopyalar.
3. `gups`: GUPS korumalı oyunlar için bilinen profil ve genel kaba kuvvet DFS arama algoritmalarıyla metadata başlığını ve bölümlerini çözer.

## Yeni Bir Şifre Çözücü Nasıl Eklenir?
`strategies/` altına `yeni_koruma.py` adında yeni bir dosya ekleyip `run(in_path, out_path)` fonksiyonunu tanımlayarak herhangi bir özel anti-cheat şifreleme algoritması bu sisteme tak-çıkar şekilde entegre edilebilir.

## Parametreler
- `--in`: Girdi `global-metadata.dat` dosyası.
- `--out`: Çıktı deşifre edilmiş dosya yolu (`global-metadata.dec.dat`).
- `--strategy`: `auto`, `gups` veya `passthrough`.
- `--report`: JSON formatında ayrıntılı deşifre raporu.
- `--words`: Deşifrenin doğruluğunu teyit etmek için aranan oyun tanımlayıcıları (identifier whitelist).

## Bağımsız Çalıştırma Örneği
```bash
python 03_decrypt_metadata/decrypt.py --in ./workspace/bin/global-metadata.dat --out ./workspace/bin/global-metadata.dec.dat --strategy auto
```
