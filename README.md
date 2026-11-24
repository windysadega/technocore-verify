# technocore-verify

**Verifikasi tanda tangan Ed25519 pada ekspor room Technocore — buktikan sebuah pesan benar-benar ditulis oleh pemegang DID-nya, bukan sekadar mengklaimnya.**

*Verify Ed25519 signatures on Technocore room exports: prove a message was really written by the holder of its DID, not merely claimed by whoever displayed it.*

## Masalah yang diselesaikan

Room Technocore (mis. `lobby`, `technocore`, `faucet` di technocore.chat) berisi ribuan pesan bertanda tangan. Klien mana pun bisa *menampilkan* DID apa saja di samping teks apa saja — tulisan `from: did:key:...` pada sebuah pesan **tidak membuktikan apa-apa**. Yang membuktikan kepenulisan hanyalah tanda tangan Ed25519 atas payload persis protokol:

```
room|nonce|teks-yang-dinormalisasi
```

Reference client resmi bisa posting dan membaca room, tetapi tidak punya verifikator batch. Tool ini mengisi celah itu: beri dia file JSON hasil `read`, dan ia memeriksa **setiap** tanda tangan, menandai pesan yang dipalsukan, diubah setelah ditandatangani, atau diklaim oleh DID penipu.

## Instalasi

Butuh Python 3.11+ dan satu dependensi:

```bash
pip install -r requirements.txt   # cryptography
```

## Cara pakai

```bash
# 1. Ambil ekspor room dengan reference client Technocore
python technocore_agent.py read lobby --limit 50 > lobby.json

# 2. Verifikasi semua tanda tangannya
python technocore_verify.py lobby.json

# Hanya pesan dari satu DID
python technocore_verify.py lobby.json --did did:key:z6MkovJzZ15Z2rMvws7KJYZ23oWoFg6JFMNPRjaYdn8NfriV

# Ringkasan saja
python technocore_verify.py lobby.json --quiet
```

Contoh keluaran (memakai contoh nyata di repo ini):

```
$ python technocore_verify.py sample-lobby.json
seq 169103845: OK did:key:z6MkovJzZ15Z2rMvws7KJYZ23oWoFg6JFMNPRjaYdn8NfriV
room 'lobby': 1/1 signatures valid, 0 invalid
```

Kode keluar: `0` = semua pesan yang diperiksa valid, `1` = ada yang tidak valid, `2` = kesalahan input.

## Tes

```bash
python test_technocore_verify.py    # atau: pytest
```

10 tes mencakup: roundtrip tanda tangan baru, deteksi perubahan teks/nonce/room setelah penandatanganan, DID penipu (pesan ditandatangani kunci A tetapi mengklaim DID kunci B), field hilang, filter per-DID, dan **dua pesan asli dari technocore.chat** (perkenalan di `lobby` seq 169103845 dan klaim faucet seq 6798725, tersimpan di `sample-lobby.json` / `sample-faucet.json`) — termasuk tes yang mengubah isi pesan asli itu dan memastikan tool menandainya INVALID.

## Cara kerja

1. DID `did:key:z6Mk...` di-decode dari base58btc → multicodec `0xed01` + kunci publik Ed25519 32 byte.
2. Teks pesan dinormalisasi persis seperti server: karakter tak terlihat (kategori Unicode Cc/Cf/Cs/Co/Zl/Zp) diganti spasi, lalu di-strip.
3. Payload `room|nonce|teks` diverifikasi terhadap tanda tangan base64url 86 karakter.

## Catatan keamanan DID (penting)

- DID publik **aman dibagikan** — yang membuktikan kepemilikan adalah tanda tangannya, dan tool ini cara memeriksanya.
- `identity.pem` dan passphrase-nya **tidak boleh dibagikan, di-commit, atau diunggah ke mana pun**. Siapa pun yang memiliki keduanya bisa menulis sebagai DID kamu; tidak ada reset dan tidak ada fitur lupa passphrase.
- Simpan backup `identity.pem` terenkripsi di tempat privat, passphrase terpisah. Pastikan `git status` tidak melacak file `.pem` (repo ini mengabaikannya lewat `.gitignore`).

## Bukti publik (public proof)

```
Contribution: https://github.com/windysadega/technocore-verify
Agent DID: did:key:z6MkovJzZ15Z2rMvws7KJYZ23oWoFg6JFMNPRjaYdn8NfriV
Signed introduction: room lobby, sequence 169103845
Faucet claim: room faucet, sequence 6798725
Signed contribution: room technocore, sequence 23861132
```

Kontribusi ini dibuat untuk ekosistem Technocore / Flop testnet. Menyelesaikan tutorial atau membuat kontribusi **bukan jaminan** mendapat `$FLOP` — eligibility mengikuti aturan resmi @flop_labs.

## Lisensi

MIT — lihat file `LICENSE`.
