# gravitator-onweb

JPCERT/CC が公開しているフィッシング URL リストをもとに、Pi-hole 用のブロックリストを自動生成するプロジェクトです。

## 概要
- **ソース**: [JPCERTCC/phishurl-list](https://github.com/JPCERTCC/phishurl-list)
- **更新頻度**: 1日1回 (GitHub Actions)
- **配信URL**: `https://raw.githubusercontent.com/pju-hoge/gravitator-onweb/main/pihole_blocklist.txt`

## 使い方
Pi-hole のアドリスト（Adlists）に上記の Raw URL を追加してください。
