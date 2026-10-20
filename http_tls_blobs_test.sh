#!/bin/sh
# http_tls_blobs_test.sh — использует оба блоба на полную через zenith -3s
set -e

echo "=== Компиляция HTTP blob (cg_httpdl_blob.z) ==="
zenith /media/ruslan/D64ED4304ED40ADF/Users/user/Desktop/b/zenith/zenith/src/cg_httpdl_blob.z -3s -o /tmp/http_blob.elf

echo "=== Компиляция TLS blob (cg_tls_blob.z) ==="
zenith /media/ruslan/D64ED4304ED40ADF/Users/user/Desktop/b/zenith/zenith/src/cg_tls_blob.z -3s -o /tmp/tls_blob.elf

echo "=== Результаты ==="
ls -la /tmp/http_blob.elf /tmp/tls_blob.elf
echo "=== Версия компилятора ==="
zenith --version
