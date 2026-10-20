#!/bin/sh
# install_zenith.sh — компилирует зенит из src/main.z (-3s -3r -3d, без --mix)
# и ставит в /usr/local/bin с добавлением в PATH. sudo пароль: 12
set -e

SUDO_PASS="12"

# Каталог скрипта = корень репозитория (скрипт лежит рядом с Makefile.linux).
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
BOOT="$SRC_DIR/build/linux/zenith"
MAIN="$SRC_DIR/src/main.z"

# Драйвер пишет ELF РЯДОМ с -o, добавляя расширение: -o build/zen/main_install
# даёт build/zen/main_install.elf. База и артефакт — разные пути.
OUT_BASE="$SRC_DIR/build/zen/main_install"
OUT_ELF="$OUT_BASE.elf"
LOG="$SRC_DIR/build/zen/main_install.log"
DEST="/usr/local/bin/zenith"

if [ ! -x "$BOOT" ]; then
    echo "install_zenith: бутстрап-компилятор $BOOT не найден." >&2
    echo "install_zenith: соберите его: make -f Makefile.linux" >&2
    exit 1
fi
if [ ! -f "$MAIN" ]; then
    echo "install_zenith: исходник $MAIN не найден." >&2
    exit 1
fi

sudo_cmd() {
    echo "$SUDO_PASS" | sudo -S sh -c "$1"
}

# Пересобираем, если установленный бинарник старше ЛЮБОГО .z-исходника:
# пайплайн склеивает src/*.z и selfhost/*.z (use/include), а не только main.z,
# поэтому судить по mtime одного main.z нельзя — иначе правка cg_*.z
# останется незамеченной и поставится устаревший компилятор.
NEED_REBUILD=1
if [ -x "$DEST" ]; then
    NEWER="$(find "$SRC_DIR/src" "$SRC_DIR/selfhost" -name '*.z' -newer "$DEST" -print -quit 2>/dev/null || true)"
    if [ -n "$NEWER" ]; then
        echo "install_zenith: исходники новее $DEST — пересобираю (например, $NEWER)"
    else
        echo "install_zenith: $DEST актуален (все .z старше установленного бинарника)"
        NEED_REBUILD=0
    fi
else
    echo "install_zenith: $DEST отсутствует — собираю заново..."
fi

if [ "$NEED_REBUILD" = "1" ]; then
    mkdir -p "$SRC_DIR/build/zen"
    echo "install_zenith: компилирую $MAIN с флагами -3s -3r -3d (без --mix)..."
    if ! "$BOOT" "$MAIN" -3s -3r -3d -o "$OUT_BASE" > "$LOG" 2>&1; then
        echo "install_zenith: компиляция не удалась:" >&2
        tail -30 "$LOG" >&2
        exit 1
    fi
    if [ ! -f "$OUT_ELF" ]; then
        echo "install_zenith: компилятор не создал $OUT_ELF (ELF появляется рядом с -o):" >&2
        tail -30 "$LOG" >&2
        exit 1
    fi
    chmod +x "$OUT_ELF"

    echo "install_zenith: копирую $OUT_ELF -> $DEST"
    if [ -w /usr/local/bin ] || [ -w /usr ]; then
        cp "$OUT_ELF" "$DEST"
    else
        sudo_cmd "cp '$OUT_ELF' '$DEST'"
    fi
    sudo_cmd "chmod +x '$DEST'"
else
    echo "install_zenith: сборка не требуется"
fi

# PATH уже содержит /usr/local/bin на большинстве систем, но проверим:
case ":$PATH:" in
    *":/usr/local/bin:"*) ;;
    *)
        echo "install_zenith: /usr/local/bin нет в PATH. Добавляю в ~/.bashrc и ~/.profile"
        for rc in "$HOME/.bashrc" "$HOME/.profile"; do
            if [ -f "$rc" ] && ! grep -q '/usr/local/bin' "$rc" 2>/dev/null; then
                echo 'export PATH="/usr/local/bin:$PATH"' >> "$rc"
            fi
        done
        ;;
esac

echo "install_zenith: проверяю..."
if command -v zenith >/dev/null 2>&1; then
    echo "install_zenith: OK. zenith установлен: $(command -v zenith)"
    zenith --version
else
    echo "install_zenith: ВНИМАНИЕ: zenith не найден в PATH после установки." >&2
    echo "install_zenith: Перезапустите терминал или выполните: export PATH=\"/usr/local/bin:\$PATH\"" >&2
    exit 1
fi

echo "install_zenith: готово."
