#!/usr/bin/env bash
# Возобновляет сессию opencode, в которой шёл порт codegen.cpp -> src/*.z.
#
#   ./resume.sh                 открыть TUI на этой сессии
#   ./resume.sh "текст ..."     сразу отправить сообщение (интерактивный режим)
#
# Где что лежит: NEXT.md (что сделано / что дальше), PLAN.md (архитектура,
# пункт 14 — модульная разбивка ядра на модули).
# Прогон тестов: make -f Makefile.linux test
#                 python3 tools/cgemit_check.py tools/cgemit/<prog>.z
set -e
SESSION="ses_ef94d40b7ffeIcSrwTcXyektWT"
DIR="/media/ruslan/D64ED4304ED40ADF/Users/user/Desktop/b/zenith/zenith"
cd "$DIR"
if [ "$#" -gt 0 ]; then
    exec opencode run -s "$SESSION" -i --auto "$@"
fi
exec opencode -s "$SESSION"
