#!/bin/bash
cd /home/usern/git/alleports || exit 1

git add -A
git commit -m "auto: $(date '+%Y-%m-%d %H:%M:%S')" >/dev/null 2>&1 || exit 0
git push origin main
