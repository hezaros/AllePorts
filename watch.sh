#!/bin/bash
WATCH_DIR=/home/usern/git/alleports

inotifywait -m -e close_write,create,delete,move "$WATCH_DIR" |
while read -r path action file; do
  "$WATCH_DIR/auto-push.sh"
done
