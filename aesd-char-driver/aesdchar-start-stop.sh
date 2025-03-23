#!/bin/sh


case "$1" in
    start)
        echo "Loading aesdchar kernel module"
        aesdchar_load
        ;;
    stop)
        echo "Unloading aesdchar kernel module"
        aesdchar_unload
        ;;
    restart)
        echo "Reloading aesdchar kernel module"
        aesdchar_unload
        aesdchar_load
        ;;
    *)
        echo "Usage $0 {start | stop | restart}"
    exit 1
esac