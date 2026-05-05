#!/bin/bash
tail -f logs/piwall.log | grep -i "block\|warn\|alert\|403\|429" --line-buffered
