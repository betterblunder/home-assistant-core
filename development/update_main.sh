#!/usr/bin/env bash
git fetch origin dev
git checkout forked_main
git pull
git merge origin/dev