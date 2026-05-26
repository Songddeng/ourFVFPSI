#!/usr/bin/env bash
export GIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.git-local"
export GIT_WORK_TREE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "GIT_DIR=$GIT_DIR"
echo "GIT_WORK_TREE=$GIT_WORK_TREE"
echo "Now you can use normal commands like: git status, git add ., git commit, git push"
