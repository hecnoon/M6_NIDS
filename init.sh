#!/bin/bash
sudo apt install python3.12 python3.12-venv
python3.12 -m venv .venv
echo "*" > .venv/.gitignore
source .venv/bin/activate
pip3 install -r ./scripts/requirements.txt