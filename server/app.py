#!/usr/bin/env python3
"""
Launcher do nó de chat P2P.

Uso:
    python app.py --port 8000
    python app.py --port 8001 --peers ws://localhost:8000/ws/peer

Cuida sozinho de criar o venv e instalar/atualizar as dependências
(mesmo mecanismo do projeto anterior) e depois inicia node_server.py
com os argumentos passados.
"""
# Ghost Protocol
# Copyright (c) 2026 GProtocolLabs
#
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.
#
# https://github.com/GProtocolLabs/ghost-protocol


import os
import sys
import json
import subprocess
import hashlib
import venv as venv_module

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_DIR = os.path.join(BASE_DIR, "venv")
REQUIREMENTS_FILE = os.path.join(BASE_DIR, "requirements.txt")
STATE_FILE = os.path.join(VENV_DIR, ".requirements_hash")

IS_WINDOWS = os.name == "nt"
VENV_PYTHON = os.path.join(
    VENV_DIR, "Scripts" if IS_WINDOWS else "bin", "python.exe" if IS_WINDOWS else "python"
)


def log(msg):
    print(f"[setup] {msg}", flush=True)


def running_inside_target_venv():
    try:
        return os.path.samefile(sys.executable, VENV_PYTHON)
    except OSError:
        return False


def create_venv_if_missing():
    if os.path.isdir(VENV_DIR) and os.path.exists(VENV_PYTHON):
        return
    log(f"Ambiente virtual não encontrado. Criando em {VENV_DIR} ...")
    venv_module.EnvBuilder(with_pip=True, upgrade_deps=True).create(VENV_DIR)
    log("Ambiente virtual criado.")


def requirements_hash():
    with open(REQUIREMENTS_FILE, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def read_stored_hash():
    if not os.path.exists(STATE_FILE):
        return None
    with open(STATE_FILE, "r") as f:
        return f.read().strip()


def write_stored_hash(value):
    with open(STATE_FILE, "w") as f:
        f.write(value)


def pip_install_requirements():
    log("Instalando/atualizando dependências do requirements.txt ...")
    subprocess.run([VENV_PYTHON, "-m", "pip", "install", "--upgrade", "pip"], check=True)
    subprocess.run([VENV_PYTHON, "-m", "pip", "install", "-r", REQUIREMENTS_FILE], check=True)
    write_stored_hash(requirements_hash())
    log("Dependências prontas.")


def dependencies_need_install():
    current_hash = requirements_hash()
    stored_hash = read_stored_hash()
    if stored_hash != current_hash:
        return True
    check_script = (
        "import importlib.util as u, sys; "
        "mods = ['fastapi', 'uvicorn', 'websockets']; "
        "missing = [m for m in mods if u.find_spec(m) is None]; "
        "sys.exit(1 if missing else 0)"
    )
    result = subprocess.run([VENV_PYTHON, "-c", check_script])
    return result.returncode != 0


def check_for_outdated_packages():
    log("Verificando pacotes desatualizados no PyPI ...")
    try:
        result = subprocess.run(
            [VENV_PYTHON, "-m", "pip", "list", "--outdated", "--format=json"],
            check=True, capture_output=True, text=True,
        )
        outdated = json.loads(result.stdout or "[]")
    except Exception as e:
        log(f"Não foi possível checar atualizações agora ({e}). Prosseguindo.")
        return
    if not outdated:
        log("Tudo já está na versão mais recente.")
        return
    names = [pkg["name"] for pkg in outdated]
    log(f"Pacotes desatualizados encontrados: {', '.join(names)}. Atualizando...")
    subprocess.run([VENV_PYTHON, "-m", "pip", "install", "--upgrade", *names], check=True)
    log("Pacotes atualizados.")


def relaunch_inside_venv():
    log("Reiniciando dentro do ambiente virtual...")
    try:
        sys.exit(subprocess.call([VENV_PYTHON, os.path.abspath(__file__), *sys.argv[1:]]))
    except Exception as e:
        log(f"Falha ao reiniciar no venv ({e}). Recriando ambiente virtual...")
        import shutil
        shutil.rmtree(VENV_DIR, ignore_errors=True)
        create_venv_if_missing()
        pip_install_requirements()
        sys.exit(subprocess.call([VENV_PYTHON, os.path.abspath(__file__), *sys.argv[1:]]))


def main():
    create_venv_if_missing()

    if not running_inside_target_venv():
        if dependencies_need_install():
            pip_install_requirements()
        relaunch_inside_venv()
        return

    if dependencies_need_install():
        pip_install_requirements()

    if "--update-check" in sys.argv:
        check_for_outdated_packages()
        sys.argv.remove("--update-check")

    log("Ambiente OK. Iniciando nó de chat...")
    sys.path.insert(0, BASE_DIR)
    import node_server
    node_server.main()


if __name__ == "__main__":
    main()
