"""
Pós-deploy: inicializa usuários padrão no banco de dados do Render.
Executado automaticamente após o build.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

try:
    from init_db import main as init_main
    init_main()
except Exception as e:
    print(f"Render init warning: {e}")
