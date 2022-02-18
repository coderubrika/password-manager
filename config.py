from dotenv import dotenv_values
import os

startup_mode = os.getenv('PY_ENV')
config = {startup_mode: dotenv_values(f"{startup_mode}.env")}
