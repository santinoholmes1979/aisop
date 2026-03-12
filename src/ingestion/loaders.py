from pathlib import Path
import pandas as pd

DATA_RAW_DIR = Path("data/raw")

def load_auth_events():
    return pd.read_csv(DATA_RAW_DIR / "auth_events.csv")

def load_process_events():
    return pd.read_csv(DATA_RAW_DIR / "process_events.csv")

def load_network_events():
    return pd.read_csv(DATA_RAW_DIR / "network_events.csv")

def load_registry_events():
    return pd.read_csv(DATA_RAW_DIR / "registry_events.csv")