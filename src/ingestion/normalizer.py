import pandas as pd
from src.ingestion.schema import NORMALIZED_EVENT_COLUMNS

def normalize_auth_events(df):
    normalized = pd.DataFrame()

    normalized["timestamp"] = df["timestamp"]
    normalized["event_type"] = "auth"
    normalized["user"] = df["user"]
    normalized["host"] = df["host"]
    normalized["source_ip"] = df["source_ip"]

    normalized["destination_ip"] = None
    normalized["destination_port"] = None
    normalized["process_name"] = None
    normalized["parent_process"] = None
    normalized["command_line"] = None

    normalized["action"] = df["action"]
    normalized["status"] = df["status"]

    normalized["action"] = df["action"]
    normalized["status"] = df["status"]

    normalized["registry_path"] = None
    normalized["registry_value"] = None

    normalized["raw_source"] = "auth_events"

    return normalized[NORMALIZED_EVENT_COLUMNS]


def normalize_process_events(df):
    normalized = pd.DataFrame()

    normalized["timestamp"] = df["timestamp"]
    normalized["event_type"] = "process"
    normalized["user"] = df["user"]
    normalized["host"] = df["host"]

    normalized["source_ip"] = None
    normalized["destination_ip"] = None
    normalized["destination_port"] = None

    normalized["process_name"] = df["process_name"]
    normalized["parent_process"] = df["parent_process"]
    normalized["command_line"] = df["command_line"]

    normalized["action"] = "process_start"
    normalized["status"] = None

    normalized["action"] = "process_start"
    normalized["status"] = None

    normalized["registry_path"] = None
    normalized["registry_value"] = None

    normalized["raw_source"] = "process_events"

    return normalized[NORMALIZED_EVENT_COLUMNS]


def normalize_network_events(df):
    normalized = pd.DataFrame()

    normalized["timestamp"] = df["timestamp"]
    normalized["event_type"] = "network"
    normalized["user"] = df["user"]
    normalized["host"] = df["host"]

    normalized["source_ip"] = None
    normalized["destination_ip"] = df["destination_ip"]
    normalized["destination_port"] = df["destination_port"]

    normalized["process_name"] = None
    normalized["parent_process"] = None
    normalized["command_line"] = None

    normalized["action"] = df["action"]
    normalized["status"] = df["protocol"]

    normalized["action"] = df["action"]
    normalized["status"] = df["protocol"]

    normalized["registry_path"] = None
    normalized["registry_value"] = None

    normalized["raw_source"] = "network_events"

    return normalized[NORMALIZED_EVENT_COLUMNS]

def normalize_registry_events(df):
    normalized = pd.DataFrame()

    normalized["timestamp"] = df["timestamp"]
    normalized["event_type"] = "registry"
    normalized["user"] = df["user"]
    normalized["host"] = df["host"]

    normalized["source_ip"] = None
    normalized["destination_ip"] = None
    normalized["destination_port"] = None

    normalized["process_name"] = None
    normalized["parent_process"] = None
    normalized["command_line"] = None

    normalized["action"] = df["event_type"]
    normalized["status"] = None

    normalized["registry_path"] = df["registry_path"]
    normalized["registry_value"] = df["registry_value"]

    normalized["raw_source"] = "registry_events"

    return normalized[NORMALIZED_EVENT_COLUMNS]


def combine_normalized_events(auth_df, process_df, network_df, registry_df):

    combined = pd.concat(
        [
            normalize_auth_events(auth_df),
            normalize_process_events(process_df),
            normalize_network_events(network_df),
            normalize_registry_events(registry_df),
        ],
        ignore_index=True,
    )

    combined["timestamp"] = pd.to_datetime(combined["timestamp"], errors="coerce")

    combined = combined.sort_values("timestamp").reset_index(drop=True)

    return combined