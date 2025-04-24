import os
import sys
import argparse
import sqlite3
import yaml
from pathlib import Path
import logging
from dotenv import load_dotenv
from supabase import create_client, Client

# --- Load Environment Variables ---
load_dotenv() 

# --- Constants ---
DB_FILENAME = 'rules_th.db' 

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Database Functions ---

def connect_db(db_file):
    """Connects to the SQLite database."""
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        logging.info(f"Connected to local SQLite database: {db_file}")
    except sqlite3.Error as e:
        logging.error(f"Error connecting to local SQLite database: {e}")
    return conn

def connect_supabase():
    """Connects to the Supabase project using environment variables."""
    url = os.getenv("SUPABASE_URL")
    # Prefer ANON key now that RPC function handles privileges
    key = os.getenv("SUPABASE_ANON_KEY") 
    key_type = "ANON_KEY"
    if not key:
        logging.warning("SUPABASE_ANON_KEY not found, trying SUPABASE_SERVICE_ROLE_KEY (less recommended).")
        key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        key_type = "SERVICE_ROLE_KEY"

    if not url or not key:
        logging.error(f"SUPABASE_URL and either SUPABASE_ANON_KEY or SUPABASE_SERVICE_ROLE_KEY must be set for Supabase destination.")
        return None
    
    try:
        supabase_client: Client = create_client(url, key)
        logging.info(f"Connected to Supabase project at: {url} using {key_type}.")
        if key_type == "SERVICE_ROLE_KEY":
             logging.warning("SECURITY WARNING: Connected using SUPABASE_SERVICE_ROLE_KEY. Consider using ANON_KEY with the custom RPC function.")
        return supabase_client
    except Exception as e:
        logging.error(f"Error connecting to Supabase: {e}")
        return None


def create_sqlite_table_if_not_exists(conn, table_name):
    """Creates the specified table in the local SQLite DB if it doesn't exist."""
    create_table_sql = f"""
    CREATE TABLE IF NOT EXISTS "{table_name}" (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      guid TEXT UNIQUE NOT NULL, -- Added NOT NULL based on DB function
      name TEXT,
      "query" TEXT,
      description TEXT,
      ms_guid TEXT DEFAULT NULL,
      ms_armid TEXT DEFAULT NULL,
      tactics TEXT DEFAULT NULL,
      techniques TEXT DEFAULT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        cursor = conn.cursor()
        cursor.execute(create_table_sql)
        conn.commit()
        logging.info(f"[SQLite] Table '{table_name}' checked/created successfully.")
    except sqlite3.Error as e:
        logging.error(f"[SQLite] Error creating table '{table_name}': {e}")

# Removed Python function for Supabase table creation - now handled by DB RPC call in main()

def call_supabase_create_table_rpc(supabase_client: Client, table_name: str):
    """Calls the custom Supabase RPC function to create the table if it doesn't exist."""
    logging.info(f"[Supabase] Calling RPC function 'create_table_if_not_exists' for table '{table_name}'.")
    try:
        # Call the specific RPC function created in the database
        response = supabase_client.rpc('create_table_if_not_exists', {'table_name_param': table_name}).execute()
        
        # Basic check - Supabase RPC errors might need more specific handling depending on function definition
        # if response.error:
        #     logging.error(f"[Supabase] RPC call 'create_table_if_not_exists' failed: {response.error.message}")
        # else:
        #     logging.info(f"[Supabase] RPC call 'create_table_if_not_exists' executed for table '{table_name}'.")
        
        # Log success attempt
        logging.info(f"[Supabase] RPC call 'create_table_if_not_exists' executed for table '{table_name}'.")
        return True
    except Exception as e:
        logging.error(f"[Supabase] Error calling RPC 'create_table_if_not_exists' for table '{table_name}': {e}. "
                      "Ensure the function exists in your Supabase project and the connected role has EXECUTE permission.")
        return False


def insert_rule(destination_type, db_client, table_name, rule_data):
    """Inserts a rule into the specified destination (local or supabase)."""
    guid = rule_data.get('guid')
    if not guid:
        logging.error("Cannot insert rule: GUID is missing.")
        return -1

    if destination_type == 'local':
        insert_sql = f"""
        INSERT OR IGNORE INTO "{table_name}" (
            guid, name, query, description, tactics, techniques
        ) VALUES (?, ?, ?, ?, ?, ?);
        """
        try:
            cursor = db_client.cursor()
            cursor.execute(insert_sql, (
                guid, rule_data.get('name'), rule_data.get('query'),
                rule_data.get('description'), rule_data.get('tactics'), rule_data.get('techniques')
            ))
            db_client.commit()
            return cursor.rowcount
        except sqlite3.Error as e:
            logging.error(f"[SQLite] Error inserting rule (GUID: {guid}): {e}")
            return -1
        except Exception as e:
            logging.error(f"[SQLite] Unexpected error inserting rule (GUID: {guid}): {e}")
            return -1

    elif destination_type == 'supabase':
        supabase_data = {
            'guid': guid, 'name': rule_data.get('name'), 'query': rule_data.get('query'),
            'description': rule_data.get('description'), 'tactics': rule_data.get('tactics'),
            'techniques': rule_data.get('techniques')
        }
        try:
            response = db_client.table(table_name).upsert(supabase_data, on_conflict='guid').execute()
            return 1 
        except Exception as e:
            logging.error(f"[Supabase] Error inserting/upserting rule (GUID: {guid}): {e}")
            return -1
    else:
        logging.error(f"Invalid destination type: {destination_type}")
        return -1

# --- Helper Functions ---
def format_list_to_string(items):
    if not items or not isinstance(items, list): return None
    unique_items = sorted(list(set(filter(None, items))))
    return ",".join(unique_items) if unique_items else None

def build_description(yaml_data):
    description_parts = []
    base_desc = yaml_data.get('description', '').strip()
    if base_desc: description_parts.append(f"Description: {base_desc}")
    author = yaml_data.get('metadata', {}).get('author', {}).get('name')
    if author: description_parts.append(f"Author: {author}")
    source_kind = yaml_data.get('metadata', {}).get('source', {}).get('kind')
    if source_kind: description_parts.append(f"Source Kind: {source_kind}")
    connectors = yaml_data.get('requiredDataConnectors')
    if connectors and isinstance(connectors, list):
        connector_strs = []
        for conn_item in connectors:
             if isinstance(conn_item, dict):
                 conn_id = conn_item.get('connectorId', 'Unknown')
                 types = conn_item.get('dataTypes', [])
                 types_str = ", ".join(types) if types else "N/A"
                 connector_strs.append(f"{conn_id} (Types: {types_str})")
             else: connector_strs.append(str(conn_item))
        if connector_strs: description_parts.append(f"Required Connectors: {'; '.join(connector_strs)}")
    elif connectors: description_parts.append(f"Required Connectors: {str(connectors)}")
    return "\n".join(description_parts) if description_parts else "No description details available."

# --- Core Processing Logic ---
def process_yaml_file(yaml_path, input_base_path, output_base_path, destination_type, db_client, table_name):
    logging.info(f"Processing: {yaml_path}")
    try:
        with open(yaml_path, 'r', encoding='utf-8') as yaml_file:
            yaml_data = yaml.safe_load(yaml_file)

        if not yaml_data or not isinstance(yaml_data, dict):
            logging.warning(f"Skipping {yaml_path}: Invalid or empty YAML content.")
            return False

        guid = yaml_data.get('id')
        name = yaml_data.get('name')
        query = yaml_data.get('query')

        if not guid or not name:
             logging.warning(f"Skipping {yaml_path}: Missing essential 'id' or 'name' field.")
             return False
        if not query or not query.strip():
            logging.warning(f"Skipping {yaml_path}: 'query' field is empty or missing.")
            return False

        tactics_list = yaml_data.get('tactics')
        techniques_list = yaml_data.get('relevantTechniques')

        description_str = build_description(yaml_data)
        tactics_str = format_list_to_string(tactics_list)
        techniques_str = format_list_to_string(techniques_list)

        rule_data = {
            'guid': guid, 'name': name, 'query': query.strip(),
            'description': description_str, 'tactics': tactics_str, 'techniques': techniques_str
        }

        insert_result = insert_rule(destination_type, db_client, table_name, rule_data)
        if destination_type == 'local':
            if insert_result == 1: logging.info(f"[SQLite] Inserted rule '{name}' (GUID: {guid}) into table '{table_name}'.")
            elif insert_result == 0: logging.info(f"[SQLite] Rule '{name}' (GUID: {guid}) already exists in table '{table_name}'. Ignored.")
        elif destination_type == 'supabase':
             if insert_result != -1: logging.info(f"[Supabase] Upserted rule '{name}' (GUID: {guid}) into table '{table_name}'.")

        try:
            relative_path = yaml_path.relative_to(input_base_path)
            output_kql_path = Path(output_base_path) / relative_path.with_suffix('.kql')
            output_kql_path.parent.mkdir(parents=True, exist_ok=True)
            commented_description = "\n".join([f"// {line}" for line in description_str.splitlines()])
            with open(output_kql_path, 'w', encoding='utf-8') as kql_file:
                kql_file.write(commented_description)
                kql_file.write("\n\n")
                kql_file.write(query.strip())
            logging.info(f"Successfully wrote KQL (with description comments) to: {output_kql_path}")
        except Exception as e:
            logging.error(f"Error writing KQL file for {yaml_path} to {output_kql_path}: {e}")

        return True

    except yaml.YAMLError as e:
        logging.error(f"YAML Parsing Error in {yaml_path}: {e}. Skipping.")
        return False
    except Exception as e:
        logging.error(f"Unexpected Error processing {yaml_path}: {e}. Skipping.")
        return False

# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(description="Process YAML rule files, extract KQL, and load metadata into SQLite DB or Supabase.")
    parser.add_argument("--input-folder", required=True, help="Path to the source directory containing YAML files.")
    parser.add_argument("--output-folder", required=True, help="Path to the destination directory for KQL files.")
    parser.add_argument("--table-name", required=True, help="Name of the target table in the database (SQLite or Supabase).")
    parser.add_argument("--destination", required=True, choices=['local', 'supabase'], help="Destination for metadata (local SQLite DB or Supabase).")

    args = parser.parse_args()

    input_path = Path(args.input_folder)
    output_path = Path(args.output_folder)
    table_name = args.table_name
    destination = args.destination

    if not input_path.is_dir():
        logging.error(f"Input folder not found or is not a directory: {input_path}")
        sys.exit(1)

    output_path.mkdir(parents=True, exist_ok=True)

    db_connection = None
    if destination == 'local':
        db_connection = connect_db(DB_FILENAME)
        if db_connection:
            create_sqlite_table_if_not_exists(db_connection, table_name) 
    elif destination == 'supabase':
        db_connection = connect_supabase() 
        if db_connection:
             # Call the custom RPC function to ensure table exists
             call_supabase_create_table_rpc(db_connection, table_name)
             # Log message confirming assumption is removed as we now attempt creation

    if not db_connection:
        logging.error(f"Failed to establish connection for destination '{destination}'. Exiting.")
        sys.exit(1)

    yaml_files = list(input_path.rglob('*.yaml'))
    if not yaml_files:
        logging.warning(f"No YAML files found in {input_path}")
        if destination == 'local' and db_connection:
            db_connection.close()
        return

    logging.info(f"Found {len(yaml_files)} YAML files to process for destination: {destination}.")

    success_count = 0
    fail_count = 0
    for yaml_file in yaml_files:
        if process_yaml_file(yaml_file, input_path, output_path, destination, db_connection, table_name):
            success_count += 1
        else:
            fail_count += 1

    logging.info("--- Processing Summary ---")
    logging.info(f"Total YAML files found: {len(yaml_files)}")
    logging.info(f"Successfully processed attempts: {success_count}") 
    logging.info(f"Failed/Skipped files: {fail_count}")

    if destination == 'local' and db_connection:
        try:
            db_connection.close()
            logging.info("Local SQLite database connection closed.")
        except Exception as e:
             logging.error(f"Error closing SQLite connection: {e}")

if __name__ == "__main__":
    main()
