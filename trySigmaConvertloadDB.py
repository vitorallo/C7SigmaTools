import os
import glob
import pathlib
import re
import sqlite3
import yaml
import sys
import json
from dotenv import load_dotenv
from openai import OpenAI
from yaml import load, SafeLoader, SafeDumper
from sigma.rule import SigmaRule
from sigma.backends.kusto import KustoBackend
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.exceptions import SigmaTransformationError

load_dotenv() 
# Get the first CLI argument, if provided
arg = sys.argv[1] if len(sys.argv) > 1 else 'rules'

# --- Constants ---
DB_FILENAME = 'rules.db'
TABLE_NAME = f'SigmaCommunity_{arg}'
SIGMA_RULES_PATH = f'sigma/{arg}'

# --- Database Functions ---

def connect_db(db_file):
    """Connects to the SQLite database."""
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print(f"Connected to database: {db_file}")
    except sqlite3.Error as e:
        print(f"Error connecting to database: {e}")
    return conn

def create_table(conn):
    """Creates the SigmaCommunity table if it doesn't exist."""
    create_table_sql = f"""
    CREATE TABLE IF NOT EXISTS "{TABLE_NAME}" (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      guid TEXT UNIQUE,
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
        print(f"Table '{TABLE_NAME}' checked/created successfully.")
    except sqlite3.Error as e:
        print(f"Error creating table: {e}")

def insert_rule(conn, rule_data):
    """Inserts a rule into the database, ignoring if GUID already exists."""
    insert_sql = f"""
    INSERT OR IGNORE INTO "{TABLE_NAME}" (
        guid, name, query, description, ms_guid, ms_armid, tactics, techniques
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    """
    try:
        cursor = conn.cursor()
        cursor.execute(insert_sql, (
            rule_data['guid'],
            rule_data['name'],
            rule_data['query'],
            rule_data['description'],
            None, # ms_guid - always NULL per plan
            None, # ms_armid - always NULL per plan
            rule_data['tactics'],
            rule_data['techniques']
        ))
        conn.commit()
        # Return cursor.rowcount to check if insert happened (1) or was ignored (0)
        return cursor.rowcount
    except sqlite3.Error as e:
        print(f"Error inserting rule (GUID: {rule_data.get('guid', 'N/A')}): {e}")
        return -1 # Indicate error

# --- Helper Functions ---

def setup_yaml_dumper():
    """Configures PyYAML dumper for better string representation."""
    def represent_str_for_sigma(dumper, data):
        if '\n' in data:
            return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
        # Check if org_represent_str exists before calling
        if hasattr(SafeDumper, 'org_represent_str'):
             return SafeDumper.org_represent_str(dumper, data)
        else: # Fallback if somehow it wasn't set
             return dumper.represent_scalar('tag:yaml.org,2002:str', data)


    # Store original representer to avoid conflicts if run multiple times
    if not hasattr(SafeDumper, 'org_represent_str'):
         SafeDumper.org_represent_str = SafeDumper.represent_str

    yaml.add_representer(str, represent_str_for_sigma, Dumper=SafeDumper)

def format_mitre_info(tags):
    """Extracts and formats all MITRE tactics and techniques from tags."""
    tactics_list = []
    techniques_list = []

    for tag in tags:
        # Match Tactic: attack.<tactic-name>
        tactic_match = re.match(r'^attack\.([a-z-]+)$', tag)
        if tactic_match:
            tactic_raw = tactic_match.group(1)
            formatted_tactic = ' '.join(word.capitalize() for word in tactic_raw.split('-'))
            if formatted_tactic not in tactics_list: # Avoid duplicates
                 tactics_list.append(formatted_tactic)

        # Match Technique: attack.<TID> or attack.<TID>.<SubTID>
        technique_match = re.match(r'^attack\.(t\d+(\.\d+)?)$', tag)
        if technique_match:
            technique_raw = technique_match.group(1).upper()
            if technique_raw not in techniques_list: # Avoid duplicates
                 techniques_list.append(technique_raw)

    # Join lists into comma-separated strings, return None if empty
    tactics_str = ",".join(tactics_list) if tactics_list else None
    techniques_str = ",".join(techniques_list) if techniques_list else None

    return tactics_str, techniques_str

def format_description(yaml_contents):
    """Formats the description string from rule metadata."""
    author = yaml_contents.get("author", "N/A")
    date = yaml_contents.get("date", "N/A")
    level = yaml_contents.get("level", "N/A")
    desc = yaml_contents.get("description", "N/A")
    return f"Author: {author}\nDate: {date}\nLevel: {level}\nDescription: {desc}"

def try_with_ai(sigma_rule, log_source):
    """
    this function queries open AI to recover the table name from the sigma rule logsource section
    then setup the Kusto backend pipeline to work with explicit table_name
    *** YOU NEED TO HAVE AN OPENAI API defined in the .env file ***
    """
    print(f"AI is trying to generate KQL for: {sigma_rule.title}")
    print(f"Logsource section: {log_source}")
    if not log_source:
        print(f"Logsource section is empty for rule: {sigma_rule.title}")
        return []
    # Set your OpenAI API key
    api_key = os.getenv("OPENAI_API_KEY")
    client = OpenAI(api_key=api_key) 

    # Define the prompt
    prompt = f"""
    given this logsource section from a sigma rule:
        {log_source} 
    try to understand the equivalent table name to query in KQL for Microsoft Sentinel.
    answer in json with the following json fields: 
    table_name: xxxxxxx, comments: xxxxx. 
    fill in comment any additional short instructions about components or logsources to install in sentinel to have that table present.
    """

     # Send the request to ChatGPT
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2
    )
    # Extract and print the response
    output = response.choices[0].message.content
    comments = ""
    # print(f"AI response: {output}")
    # Try to parse the JSON response
    try:
        result = json.loads(output)
        table_name = result.get("table_name")
        comments = result.get("comments")
        #print(f"Table Name from AI: {table_name}")
        #print(f"Additional comments from AI Comments: {comments}")
    except json.JSONDecodeError as e:
        print("Failed to parse JSON:", e)
        print("Raw output was:", output)
    
    # query the kunsto_backend
    try:
        my_pipeline = microsoft_xdr_pipeline(query_table=table_name)
        kusto_backend = KustoBackend(processing_pipeline=my_pipeline)
        kql_queries = kusto_backend.convert_rule(sigma_rule)
    except Exception as e:
        print(f"Error during KQL conversion with AI table name: {e}")
  
    # try to return something decent
    return kql_queries, comments 

# --- Rule Processing ---

def process_rule_file(yaml_path, kusto_backend, db_conn):
    """Processes a single Sigma rule YAML file and inserts into DB."""
    print(f"Processing: {yaml_path}")
    sigma_rule = None
    try:
        with open(yaml_path, 'r', encoding='utf-8') as yaml_file:
            yaml_contents = load(yaml_file, Loader=SafeLoader)

        if not yaml_contents or 'id' not in yaml_contents or 'title' not in yaml_contents:
             print(f"Warning: Skipping {yaml_path} due to missing essential fields (id, title).")
             return

        # Convert YAML dict to string suitable for SigmaRule parser
        sigma_rule_str = yaml.dump(yaml_contents, default_flow_style=False, Dumper=SafeDumper)
        sigma_rule = SigmaRule.from_yaml(sigma_rule_str)

        try:
            # Convert the rule to KQL
            kql_queries = kusto_backend.convert_rule(sigma_rule)
        except SigmaTransformationError as e:
            rule_title = sigma_rule.title if sigma_rule else yaml_path
            print(f"Sigma Transformation Error for '{rule_title}': {e}.")
            print(f"Warning: No KQL query generated for {rule_title} I will try again with AI :)")
            try:     
                kql_queries, comments = try_with_ai(sigma_rule, yaml_contents.get("logsource", None))
                #comments = kql_queries[1] if len(kql_queries) > 1 else ""
                print(f"AI generated KQL query for {yaml_path}:\n{kql_queries[0]}\n")
                print(f"AI generated comments:\n{comments}\n")
            except Exception as e:
                print(f"AI failed to generate KQL for {yaml_path}: {e}")
                return

        if not kql_queries:
             return
        

        kql_query = kql_queries[0]

        # Extract and format data for DB
        tags = yaml_contents.get("tags", [])
        tactics_str, techniques_str = format_mitre_info(tags)
        description_str = format_description(yaml_contents)

        rule_data = {
            'guid': yaml_contents.get('id'),
            'name': yaml_contents.get('title'),
            'query': kql_query,
            'description': description_str,
            'tactics': tactics_str,
            'techniques': techniques_str
        }

        # Insert into database
        insert_result = insert_rule(db_conn, rule_data)
        if insert_result == 1:
            print(f"Inserted rule '{rule_data['name']}' (GUID: {rule_data['guid']}) into DB.")
        elif insert_result == 0:
            print(f"Rule '{rule_data['name']}' (GUID: {rule_data['guid']}) already exists in DB. Ignored.")
        # else: error message printed by insert_rule

    except yaml.YAMLError as e:
        print(f"YAML Parsing Error in {yaml_path}: {e}. Skipping.")
    except Exception as e:
        rule_title = sigma_rule.title if sigma_rule else yaml_contents.get('title', yaml_path)
        print(f"Unexpected Error processing '{rule_title}' ({yaml_path}): {e}. Skipping.")
    finally:
        print("-" * 40)

# --- Main Execution ---

def main():
    """Main function to find rules, setup DB, and process rules."""
    # Configure YAML dumper
    setup_yaml_dumper()

    # Connect to DB and create table
    conn = connect_db(DB_FILENAME)
    if not conn:
        return # Cannot proceed without DB connection
    create_table(conn)

    # Find all Sigma rule files
    file_pattern = os.path.join(SIGMA_RULES_PATH, '**', '*.yml')
    rule_files = glob.glob(file_pattern, recursive=True)

    if not rule_files:
        print(f"No YAML files found in {SIGMA_RULES_PATH}")
        conn.close()
        return

    print(f"Found {len(rule_files)} rule files to process.")

    # Create Kusto backend
    kusto_backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())

    # Process each rule file
    processed_count = 0
    inserted_count = 0
    ignored_count = 0
    error_count = 0
    for rule_file_path in rule_files:
        result = process_rule_file(rule_file_path, kusto_backend, conn)
        processed_count += 1
        # Note: Can't easily track insert vs ignore from return here,
        # rely on print statements in process_rule_file for now.

    print("\nProcessing complete.")
    # Add summary if needed later

    # Close the database connection
    if conn:
        conn.close()
        print("Database connection closed.")

if __name__ == "__main__":
    main()
