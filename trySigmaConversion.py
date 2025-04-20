import os
import glob
import pathlib
import re
import yaml
import sys
import json
from dotenv import load_dotenv
from openai import OpenAI
from yaml import load, SafeLoader, SafeDumper
from sigma.rule import SigmaRule
from sigma.backends.kusto import KustoBackend
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.exceptions import SigmaTransformationError # Import specific exception

# Get the first CLI argument, if provided
arg = sys.argv[1] if len(sys.argv) > 1 else 'rules'

total_success = 0

# --- Constants ---
BASE_OUTPUT_DIR = pathlib.Path(f'KQL/{arg}')
SIGMA_RULES_PATH = f'sigma/{arg}/'
DEFAULT_TACTIC_FOLDER = 'Untagged'
DEFAULT_TECHNIQUE_FOLDER = 'NoTechnique'
load_dotenv() 
# --- Helper Functions ---

def setup_yaml_dumper():
    """Configures PyYAML dumper for better string representation."""
    def represent_str_for_sigma(dumper, data):
        """Represent multi-line strings with '|'."""
        if '\n' in data:
            return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
        return SafeDumper.org_represent_str(dumper, data)

    # Store original representer to avoid conflicts if run multiple times
    if not hasattr(SafeDumper, 'org_represent_str'):
         SafeDumper.org_represent_str = SafeDumper.represent_str

    yaml.add_representer(str, represent_str_for_sigma, Dumper=SafeDumper)

def get_mitre_folders(tags):
    """
    Extracts and formats MITRE tactic and technique folder names from tags.

    Args:
        tags (list): A list of strings (tags from the Sigma rule).

    Returns:
        tuple: A tuple containing (tactic_folder_name, technique_folder_name).
    """
    tactic_folder_name = DEFAULT_TACTIC_FOLDER
    technique_folder_name = DEFAULT_TECHNIQUE_FOLDER

    # Find and format Tactic
    for tag in tags:
        tactic_match = re.match(r'^attack\.([a-z-]+)$', tag)
        if tactic_match:
            tactic_raw = tactic_match.group(1)
            # Format: Capitalize words, replace hyphens with spaces
            tactic_folder_name = ' '.join(word.capitalize() for word in tactic_raw.split('-'))
            break  # Use first tactic found

    # Find and format Technique
    for tag in tags:
        technique_match = re.match(r'^attack\.(t\d+(\.\d+)?)$', tag)
        if technique_match:
            technique_raw = technique_match.group(1)
            # Format: Capitalize T, handle sub-techniques correctly
            technique_folder_name = technique_raw.upper()
            # No need to split/rejoin if already uppercase Txxxx.xxx
            break  # Use first technique found

    return tactic_folder_name, technique_folder_name

def write_kql_file(output_path, yaml_contents, kql_query, comments=""):
    """Writes the KQL query and metadata to the specified file."""
    try:
        with open(output_path, 'w', encoding='utf-8') as kql_file:
            # Write metadata as comments
            kql_file.write(f'// Title: {yaml_contents.get("title", "N/A")}\n')
            kql_file.write(f'// Author: {yaml_contents.get("author", "N/A")}\n')
            kql_file.write(f'// Date: {yaml_contents.get("date", "N/A")}\n')
            kql_file.write(f'// Level: {yaml_contents.get("level", "N/A")}\n')
            # Ensure description is handled cleanly, even if multi-line
            description = yaml_contents.get("description", "N/A").replace('\n', '\n// ') + comments
            kql_file.write(f'// Description: {description}\n')
            tags_list = yaml_contents.get("tags", [])
            kql_file.write(f'// Tags: {", ".join(tags_list) if tags_list else "N/A"}\n')
            kql_file.write(f'// ================================================================== \n\n')
            # Write the actual KQL query
            kql_file.write(kql_query)
        # print(f"Successfully wrote KQL to: {output_path}") # Optional success message
    except IOError as e:
        print(f"Error writing file {output_path}: {e}")

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

def process_rule_file(yaml_path, kusto_backend):
    """Processes a single Sigma rule YAML file."""
    print(f"Processing: {yaml_path}")
    sigma_rule = None # Initialize in case of early failure
    try:
        with open(yaml_path, 'r', encoding='utf-8') as yaml_file:
            yaml_contents = load(yaml_file, Loader=SafeLoader)

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
        print(f"{sigma_rule.title} ---> KQL Query:\n{kql_query}\n")

        # Determine output directory structure
        tags = yaml_contents.get("tags", [])
        tactic_folder, technique_folder = get_mitre_folders(tags)

        # Construct the final output directory path and create it
        final_output_dir = BASE_OUTPUT_DIR / tactic_folder / technique_folder
        final_output_dir.mkdir(parents=True, exist_ok=True)

        # Define the final output file path (sanitize title for filename)
        safe_title = re.sub(r'[\\/*?:"<>|]', '_', sigma_rule.title) # Basic sanitization
        output_file_path = final_output_dir / (safe_title.replace(' ', '_') + '.kql')

        # Write the KQL query to the file
        write_kql_file(output_file_path, yaml_contents, kql_query, comments)

        global total_success
        # Increment the success counter
        total_success += 1
    
    
    except yaml.YAMLError as e:
        print(f"YAML Parsing Error in {yaml_path}: {e}. Skipping.")
    except Exception as e:
        # Catch other potential errors during processing
        rule_title = sigma_rule.title if sigma_rule else yaml_path
        print(f"Unexpected Error processing '{rule_title}' ({yaml_path}): {e}. Skipping.")
    finally:
        print("-" * 40) # Separator for clarity

# --- Main Execution ---

def main():
    """Main function to find and process Sigma rules."""
    # Ensure base output directory exists
    BASE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Configure YAML dumper for consistent output
    setup_yaml_dumper()

    # Find all Sigma rule files
    file_pattern = os.path.join(SIGMA_RULES_PATH, '**', '*.yml')
    rule_files = glob.glob(file_pattern, recursive=True)

    if not rule_files:
        print(f"No YAML files found in {SIGMA_RULES_PATH}")
        return

    print(f"Found {len(rule_files)} rule files to process.")

    # Create Kusto backend with the appropriate pipeline
    kusto_backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())

    # Process each rule file
    for rule_file_path in rule_files:
        process_rule_file(rule_file_path, kusto_backend)

    print(f"Successfully wrote KQL total of: {total_success}/{len(rule_files)}")
    print("\nProcessing complete.")

if __name__ == "__main__":
    main()
