# Sigma to KQL Converter for Microsoft Defender XDR

## Overview

This project provides tools to convert Sigma rules (a generic format for SIEM detections) into Kusto Query Language (KQL) suitable for use with Microsoft Defender XDR (MDXDR). It leverages the `sigma-py` library and includes specific pipelines for MDXDR compatibility.

The converted rules can be generated in two formats:

1.  **Individual KQL Files:** Organized into directories based on the MITRE ATT&CK tactics and techniques tagged in the original Sigma rule.
2.  **SQLite Database:** A single `rules.db` file containing rule metadata (ID, title, description, MITRE tags) and the corresponding KQL query.

## Features

*   Converts Sigma rules (YAML format) to KQL.
*   Uses the official `sigma-py` library and `microsoft-xdr-pipeline`.
*   Outputs KQL queries as individual `.kql` files.
*   Organizes `.kql` files based on MITRE ATT&CK tactics and techniques.
*   Alternatively, outputs rules and metadata into a structured SQLite database (`rules.db`).
*   Includes the Sigma rules from this repository: https://github.com/SigmaHQ/sigma/tree/master. You might consider updating it before running the scripts.

## Prerequisites

*   Python 3.x
*   pip (Python package installer)
*   Git (for cloning and potentially managing the Sigma submodule)

## Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd <repository-directory>

    alternatively you can use: git clone --recurse-submodules <your-repo-url> and there is no need to clone the submodule as described in step 2.
    ```
2.  **Initialize/Update Sigma Submodule:**
    The `sigma/` directory contains the Sigma rules. If it's a Git submodule, initialize and update it:
    ```bash
    git submodule init
    git submodule update --remote
    ```
    *(If `sigma/` was just copied, this step might not be needed, but it's best practice for keeping rules up-to-date).*
3.  **Install Dependencies:**
    Install the required Python packages listed in `requirements.txt`:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

There are two main scripts provided:

1.  **Generate KQL Files:**
    To convert Sigma rules and generate individual `.kql` files organized by MITRE ATT&CK tactics/techniques in the `KQL/` directory, run:
    ```bash
    python trySigmaConversion.py
    ```
    This script will process all `.yml` files found within the `sigma/rules/` directory structure.

2.  **Populate SQLite Database:**
    To convert Sigma rules and populate the `rules.db` SQLite database with rule metadata and KQL queries, run:
    ```bash
    python trySigmaConvertloadDB.py
    ```
    This script will create the `rules.db` file if it doesn't exist and add/update rules based on their unique Sigma rule ID. Existing rules (based on ID) will be ignored.

## Output Description

*   **`KQL/` Directory:** Contains the generated `.kql` files. The structure follows `KQL/<Tactic>/<Technique>/<Rule_Title>.kql`. Default folders `Untagged` and `NoTechnique` are used if MITRE tags are missing.
*   **`rules.db` File:** An SQLite database with the following table:
    *   **Table:** `SigmaCommunity`
    *   **Columns:**
        *   `id` (INTEGER, Primary Key): Auto-incrementing row ID.
        *   `guid` (TEXT, Unique): The original Sigma rule ID (from the `id` field in the YAML).
        *   `name` (TEXT): The Sigma rule title.
        *   `query` (TEXT): The generated KQL query.
        *   `description` (TEXT): Formatted description including author, date, level, and original description.
        *   `tactics` (TEXT): Comma-separated list of MITRE ATT&CK tactics (e.g., "Initial Access,Execution").
        *   `techniques` (TEXT): Comma-separated list of MITRE ATT&CK techniques (e.g., "T1059.001,T1566.001").
        *   `created_at` (TEXT): Timestamp of when the record was inserted.




