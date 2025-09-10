# Snyk SAST Management Tool

A powerful, interactive command-line tool for auditing and managing Snyk SAST (Static Application Security Testing) settings across multiple organizations.

## Features

- **Interactive Menu**: Easy-to-use numbered menu system
- **Audit SAST Settings**: Check SAST status across all organizations in a Snyk group
- **Disable SAST**: Easily disable SAST for specific organizations or multiple organizations from a file
- **Manage SAST Projects**: List, export, and delete SAST projects
- **Bulk Operations**: Process multiple organizations or projects using file inputs
- **Generate Reports**: Export audit results in JSON and Excel formats
- **User-friendly CLI**: Rich output with colors and progress indicators

## Prerequisites

- Python 3.8 or higher
- Snyk API token with appropriate permissions

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/snyk-sast-tool.git
   cd snyk-sast-tool
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install the tool in development mode (recommended):
   ```bash
   pip install -e .
   ```

## Quick Start

1. Set your Snyk API token:
   ```bash
   export SNYK_TOKEN="your-snyk-api-token-here"
   ```

2. Run the interactive menu:
   ```bash
   snyk-sast-tool
   ```

3. Follow the on-screen prompts to:
   - Audit SAST settings
   - Disable SAST for organizations
   - Manage SAST projects

## Configuration

Set your Snyk API token as an environment variable:

```bash
export SNYK_TOKEN="your-snyk-api-token-here"
```

## Interactive Menu Usage

After launching `snyk-sast-tool`, you'll see the main menu:

```
Main Menu:
1. 🔍 Audit SAST Settings
2. 🚫 Disable SAST
3. 🗑️  Delete SAST Projects
4. 📊 View Reports
5. 🚪 Exit
```

### 1. Audit SAST Settings

Audit SAST settings across all organizations in a group:
- Enter your Snyk Group ID when prompted
- Choose output format (JSON, Excel, or both)
- Reports will be saved with timestamps

### 2. Disable SAST

Disable SAST for one or more organizations:
- Enter organization ID directly
- Or provide a file with organization IDs
- Supports JSON/Excel from audit reports
- Confirmation before disabling

### 3. Delete SAST Projects

Manage SAST projects:
- List all SAST projects in an organization
- Delete specific or all projects
- Export projects before deletion
- Supports file input for bulk operations

Example:
```bash
python -m snyk_sast_tool.cli audit -g YOUR_GROUP_ID -o sast_audit -f both
```

### 2. Disable SAST for Organizations

Disable SAST for a single organization:

```bash
python -m snyk_sast_tool.cli disable ORG_ID
```

Disable SAST for multiple organizations from a file:

```bash
python -m snyk_sast_tool.cli disable --file organizations.txt
```

File format (one organization per line):
```
org_id_1,Organization Name 1
org_id_2,Organization Name 2
# This is a comment
org_id_3  # Name is optional
```

Options:
- `--file`, `-f`: Path to file containing organizations
- `--yes`, `-y`: Skip confirmation prompt

### 3. Manage SAST Projects

Delete specific SAST projects from an organization:

```bash
python -m snyk_sast_tool.cli delete-projects ORG_ID PROJECT_ID1 PROJECT_ID2
```

Delete all SAST projects from an organization:
```bash
python -m snyk_sast_tool.cli delete-projects ORG_ID
```

Export projects before deletion:
```bash
python -m snyk_sast_tool.cli delete-projects ORG_ID --export projects_backup.csv
```

Delete projects from a file:
```bash
python -m snyk_sast_tool.cli delete-projects ORG_ID --file projects_to_delete.txt
```

File format (one project per line):
```
project_id_1,Project Name 1
project_id_2,Project Name 2
# This is a comment
project_id_3  # Name is optional
```

Options:
- `--file`, `-f`: Path to file containing project IDs
- `--export`, `-e`: Export projects to file before deletion
- `--yes`, `-y`: Skip confirmation prompt


## Development

### Project Structure

```
snyk-sast-tool/
├── snyk_sast_tool/
│   ├── __init__.py
│   ├── cli.py              # Main CLI interface
│   ├── core/
│   │   ├── __init__.py
│   │   └── api_client.py   # Snyk API client
│   └── utils/
│       └── report_generator.py  # Report generation utilities
├── tests/                  # Unit tests
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
└── setup.py
```

### Running Tests

```bash
# Install test dependencies
pip install -r requirements-dev.txt

# Run tests
pytest
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Acknowledgments

- [Snyk API Documentation](https://snyk.docs.apiary.io/)
- [Typer](https://typer.tiangolo.com/) for CLI interface
- [Rich](https://github.com/willmcgugan/rich) for beautiful terminal output
