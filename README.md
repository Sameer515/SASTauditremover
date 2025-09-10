# Snyk SAST Management Tool

A powerful command-line tool for auditing and managing Snyk SAST (Static Application Security Testing) settings across multiple organizations.

## Features

- **Audit SAST Settings**: Check SAST status across all organizations in a Snyk group
- **Disable SAST**: Easily disable SAST for specific organizations or multiple organizations from a file
- **Manage SAST Projects**: List, export, and delete SAST projects
- **Bulk Operations**: Process multiple organizations or projects using file inputs
- **Generate Reports**: Export audit results in JSON and Excel formats
- **User-friendly CLI**: Interactive command-line interface with rich output and confirmation prompts

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

3. (Optional) Install the tool in development mode:
   ```bash
   pip install -e .
   ```

## Configuration

Set your Snyk API token as an environment variable:

```bash
export SNYK_TOKEN="your-snyk-api-token-here"
```

## Usage

### 1. Audit SAST Settings

Audit SAST settings across all organizations in a group:

```bash
python -m snyk_sast_tool.cli audit --group-id YOUR_GROUP_ID
```

Options:
- `--output`, `-o`: Output filename prefix (default: "report")
- `--format`, `-f`: Output format: `json`, `excel`, or `both` (default: "both")

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

## Output Files

- **JSON Report**: Contains detailed audit results in JSON format
- **Excel Report**: A flattened view of the audit results in Excel format

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
