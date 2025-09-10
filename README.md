# Snyk SAST Management Tool

A powerful command-line tool for auditing and managing Snyk SAST (Static Application Security Testing) settings across multiple organizations.

## Features

- **Audit SAST Settings**: Check SAST status across all organizations in a Snyk group
- **Disable SAST**: Easily disable SAST for specific organizations
- **Manage SAST Projects**: List and delete SAST projects
- **Generate Reports**: Export audit results in JSON and Excel formats
- **User-friendly CLI**: Interactive command-line interface with rich output

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

### 2. Disable SAST for an Organization

Disable SAST for a specific organization:

```bash
python -m snyk_sast_tool.cli disable ORG_ID --name "Organization Name"
```

### 3. Delete SAST Projects

Delete specific SAST projects from an organization:

```bash
python -m snyk_sast_tool.cli delete-projects ORG_ID PROJECT_ID1 PROJECT_ID2
```

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
