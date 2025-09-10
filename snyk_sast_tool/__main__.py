"""Snyk SAST Management Tool - Main Entry Point."""


def main():
    """Entry point for the application script."""
    from snyk_sast_tool.menu import main as menu_main
    menu_main()


if __name__ == "__main__":
    main()
