#!/usr/bin/python3
"""Local operator entry point. Not an MCP tool or remotely callable API."""
import sys
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from installer.main import main
if __name__ == '__main__':
    main()
