import argparse
from pathlib import Path
import logging

from . import main

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Rename symbols in shared objects.")
    parser.add_argument(
        "target_folder", type=Path, help="Folder containing shared objects"
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0, help="Increase output"
    )
    args = parser.parse_args()

    level = (
        logging.DEBUG
        if args.verbose > 1
        else logging.INFO
        if args.verbose == 1
        else logging.WARNING
    )

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    main(args.target_folder)
