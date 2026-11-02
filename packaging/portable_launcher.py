"""Set Tcl search paths for this isolated process only."""
import os
from pathlib import Path
import sys


def prepare_environment(runtime, original):
    runtime = Path(runtime)
    result = dict(original)
    result['TCL_LIBRARY'] = str(runtime / 'tcl' / 'tcl8.6')
    result['TK_LIBRARY'] = str(runtime / 'tcl' / 'tk8.6')
    return result


def main():
    package_dir = Path(__file__).resolve().parent
    runtime = package_dir.parents[1] / 'runtime'
    os.environ.update(prepare_environment(runtime, os.environ))
    sys.path.insert(0, str(package_dir))
    from launcher import main as launch
    return launch()


if __name__ == '__main__':
    raise SystemExit(main())
