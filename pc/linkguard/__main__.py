# -*- coding: utf-8 -*-
"""允许 `python -m linkguard ...`。"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
