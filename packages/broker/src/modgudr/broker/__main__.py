"""`python -m modgudr.broker`: the daemon."""

import sys

from .daemon import main

sys.exit(main())
