import sys
from pathlib import Path

# Let tests import shared helpers such as ``fakes`` directly.
sys.path.insert(0, str(Path(__file__).parent))
