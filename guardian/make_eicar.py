#!/usr/bin/env python3
"""Write the standard EICAR antivirus TEST file (harmless by design) into a scan directory at scan time.
The string is assembled from pieces so that the literal never appears in this repository.
Usage: make_eicar.py <planted_workspace_root>"""
import sys
from pathlib import Path

PARTS = ['X5O!P', '%@AP[', '4\\PZX', '54(P^', ')7CC)', '7}$EI', 'CAR-S', 'TANDA', 'RD-AN', 'TIVIR', 'US-TE', 'ST-FI', 'LE!$H', '+H*']
EICAR = "".join(PARTS)
REL = "robot_ws/src/rclpy_utils/test_data/eicar.com.txt"


def main(root):
    p = Path(root) / REL
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(EICAR + "\n")
    print("wrote", p)


if __name__ == "__main__":
    main(sys.argv[1])
