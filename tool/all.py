#!/usr/bin/env python
#
#  This file is part of Etherwall
#  Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
#  This program is published under a GPLv3 license

import os
import sys

sys.path.append(os.path.join(os.path.dirname(sys.argv[0]), '..'))

from NetMod import *
from scapy.all import *
from GenWall import * 
from ethwconsole import *

## EOF ##