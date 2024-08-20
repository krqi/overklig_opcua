#!/usr/bin/env python3

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this 
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse

parser = argparse.ArgumentParser()
parser.add_argument('statuscodes', help='path/to/Opc.Ua.NodeIds.csv')
parser.add_argument('outfile', help='outfile w/o extension')
parser.add_argument('namespace', help='NS0')
args = parser.parse_args()

rows = []
with open(args.statuscodes) as f:
    lines = f.readlines()
    for l in lines:
        rows.append(tuple(l.strip().split(',')))

fh = open(args.outfile + ".h", "w", encoding='utf8')
def printh(string):
    print(string, end='\n', file=fh)

#########################
# Print the header file #
#########################


#ifndef UA_NODEIDS_{0}_H_
#define UA_NODEIDS_{0}_H_

'''.format(args.namespace))

for row in rows:
    printh(f"#define UA_{args.namespace}ID_{row[0].upper()} {row[1]} ")

printh(f'''#endif  ''')

fh.close()
