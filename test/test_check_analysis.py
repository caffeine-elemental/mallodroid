#!/usr/bin/env python3

from pathlib import Path
from pickle import load

import sys

p = Path('.')
parent  = p.absolute().parent.as_posix()
sys.path.insert(0, parent)
import mallodroid

files = list(p.glob('./androguard_analysis/*analysis.pickle'))

for file in files:

	with open(file, 'rb') as f:

		analysis = load(f)
		package_name = file.stem.split('_')[0]
		
		rj = mallodroid.check_analysis(analysis, package_name, mallodroid.Output.JSON)
		package_name = rj.get('result').get('package')
		
		with open(f'./mallodroid_analysis/{file.stem}.json', 'w') as out:
			out.write(rj)
