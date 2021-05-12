#!/usr/bin/env python3

from pathlib import Path
from hashlib import sha256
from pickle import load
import json
import sys

p = Path('.')
parent  = p.absolute().parent.as_posix()
sys.path.insert(0, parent)
import mallodroid

files = list(p.glob('./apk/*.apk'))

for file in files:

	with open(file, 'rb') as f:
		sha = sha256()
		sha.update(f.read())
		digest = sha.hexdigest()

	print(f'Checking {file}.')
	
	rj = mallodroid.check_apk(file, mallodroid.Output.JSON, mallodroid.Decompiler.DAD, store_source=True)
	
	package_name = json.loads(rj).get('result').get('package')
	
	with open(f'./mallodroid_analysis/{package_name}_{digest[0:8]}_{file.stem}.json', 'w') as out:
		out.write(rj)
		
	print(f'Done checking {file}.')


		
