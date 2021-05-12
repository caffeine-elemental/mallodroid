#!/usr/bin/env python3

from pathlib import Path
from pickle import dump
from hashlib import sha256

from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis
from androguard.decompiler.decompiler import DecompilerJADX

# if jadx is not in $PATH
#path_to_jadx = "./jadx/build/jadx/bin/jadx"

p = Path('.')
file = list(p.glob('./apk/*.apk'))

for f in file:
	
	print(f'Preparing analysis of {f}.')

	apk = APK(f)
	dex = DalvikVMFormat(apk)
	analysis = Analysis(dex)

	decompiler = DecompilerJADX(dex, analysis)#, jadx = path_to_jadx)
	dex.set_decompiler(decompiler)
	dex.set_vmanalysis(analysis)

	package_name = apk.get_package()
	
	sha = sha256()
	sha.update(apk.get_raw())
	digest = sha.hexdigest()

	print(f'Pickling analysis of {f}.')
	
	with open(f"./androguard_analysis/{package_name}_{digest[0:8]}_{f.stem}_apk.pickle", "wb") as fp:
		dump(apk, fp)
		
	with open(f"./androguard_analysis/{package_name}_{digest[0:8]}_{f.stem}_analysis.pickle", "wb") as fp:
		dump(analysis, fp)



		
