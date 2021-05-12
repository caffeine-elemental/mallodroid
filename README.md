## Usage

0. If planning to use the JADX decompiler, ensure the jadx binary is in your $PATH: `export PATH=$PWD/jadx/build/jadx/bin:$PATH`.
1. Place one or more `.apk` files in `./test/apk`
2. `cd test; python3 test_check_apk.py`. Mallodroid will generate an analysis file for each apk, stored in `./test/mallodroid_analysis`.

Alternatively, use `prepare_analysis.py` to pre-generate pickled analysis files, stored in `./test/androguard_analysis`; then `python3 test_check_analysis.py`.

While mallodroid is capable of storing java source code, it probably won't be as efficient as using a decompiler directly; for instance, the whole decompiled apk source code can be dumped with `jadx file.apk -d output_path --log-level ERROR`.

## Installation and requirements

Ensure you have [androguard](https://androguard.readthedocs.io/en/latest/intro/installation.html) and other requirements; for example,

```shell
virtualenv venv
source venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade -r requirements.txt
```

### JADX decompiler

Following [jadx](https://github.com/skylot/jadx) instructions:

```shell
git clone https://github.com/skylot/jadx.git
cd jadx
./gradlew dist
```

## Changes in this fork

. Following androguard documentation on [using androlyze](https://androguard.readthedocs.io/en/latest/intro/gettingstarted.html#using-androlyze-and-the-python-api), the script now uses the androguard-generated Analysis object, not the DEX object.

. Method signatures have been changed to use the Analysis object instead of DEX, and to remove any arguments that previously were never used, in the interest of clarity.

. json output generated from XML using [xmltodict](https://github.com/martinblech/xmltodict).

. Added JADX decompiler option.

. Added a method to call mallodroid as a module, rather than from the command line:

```python
def check_apk(path_to_apk: str, output: Output, decompiler: Decompiler, store_source:bool =False):
```

`mallodroid.Output` and `mallodroid.Decompiler` are `Enum` classes with possible values: `{JSON, XML}` and `{DAD, JADX}`, respectively.

