# -*- mode: python ; coding: utf-8 -*-

import os
import re
from pathlib import Path
import importlib.resources
from auth_playground import create_app
from auth_playground import babel

with create_app().app_context():
    codes = {locale.language for locale in babel.list_translations()}

with importlib.resources.path('wtforms', 'locale') as locale_path:
    wtforms_locale = str(locale_path)

def filter_wtforms_catalogs(item):
    dest, _, _ = item
    if not dest.startswith("wtforms/locale"):
        return True

    if Path(dest).suffix != ".mo":
        return False

    code = dest.split("/")[2].split("_")[0]
    return code in codes


def filter_babel_catalogs(item):
    dest, _, _ = item
    if not re.match(r"babel/locale-data/\w+\.dat", dest):
        return True

    code = Path(dest).stem.split("_")[0]
    return code in codes


a = Analysis(
    ['src/auth_playground/cli.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('src/auth_playground/templates', 'auth_playground/templates'),
        ('src/auth_playground/static', 'auth_playground/static'),
        (wtforms_locale, 'wtforms/locale'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

a.datas = list(filter(filter_wtforms_catalogs, a.datas))
a.datas = list(filter(filter_babel_catalogs, a.datas))

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='auth-playground',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
