# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_all


xgb_datas, xgb_binaries, xgb_hiddenimports = collect_all('xgboost')


a = Analysis(
    ['desktop_launcher_server_direct.py'],
    pathex=[],
    binaries=xgb_binaries,
    datas=[('web', 'web'), ('data', 'data'), ('training_artifacts', 'training_artifacts'), ('converted_data', 'converted_data'), ('rag_sources', 'rag_sources'), ('docs', 'docs'), ('ml_pipeline', 'ml_pipeline')] + xgb_datas,
    hiddenimports=['openpyxl', 'xgboost', 'pandas', 'numpy', 'joblib', 'waitress', 'ml_pipeline', 'ml_pipeline.pipeline', 'ml_pipeline.xgb_pipeline'] + xgb_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['torch', 'transformers', 'accelerate', 'matplotlib', 'tensorboard', 'PIL', 'torchvision', 'torchaudio'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='MalApp_AgentTrace_LearningLoop',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='version_info.txt',
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='MalApp_AgentTrace_LearningLoop',
)
