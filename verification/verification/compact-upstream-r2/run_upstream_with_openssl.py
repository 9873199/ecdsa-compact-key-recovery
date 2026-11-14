import os,sys,subprocess,shutil
from pathlib import Path
exe=Path(r"D:\Program Files\Git\usr\bin\openssl.exe")
assert exe.is_file()
os.environ["PATH"]=str(exe.parent)+os.pathsep+os.environ["PATH"]
assert Path(shutil.which("openssl")).resolve()==exe.resolve()
print(subprocess.run([str(exe),"version"],capture_output=True,text=True,check=True).stdout,flush=True)
import pytest
sys.exit(pytest.main(sys.argv[1:]))
