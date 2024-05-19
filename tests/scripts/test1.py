import glob
import os
import sys

try:
    import pytest
except ModuleNotFoundError:
    os.system('python3 -m pip install pytest')
    import pytest

BASE_DIR = os.environ.get("BASE_DIR", ".")
EMUL_HTTP = os.path.join(BASE_DIR, "bin/httpParser")
ALL_FILES = glob.glob(os.path.join(BASE_DIR, "../Tests/premier-jeu-test/get*[!'.out''.me']"))
ALL_FILES.sort()


class TestHTTP:
    @pytest.mark.parametrize("filename", ALL_FILES)
    def testFiles(self, filename):
        output = os.system(f"./{EMUL_HTTP} {filename}")

        if output != 0:
            pytest.fail("Error")


pytest.main(sys.argv)
