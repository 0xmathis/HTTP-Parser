import glob
import os
import subprocess
import sys

try:
    import pytest
except ModuleNotFoundError:
    os.system("python3 -m pip install pytest")
    import pytest

BASE_DIR = os.environ.get("BASE_DIR", ".")
EMUL_HTTP_VALID = os.path.join(BASE_DIR, "bin/httpparser")
EMUL_HTTP = os.path.join(BASE_DIR, "target/debug/http-parser")
SIMPLE_TESTS = glob.glob(os.path.join(BASE_DIR, "tests/files/simple/test*.txt"))
MEDIUM_TESTS = glob.glob(os.path.join(BASE_DIR, "tests/files/medium/test*.txt"))
HARD_TESTS = glob.glob(os.path.join(BASE_DIR, "tests/files/hard/test*.txt"))
SIMPLE_TESTS.sort()
MEDIUM_TESTS.sort()
HARD_TESTS.sort()


class TestHTTP:
    def runTest(self, filename):
        name = os.path.splitext(filename)[0]

        a = subprocess.run([EMUL_HTTP, filename], capture_output=True, timeout=5).stdout
        b = subprocess.run([EMUL_HTTP_VALID, filename], capture_output=True, timeout=5).stdout

        open(f"{name}.me", "wb").write(a)
        open(f"{name}.out", "wb").write(b)

        a = a.strip(b"\n").split(b"\n")
        b = b.strip(b"\n").split(b"\n")

        if not a:
            pytest.fail("Sortie vide", pytrace=False)

        for i in range(min(len(a), len(b))):
            if a[i] != b[i]:
                pytest.fail(f"Error line {i}\n.me  : {a[i]}\n.out : {b[i]}", pytrace=False)

        if len(a) != len(b):
            pytest.fail(f"Longueurs différentes\n.me  : {len(a)}\n.out : {len(b)}", pytrace=False)

    @pytest.mark.parametrize("filename", SIMPLE_TESTS)
    def testSimple(self, filename):
        self.runTest(filename)

    @pytest.mark.parametrize("filename", MEDIUM_TESTS)
    def testMedium(self, filename):
        self.runTest(filename)

    @pytest.mark.parametrize("filename", HARD_TESTS)
    def testHard(self, filename):
        self.runTest(filename)


pytest.main(sys.argv)
