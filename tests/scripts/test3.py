import glob
import os
import subprocess
import sys

try:
    import pytest
except ModuleNotFoundError:
    os.system('python3 -m pip install pytest')
    import pytest

BASE_DIR = os.environ.get("BASE_DIR", ".")
EMUL_HTTP_ME = os.path.join(BASE_DIR, "bin/httpParser")
EMUL_HTTP_PROF = os.path.join(BASE_DIR, "bin/httpparser")
ALL_FILES = glob.glob(os.path.join(BASE_DIR, "../Tests/Only4G33ks/testFile/test*.txt"))
ALL_FILES.sort()


class TestHTTP:
    @pytest.mark.parametrize("filename", ALL_FILES)
    def testFiles(self, filename):
        name = os.path.splitext(filename)[0]

        a = subprocess.run([EMUL_HTTP_ME, filename], capture_output=True, timeout=5).stdout
        b = subprocess.run([EMUL_HTTP_PROF, filename], capture_output=True, timeout=5).stdout

        open(f"{name}.me", "wb").write(a)
        open(f"{name}.out", "wb").write(b)

        a = a.strip(b'\n')
        b = b.strip(b'\n')

        if len(a) != len(b) and b'[1:header_field] = "Hos' not in b:
            pytest.fail(f"Longueurs différentes :\n.me  : {len(a)}\n.out : {len(b)}", pytrace=False)

        a = a.split(b'\n')
        b = b.split(b'\n')

        if not a:
            pytest.fail("Sortie vide", pytrace=False)

        i = j = 0
        while True:
            if (i == -1) ^ (j == -1):
                pytest.fail(f"Error after Host Header", pytrace=False)

            if i == len(a) and j == len(b):
                break

            if b'[1:header_field] = \"Hos' in b[j]:  # si on est sur un header Host
                i = self.skipHost(a, i)
                j = self.skipHost(b, j)
            elif a[i] != b[j]:
                pytest.fail(f"Error line {i}(.me) / {j}(.out) :\n.me  : \'{a[i]}\'\n.out : \'{b[j]}\'", pytrace=False)

            i += 1
            j += 1

    @staticmethod
    def getDepth(line: bytes) -> bytes:
        return line.strip(b' \t').replace(b'[', b'').split(b':')[0]

    def skipHost(self, lines: list[bytes], index) -> int:
        depth = self.getDepth(lines[index])

        for i in range(index + 1, len(lines)):
            if self.getDepth(lines[i]) == depth:
                return i

        return -1


pytest.main(sys.argv)
