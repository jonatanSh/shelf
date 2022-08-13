import os
import sys
import stat


class BaseOsUtils(object):
    def chmod_execute(self, file_path):
        raise NotImplementedError()


class LinuxOsUtils(BaseOsUtils):
    def chmod_execute(self, file_path):
        st = os.stat(file_path)
        os.chmod(file_path, st.st_mode | stat.S_IEXEC)


if "linux" in sys.platform:
    OsUtils = LinuxOsUtils()
else:
    OsUtils = BaseOsUtils()
