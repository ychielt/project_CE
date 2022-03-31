# class A:
#     def __init__(self):
#         self.a=1
#         self.b=2
#
# class B:
#     def __init__(self):
#         self.c = A()
#         self.d="fff"
#
# b = B()
# for item in b.__dict__.items():
#     if isinstance(item[1], (int, str, list)):
#         print(item)
#     else:
#         print(item[1].__dict__)
import re
EXECUTABLE_FILES_EXTENTIONS = "(\.exe|\.dll|\.bat|\.vbs|\.pyc|\.py|\.js|\.lnk|\.cmd)"
print(re.search(EXECUTABLE_FILES_EXTENTIONS + '$', "fjvnmfr.exe"))

