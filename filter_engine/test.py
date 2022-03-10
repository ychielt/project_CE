import re

s = "aabbcc.batddeeff.xe"
if re.search("(\.exe|\.dll|\.bat)", s):
    print("aa")
