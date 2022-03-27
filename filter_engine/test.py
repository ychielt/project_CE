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
a={"a":1}
b={"a":1}
print(a==b)

