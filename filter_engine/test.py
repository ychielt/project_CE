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
def f(a,b,c):
    print(a)
    print(b)
    print(c)

def g(action, *args):
    action(*args)

g(f, *["x", "y", "z"])