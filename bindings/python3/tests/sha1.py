
"""

# todos

1. create custom python class 
2. define operations on the class 


Class name:
Sha1()
   - update(bytes) -> None
   - digest() -> bytes

Expected API:

 >>> import cgrophy
 >>> m = cgrophy.sha1()
 >>> m.update(b"Nobody inspects")
 >>> m.update(b" the spammish repetition")
 >>> m.digest()  # doctest: +ELLIPSIS
 b'\x03\x1e\xdd}Ae\x15\x93\xc5\xfe\\\x00o\xa5u+7...'

"""
