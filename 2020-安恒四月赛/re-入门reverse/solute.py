
enc = 'akhb~chdaZrdaZudqduvdZvvv|'
dec = ''
for i in enc:
	tmp = (ord(i) - 1) ^ 6
	dec += chr(tmp)

print(dec)