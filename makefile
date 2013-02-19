all:
	gcc uoenc.c -o uoenc -lgcrypt
	gcc uodec.c -o uodec -lgcrypt
