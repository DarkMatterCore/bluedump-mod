The custom font used in the application (confont512.c) is not part of the code; the font included in libogc NEEDS to be replaced, and then you
have to recompile the whole library.

To avoid problems, I have included a copy of the modified libogc.a file. Just replace the one you already have in $(LIBOGC)/lib/wii with the
file included in this dir.