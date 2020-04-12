./configure --prefix=./  \
             --enable-gpl --enable-version3  --disable-mmx \
             --disable-stripping  --enable-libcronet \
             --extra-cflags=-I./external_lib/cronet/include \
             --extra-ldflags=-L./external_lib/cronet \
             --extra-libs=-lcronet.81.0.4008.1
