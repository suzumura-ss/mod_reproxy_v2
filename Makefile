CXX=g++
INSTALL=install
#CFLAGS=-Wall -O3
CFLAGS=-Wall -g
CFLAGS+=-I/usr/include/httpd/ -I/usr/include/apr-1/
CFLAGS+=-shared -fPIC -lcurl -lstdc++

TARGET=mod_reproxy.so
TARGETDIR=/usr/lib/httpd/modules/

SRC=mod_reproxy.cpp curl_bucket.cpp
HEADERS=mod_reproxy.hxx



all: $(TARGET)

$(TARGET): $(SRC) $(HEADERS)
	$(CXX) $(CFLAGS) -o $(TARGET) $(SRC)

install: $(TARGET)
	sudo $(INSTALL) $(TARGET) $(TARGETDIR)

clean:
	@rm -f $(TARGET)


#--- for debug targets ---
APACHECTL=apachectl
TESTCONF=mod_reproxy.conf
TESTCONFDIR=/etc/httpd/conf.d/
TESTCGI=reproxy.cgi
TESTCGIDIR=/var/www/cgi-bin/

configtest:
	$(APACHECTL) -t

start:
	@echo -n "Starting apache..."
	@sudo $(APACHECTL) -k start
	@echo "done."

stop: __stop __wait

reload: stop start

update: stop all __install start

test:
	@sudo $(INSTALL) t/$(TESTCGI) $(TESTCGIDIR)
	@rm -f recvdata
	@curl -D /dev/tty -s localhost/cgi-bin/$(TESTCGI) > recvdata && ls -l recvdata
	@md5sum recvdata
	@echo "34c9ccca520e7c049768b672c05644a4  /var/www/html/CentOS-5.4-i386-netinstall.iso"
	@echo "7fa3d119c7cc22a752e35185fe451de0  /var/www/html/testdata"

debug: stop install
	sudo gdb /usr/sbin/httpd

__stop:
	@echo -n "Stopping apache..."
	@sudo $(APACHECTL) -k stop
	@echo "done."

__wait:
	@HTTPD=`$(APACHECTL) 2>&1 |head -1|awk '{ print $$2 }'`; \
	while [ -n "`pgrep -f $$HTTPD`" ]; do sleep 1; done

__install:
	@sudo make install
	sudo $(INSTALL) -m 644 t/$(TESTCONF) $(TESTCONFDIR)
