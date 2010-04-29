#!/bin/sh

echo "Status: 200"
#echo "X-Reproxy-URL: http://localhost/CentOS-5.4-i386-netinstall.iso"
#echo "X-Reproxy-URL: http://localhost:8888/CentOS-5.4-i386-netinstall.iso"
echo "X-Reproxy-URL: http://localhost:8888/testdata"
#echo "X-Reproxy-URL: http://localhost:8888/"
echo "Content-Range: bytes=-10/0"
echo "Content-Type: text/plain"
echo "Content-Length: 6"
echo "Last-Modified: Tue, 16 Feb 2010 13:33:05 GMT"
echo "Etag: f1352e18-4e66-4d25-8c0e-f6949ce4183b"
echo ""
echo "HELLO"
