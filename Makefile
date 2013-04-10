bitstamper: bitstamper.cpp
	g++ -O3 -I. -o bitstamper bitstamper.cpp -lssl -lcrypto
clean:
	rm bitstamper
install: bitstamper
	cp bitstamper /usr/bin
commit:
	git commit -a
	git push origin master
