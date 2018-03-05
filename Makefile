all:
	g++ -lpcap -I./lib anal.cpp -o anal

ht:
	g++ -lpcap -I./lib http.cpp -o http
