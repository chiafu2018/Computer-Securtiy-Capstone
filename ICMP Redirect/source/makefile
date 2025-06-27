CXX = g++ 

all: icmp_redirect pharm_attack 
icmp_redirect: icmp_redirect.cpp
	$(CXX) icmp_redirect.cpp -o icmp_redirect  

pharm_attack: pharm_attack.cpp 
	$(CXX) pharm_attack.cpp -o pharm_attack -lnetfilter_queue

clean: 
	rm -rf icmp_redirect pharm_attack 
