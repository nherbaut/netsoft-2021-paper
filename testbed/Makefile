fat: clean
	sudo mn --custom ./fattree.py --topo fattree,4 --mac --switch ovsk  --controller remote
simple: clean
	sudo python minidc.py

clean: clean
	sudo mn -c
