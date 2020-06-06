all:
	./check-logs.py --timestamp $$(cat /home/nherbaut/flow-logs |sed -rn "s/^([0-9]+)\t.*/\1/p"|uniq|tail -n 1)
