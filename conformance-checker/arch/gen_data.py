import os
import re
import sys
import pandas as pd
import matplotlib.pyplot as plt 


file_name_matcher=r"(scoi?)_(flow|intent)_([a-z0-9]+)_([0-9]+)\.csv"

data_files = [f for f in next(os.walk("."))[2] if re.match(file_name_matcher,f)]

series=[]

for f in data_files:
	df=pd.read_csv(f,sep="\t",names=["epoch","delta","error_rate","hb","hc","count_b","count_c"])
	serie=pd.Series(df["error_rate"].values,index=pd.TimedeltaIndex(df["delta"],unit="s"),name=f.split(".csv")[0].replace("_"," "))
	serie=serie.resample("1s").pad()
	series=[pd.concat([*series,serie],axis=1)]

file_name_matcher=r"faults_t[0-9]+.csv"

fault_files = [f for f in next(os.walk("."))[2] if re.match(file_name_matcher,f)]

for f in fault_files:
	df=pd.read_csv(f,sep="\t",names=["delta","fault_count"])
	serie=pd.Series(df["fault_count"].values,index=pd.TimedeltaIndex(df["delta"],unit="s"),name="fault count")
	series=[pd.concat([*series,serie],axis=1)]

series[0].to_csv("data.csv")
series[0].plot()
plt.show() 

