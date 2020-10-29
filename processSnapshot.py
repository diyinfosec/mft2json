from ParseMFT import ParseMFT
import json
import os
from timeit import default_timer as timer



'''
TODO:
File should begin with magic "FILE"
File size should be a multiple of 1024
'''


inp_file_name='C_MFT_20-05-19-11_52_55.bin'
#inp_file_name='G_MFT_20-05-20-19_01_32.bin'
inp_file_name='G_MFT_20-05-23-10_15_14.bin'
inp_file_name='E_MFT_2020-05-25-17_54_25.bin'
p=ParseMFT()


out_file_name=inp_file_name+".json"

include_slack_space="N"
denormalize_output="Y"


MFT_RECORD_SIZE=p.MFT_RECORD_SIZE

#- Getting the size of the MFT file. 
inp_file_size=os.path.getsize(inp_file_name)
num_mft_recs=inp_file_size/p.MFT_RECORD_SIZE
#- Print when 5% is completed.
counter_completion=int(num_mft_recs*0.05)
print('MFT Records in this file are: ', num_mft_recs)


with open(inp_file_name,'rb') as inp_file, open(out_file_name,'w') as out_file:
	start_time=timer()
	counter=0
	while True:
		mft_bytes=p.read_mft_record(inp_file,counter*p.MFT_RECORD_SIZE)
		#print(mft_bytes)

		if len(mft_bytes) < p.MFT_RECORD_SIZE:
			break

		#- Parsing each MFT record into a dictionary. 
		#- def parse_mft_record(self,mft_record,include_slack='N',denormalize_output='N')
		d=p.parse_mft_record(mft_bytes,include_slack_space,denormalize_output)

		#print(d)
		
		
		'''
		#- Code to check if any bytes are sent as-is from the MFT record. 
		#- It is expected that bytes will be converted to a JSON serializable format in ParseMFT. 		
		for k,v in d.items():
			if type(v)is bytes:
				d[k]=v.hex()
				print(k)
				print(v)
				exit()
		'''
		if(denormalize_output=="Y"):
			for x in d:
				out_file.write(json.dumps(x)+'\n')
		else:
			out_file.write(json.dumps(d)+'\n')
		
		counter = counter +1

		if(counter%counter_completion==0):
			pct_completed=(counter*100)/num_mft_recs
			print('Records processed %d. Percentage completed: %d%%. Time Elapsed:%d'%(counter,pct_completed,timer()-start_time))


end_time = timer()
print("Time taken to process MFT %2f"%(end_time-start_time))
