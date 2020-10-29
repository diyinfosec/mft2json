from timeit import default_timer as timer
from datetime import datetime
from ParseMFT import ParseMFT

'''
TODO: Maybe config parser to get inputs?	
TODO
source_drive	and target_path as inputs
Warning if source/target drive letters are not same
Check if you are running as administrator
List the NTFS drives
'''	

try:
	

	source_drive=r"\\.\e:"
	target_path=r"d:\\"

	filename_counter=0

	m=ParseMFT()

	#- TODO - maybe allow only 2 snapshots. 

	while True:
			if filename_counter ==0:
						print("This program will take a snapshot of the $MFT in %s and write the output file to %s"%(source_drive,target_path))
						print("You an keep taking snapshots and press ctrl+c to quit the program")
			
			input('\n\nPress enter to take a snapshot. Ctrl+c to Quit. ');
			start_time=timer()
			m.take_mft_snapshot(source_drive,target_path)
			end_time = timer()
			print("Time taken to Snapshot %2f"%(end_time-start_time))
			filename_counter=filename_counter+1
except KeyboardInterrupt:
	print("\nCancelled by user. Snapshots taken: ", filename_counter)




