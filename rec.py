

from ParseMFT import ParseMFT
import json

m=ParseMFT()

source_drive=r"\\.\d:"
mft_record_num=1

r=m.get_mft_record(source_drive,mft_record_num)
mft_bytes=r[0]
mft_parsed=r[1]
print (json.dumps(mft_parsed, indent=2))
