from datetime import datetime
from hashlib import sha1
import json
'''
import win32api

drives = win32api.GetLogicalDriveStrings()
drives = drives.split('\000')[:-1]
print(drives)

'''


class ParseMFT:
	SECTOR_SIZE = 512
	MFT_RECORD_SIZE = 1024
	FILENAME_NOT_FOUND_STR="Filename_not_found"

	def parse_boot_record(self,first_sector):
			#- Reading the BIOS parameter block and locating the $MFT
			#- TODO - Derive size of the MFT record from the BPB

			'''
			11 - Bytes per sector - 2 bytes
			13 - Sectors per cluster - 1 byte
			48 - MFT Cluster Number - 8 bytes
			Ref: https://www.delftstack.com/howto/python/how-to-convert-bytes-to-integers/
			'''
			bytes_per_sector = int.from_bytes(first_sector[11:13:],byteorder='little')
			sectors_per_cluster = int.from_bytes(first_sector[13:14:],byteorder='little')
			cluster_size = bytes_per_sector * sectors_per_cluster
			mft_cluster_num = int.from_bytes(first_sector[48:56:],byteorder='little')		
			
			mft_offset = (mft_cluster_num * cluster_size) 

			print('Bytes per sector is %s'%(bytes_per_sector))
			print('Sectors per cluster is %s'%(sectors_per_cluster))
			print('MFT cluster number is %s'%(mft_cluster_num))
			print('Offset to MFT is %s'%(mft_offset))

			d={}

			d['cluster_size'] = cluster_size
			d['mft_offset'] = mft_offset

			return d

	def read_mft_record(self,fd,offset):
			#- Reading the FILE record of $MFT
			#- Seek should ALWAYS be a multiple of sector size for direct disk access. 
			#- Refer: https://support.microsoft.com/en-ie/help/100027/info-direct-drive-access-under-win32
			fd.seek(offset)		
			return fd.read(ParseMFT.MFT_RECORD_SIZE)

	def parse_mft_flags(self,mft_flag):
		d={}
		d['mft_in_use_flg'] = 0
		d['mft_is_dir_flg'] = 0
		d['mft_is_4_flg'] = 0
		d['mft_is_view_idx_flg'] = 0
		d['mft_flag_unknown'] = 0
		
		#- Handling the MFT header flags. 
		#- [MFT_RECORD_IN_USE: 1], 
		#- [MFT_RECORD_IS_DIRECTORY: 2],[MFT_RECORD_IS_4: 4], [MFT_RECORD_IS_VIEW_INDEX: 8]
		#- The MFT flags is a 2 byte field, which contains the sum of the above properties. 
		#- 0= Deleted File, 1 = In use file, 2 = Deleted Directory, 3 = In-use Directory

		if(mft_flag==0):
			d['mft_in_use_flg'] = 0
			d['mft_is_dir_flg'] = 0
		elif(mft_flag==1):
			d['mft_in_use_flg'] = 1
			d['mft_is_dir_flg'] = 0
		elif(mft_flag==2):
			d['mft_in_use_flg'] = 0
			d['mft_is_dir_flg'] = 1
		elif(mft_flag==3):
			d['mft_in_use_flg'] = 1
			d['mft_is_dir_flg'] = 1
		elif(mft_flag==4):
			d['mft_is_4_flg'] = 1
			d['mft_in_use_flg'] = 0
		elif(mft_flag==5):
			d['mft_is_4_flg'] = 1
			d['mft_in_use_flg'] = 1
		elif(mft_flag==8):
			d['mft_is_view_idx_flg'] = 1
			d['mft_in_use_flg'] = 0
		elif(mft_flag==9):
			d['mft_is_view_idx_flg'] = 1
			d['mft_in_use_flg'] = 1
		elif(mft_flag==12):
			d['mft_is_4_flg'] = 1
			d['mft_is_view_idx_flg'] = 1
			d['mft_in_use_flg'] = 0
		elif(mft_flag==13):
			d['mft_is_4_flg'] = 1
			d['mft_is_view_idx_flg'] = 1
			d['mft_in_use_flg'] = 1
		else:
			d['mft_flag_unknown'] =1

		return d

	def parse_mft_record(self,mft_record,include_slack_space='N',denormalize_output='N'):

		#- Dictionary to hold the parsed fields in the MFT record. 
		d={}

		#- If the set of bytes begins with FILE then it's a valid MFT record. 
		#-  otherwise set the valid flat to N and return. 
		#- TODO: There could be other beginnings to the MFT record as well. 
		d['mft_signature']=mft_record[0:4].hex()

		if d['mft_signature'] == '46494c45':
			#print("File record!")
			d['mft_is_valid_record']='Y'
			d['mft_update_seq_offset'] = int.from_bytes(mft_record[4:6],byteorder='little')
			d['mft_update_seq_size'] = int.from_bytes(mft_record[6:8],byteorder='little')
			d['mft_logfile_seq'] = int.from_bytes(mft_record[8:16],byteorder='little')
			d['mft_seq_num'] = int.from_bytes(mft_record[16:18],byteorder='little')
			d['mft_hardlink_count'] = int.from_bytes(mft_record[18:20],byteorder='little')
			d['mft_first_attr_offset'] = int.from_bytes(mft_record[20:22],byteorder='little')
			
			mft_flag=int.from_bytes(mft_record[22:24],byteorder='little')
			d['mft_flg_value']=mft_flag
			flag_d=self.parse_mft_flags(mft_flag)
			d.update(flag_d)


			d['mft_real_size'] = int.from_bytes(mft_record[24:28],byteorder='little')
			d['mft_allocated_size'] = int.from_bytes(mft_record[28:32],byteorder='little')
			
			#-Parsing base record. 
			d['mft_base_id'] = int.from_bytes(mft_record[32:38],byteorder='little')
			d['mft_base_seq_num'] = int.from_bytes(mft_record[38:40],byteorder='little')

			d['mft_next_attr_num'] = int.from_bytes(mft_record[40:42],byteorder='little')
			d['mft_reserved'] = int.from_bytes(mft_record[42:44],byteorder='little')
			d['mft_id'] = int.from_bytes(mft_record[44:48],byteorder='little')
			d['mft_update_seq_num'] = mft_record[48:50].hex()

			mft_header_size = 50+(d['mft_update_seq_size']*2)
			update_seq_array = mft_record[50:mft_header_size]

			d['mft_update_seq_array'] = update_seq_array.hex()

			#- Setting the effective MFT ID.
			#- For most cases this will be the mft_id of the record. 
			#- In rare occasions, where a file is spread over multiple records this field will have the mft_id of the parent (first) MFT record.
			if(d['mft_base_id']==0):
				d['eff_mft_id']=d['mft_id']
			else:
				d['eff_mft_id']=d['mft_base_id']

			#- Apply fix up:
			fixed_up_mft_record=self.apply_fixup(mft_record,update_seq_array)

			#- The body of the MFT record. This will contain all the attributes. 
			mft_body=fixed_up_mft_record[mft_header_size:d['mft_real_size']]


			#- Getting the slack information. 
			mft_slack_len=d['mft_allocated_size']-d['mft_real_size']
			mft_slack=fixed_up_mft_record[d['mft_real_size']:].hex()

			#- Calculate SHA1 of the MFT body
			d['mft_body_sha1']=sha1(mft_body).hexdigest()
			#print(d)

			'''
			#- TODO: This should move into Attribute Parser
			#- TODO: this can be deleted, along with the get_fn_from_mft_rec_body function. 
			#- If it is a non-base record, don't bother looking for the FILENAME attribute. 
			if(d['mft_base_id']==0):
				d['file_name']=self.get_fn_from_mft_rec_body(mft_body)
			else:
				d['file_name'] = ParseMFT.FILENAME_NOT_FOUND_STR
			'''
		
			#- MFT Body parsing
			l=self.parse_mft_body(mft_body)
			#print(l)
			d['mft_end_marker']=l[-3]
			d['mft_unknown1']=l[-2]
			d['mft_filename']=l[-1]

			#- Setting the MFT body ignoring the last three fields. These are the end marker,  unknown1 and mft_filenamein the list. 
			mft_body_parsed=l[:-3]

			#- If we need to normalize the output then we take the MFT header fields and prefix it on top of each attribute. 
			tmp_attr_d={}
			tmp_attr_l=[]
			if(denormalize_output=="Y"):
				#- Handling the MFT header fields, these will be considered as a separate attribute.
				#- TODO: Review this approach
				attribute_zero=d
				d['attr_type']="0x00"
				d['attr_type_str']="$MFT_HEADER"
				tmp_attr_l.append(d)

				
				req_keys_l=['mft_is_valid_record','mft_in_use_flg','mft_is_dir_flg','mft_id','eff_mft_id','mft_base_id','mft_base_seq_num','mft_filename']
				mft_header={k:d[k] for k in req_keys_l}
				#print(mft_header)
				#mft_header=d
				tmp_attr_d={}
				for attribs in mft_body_parsed:
					#print(attribs)
					#- {'attr_type': '0x30', 'attr_len': 104, 'attr_non_res_flg': 0, 'attr_name_len': 0, 'attr_name_offset': 24, 'attr_flags': 0, 'attr_id': 3, 'attr_body_len': 74, 'attr_body_offset': 24, 'attr_idx_flg': 1, 'attr_padding': 0, 'attr_body': {'fn_parent_dir_mft_id': 5, 'fn_parent_dir_seq_num': 5, 'fn_btime': 132319692985103424, 'fn_mtime': 132319692985103424, 'fn_ctime': 132319692985103424, 'fn_atime': 132319692985103424, 'fn_file_alloc_size': 16384, 'fn_file_real_size': 16384, 'fn_flags': 6, 'fn_ea_rp_bytes': 0, 'fn_filename_len': 4, 'fn_filename_ns': 3, 'fn_filename': '$MFT'}}
					
					for attr_header_key,attr_header_value in attribs.items():

						if(attr_header_key!='attr_body'):
							tmp_attr_d[attr_header_key]=attr_header_value
						else:
							for attr_body_key, attr_body_value in attr_header_value.items():
								tmp_attr_d[attr_body_key]=attr_body_value
					
					#- Append the MFT header to every attribute information dict. 
					tmp_attr_d.update(mft_header)
					#- This new dict is now appended to a list. 
					#- This completes the normalization. Now you will have a MFT record header for EVERY attribute. 
					tmp_attr_l.append(tmp_attr_d)
					tmp_attr_d={}
				if(include_slack_space=='Y'):
					#-TODO: Review, you are assuming that the slack will have an attribute type of 0xFF. 
					tmp_attr_d['attr_type']='0xFF'
					tmp_attr_d['mft_slack']=mft_slack
					#- Append the MFT header with the slack. We are also treating slack as a separate "attribute"
					tmp_attr_d.update(mft_header)
					tmp_attr_l.append(tmp_attr_d)

				#print(tmp_attr_l)
				d=tmp_attr_l
			else:
				d['mft_body']=mft_body_parsed
				if(include_slack_space=='Y'):
					d['mft_slack']=mft_slack
					

			#- TODO: Some notes about slack processing here. Check. 
			#- TODO: Check for zero buffer, send only non-zero slack. Add an 'mft_slack_len' and 'mft_slack_zero_flg'			
			#- https://stackoverflow.com/questions/18841108/how-to-check-if-byte-contains-only-zeros/18841123
			#- Generators: https://stackoverflow.com/questions/3525953/check-if-all-values-of-iterable-are-zero/3526286

		else:
			d['mft_is_valid_record']='N'
			d['mft_body_sha1'] = 'dummy'
			if(denormalize_output=="Y"):
				l=[d]
				d=l
			#print('Not a FILE record %s',mft_record[0:4])
		
		#- The return value. 
		#- If denormalize_output is "N" then this returns a dictionary containing a parsed MFT record. 
		#- If denormalize_output is "Y" the this returns a list of dictionaries. Each entry in the list will be an attribute dictionary. 
		return d


	def parse_attribute_body(self,attr_type,attr_body,additional_info=[]):
		d={}
		if(attr_type==0x10):
			d['si_btime'] = self.process_filetime(int.from_bytes(attr_body[0:8],byteorder='little'))
			d['si_mtime'] = self.process_filetime(int.from_bytes(attr_body[8:16],byteorder='little'))
			d['si_ctime'] = self.process_filetime(int.from_bytes(attr_body[16:24],byteorder='little'))
			d['si_atime'] = self.process_filetime(int.from_bytes(attr_body[24:32],byteorder='little'))
			d['si_dos_perms'] = int.from_bytes(attr_body[32:36],byteorder='little')
			d['si_max_versions'] = int.from_bytes(attr_body[36:40],byteorder='little')
			d['si_version_num'] = int.from_bytes(attr_body[40:44],byteorder='little')
			d['si_class_id'] = int.from_bytes(attr_body[44:48],byteorder='little')
			d['si_owner_id'] = int.from_bytes(attr_body[48:52],byteorder='little')
			d['si_security_id'] = int.from_bytes(attr_body[52:56],byteorder='little')
			d['si_quota_charged'] = int.from_bytes(attr_body[56:64],byteorder='little')
			d['si_usn'] = int.from_bytes(attr_body[72:80],byteorder='little')
		elif(attr_type==0x30):
			d['fn_parent_dir_mft_id'] = int.from_bytes(attr_body[0:6],byteorder='little')
			d['fn_parent_dir_seq_num'] = int.from_bytes(attr_body[6:8],byteorder='little')
			d['fn_btime'] = self.process_filetime(int.from_bytes(attr_body[8:16],byteorder='little'))
			d['fn_mtime'] = self.process_filetime(int.from_bytes(attr_body[16:24],byteorder='little'))
			d['fn_ctime'] = self.process_filetime(int.from_bytes(attr_body[24:32],byteorder='little'))
			d['fn_atime'] = self.process_filetime(int.from_bytes(attr_body[32:40],byteorder='little'))
			d['fn_file_alloc_size'] = int.from_bytes(attr_body[40:48],byteorder='little')
			d['fn_file_real_size'] = int.from_bytes(attr_body[48:56],byteorder='little')
			d['fn_flags'] = int.from_bytes(attr_body[56:60],byteorder='little')
			d['fn_ea_rp_bytes'] = int.from_bytes(attr_body[60:64],byteorder='little')
			d['fn_filename_len'] = int.from_bytes(attr_body[64:65],byteorder='little')
			d['fn_filename_ns'] = int.from_bytes(attr_body[65:66],byteorder='little')
			d['fn_filename'] = attr_body[66:66+(2*d['fn_filename_len'])].decode('utf-16')
		#- https://flatcap.org/linux-ntfs/ntfs/attributes/object_id.html
		elif(attr_type==0x40):
			d['oi_object_id'] = attr_body[0:16].hex()
			d['oi_birth_volume_id'] = attr_body[16:32].hex()
			d['oi_birth_object_id'] = attr_body[32:48].hex()
			d['oi_domain_id'] = attr_body[48:64].hex()
		elif(attr_type==0x80 and additional_info[0]=='Zone.Identifier'):
			zone_data_l=attr_body.decode('ascii').splitlines()
			#print(zone_data_l)
			counter=1
			for x in zone_data_l:
				key_prefix='ads_zi_'

				y=x.split('=',1)
				if len(y)==1:
					d[key_prefix+"key_"+str(counter)] = y[0]
					#print(y[0],'counter is ',counter)
					counter=counter+1
				elif len(y)==2:
					d[key_prefix + str(y[0])]=y[1]
			
			#- {'ads_zi_key_1': '[ZoneTransfer]', 'ads_zi_ZoneId': '3', 'ads_zi_ReferrerUrl': 'https://www.education.com/download/worksheet/98610/tangram-puzzle-9.pdf', 'ads_zi_HostUrl': 'https://www.education.com/download/worksheet/98610/tangram-puzzle-9.pdf'}
			#print(d)
		elif(attr_type==0x90):
			d['ir_entry_type'] = self.attr_type_lookup(hex(int.from_bytes(attr_body[0:4],byteorder='little')))
			d['ir_collation_rule'] = int.from_bytes(attr_body[4:8],byteorder='little')
			d['ir_bytes_per_idx_record'] = int.from_bytes(attr_body[8:12],byteorder='little')
			d['ir_clusters_per_idx_record'] = int.from_bytes(attr_body[12:13],byteorder='little')
			#- TODO: Check if there could be more index node headers. 
			#- This has 4 bytes each of:  offset_to_first_idx_entry, total_idx_entry_size, allocated_idx_entry_size, flag
			d['ir_idx_entry_offset'] = int.from_bytes(attr_body[13:17],byteorder='little')
			d['ir_idx_entry_total_size'] = int.from_bytes(attr_body[17:21],byteorder='little')
			d['ir_idx_entry_alloc_size'] = int.from_bytes(attr_body[21:25],byteorder='little')
			d['ir_idx_header_flags'] = int.from_bytes(attr_body[25:29],byteorder='little')
			
	
			'''
			#- If we have 0x100 as a resident attribute then it means it's part of Transactional NTFS> 
			elif(attr_type==0x100):
				d['tx_unknown1'] = int.from_bytes(attr_body[0:6],byteorder='little')
				d['tx_mft_id'] = int.from_bytes(attr_body[6:14],byteorder='little')
				d['tx_usn_index'] = int.from_bytes(attr_body[14:22],byteorder='little')
				d['tx_file_id'] = int.from_bytes(attr_body[22:30],byteorder='little')
				d['tx_data_lsn'] = int.from_bytes(attr_body[30:38],byteorder='little')
				d['tx_metadata_lsn'] = int.from_bytes(attr_body[38:46],byteorder='little')
				d['tx_dir_idx_lsn'] = int.from_bytes(attr_body[46:54],byteorder='little')
				d['tx_flags'] = int.from_bytes(attr_body[54:56],byteorder='little')		
			'''
		else:
			d['attr_body_unparsed']=attr_body.hex()

		return d


	#- This function will convert FILETIME to Unix epoch milliseconds
	#- TODO: Take the outputformat as an argument. 
	def process_filetime(self,inp_filetime,out_format="unix_epoch_millis"):
		#- Number of 100ns between 01-Jan-1601 and 01-Jan-1970. 
		ns_till_unix_epoch=116444736000000000

		if(out_format=="unix_epoch_millis"):
			inp_epoch_ns=(inp_filetime-ns_till_unix_epoch)
			#- Converting 100nanoseconds to milliseconds
			out_time=int(inp_epoch_ns/10000)
		elif(out_format=="unix_epoch_nanos"):
			out_time=(inp_filetime-ns_till_unix_epoch)

		return out_time

	def get_fn_from_mft_rec_body(self,mft_body):

		start=0
		file_name= ParseMFT.FILENAME_NOT_FOUND_STR
		while True:
			#print('Start value is now ', start)
			#print('Length of mft body is ', len(mft_body))
			attr_type=int.from_bytes(mft_body[start:start+4],byteorder='little')
			
			if attr_type!= 48:
				attr_len=int.from_bytes(mft_body[start+4:start+8],byteorder='little')
			else:
				file_name_len=int.from_bytes(mft_body[start+88:start+89],byteorder='little')*2
				file_name=mft_body[start+90:start+90+file_name_len].decode('utf-16')
				break

			start=start+attr_len

			if(start >= len(mft_body)-8):
				break
		#print(file_name)
		return file_name
#@profile 
	def parse_mft_body(self,mft_body):
		out_l=[]
		tmp_d=[]
		mft_filename=self.FILENAME_NOT_FOUND_STR

		start=0
		mft_body_len=len(mft_body)

		while start < mft_body_len:
			d={}
			attr_type=int.from_bytes(mft_body[start:start+4],byteorder='little')
			#- Checking for end marker
			if(attr_type==0xffffffff):
				out_l.append(hex(attr_type))
				out_l.append(mft_body[start+4:mft_body_len].hex())
				break

			#- Reference for this section: https://flatcap.org/linux-ntfs/ntfs/concepts/attribute_header.html
			d['attr_type']=hex(attr_type)
			d['attr_type_str']=self.attr_type_lookup(d['attr_type'])


			attr_len=int.from_bytes(mft_body[start+4:start+8],byteorder='little')
			d['attr_len']= attr_len


			d['attr_non_res_flg']=int.from_bytes(mft_body[start+8:start+9],byteorder='little')
			#- Multiplying by two as the name is stored in Unicode (UTF-16?)
			d['attr_name_len']=int.from_bytes(mft_body[start+9:start+10],byteorder='little')*2
			d['attr_name_offset']=int.from_bytes(mft_body[start+10:start+12],byteorder='little')
			#- 0x0001	Compressed,  0x4000	Encrypted, 0x8000	Sparse
			d['attr_flags']=int.from_bytes(mft_body[start+12:start+14],byteorder='little')
			d['attr_id']=int.from_bytes(mft_body[start+14:start+16],byteorder='little')

			#- Attribute body - setting it as a dictionary
			
			
			#- Handling non-resident attributes
			if(d['attr_non_res_flg']==1):
				d['attr_start_vcn']=int.from_bytes(mft_body[start+16:start+24],byteorder='little')
				d['attr_last_vcn']=int.from_bytes(mft_body[start+24:start+32],byteorder='little')
				d['attr_body_offset']=int.from_bytes(mft_body[start+32:start+34],byteorder='little')
				d['attr_compr_unit_size']=int.from_bytes(mft_body[start+34:start+36],byteorder='little')
				d['attr_padding']=int.from_bytes(mft_body[start+36:start+40],byteorder='little')
				d['attr_alloc_size']=(int.from_bytes(mft_body[start+40:start+48],byteorder='little'))
				d['attr_real_size']=(int.from_bytes(mft_body[start+48:start+56],byteorder='little'))
				d['attr_init_size']=(int.from_bytes(mft_body[start+56:start+64],byteorder='little'))
				name_offset=start+64
				#- Handling attribute name.
				#- TODO: maybe this is unicode. Test with ADS. 
				if(d['attr_name_len']>0):
					d['attr_name']=mft_body[name_offset:name_offset+d['attr_name_len']].decode('utf-16')
					#print('Inside attribute name >0')
					#print('Attribute name length is', d['attr_name_len'])
					#print('Attribute name is ',d['attr_name'])
				
				#- Body of the attribute. In case of a non-resident attribute, this will just be a data run. 
				d['attr_body']={}
				attr_body=mft_body[start+d['attr_body_offset']:start+attr_len]
				d['attr_body']['data_runs']=self.parse_data_runs(attr_body)


			#- Handling resident attributes.
			elif(d['attr_non_res_flg']==0):
				d['attr_body_len']=int.from_bytes(mft_body[start+16:start+20],byteorder='little')
				d['attr_body_offset']=int.from_bytes(mft_body[start+20:start+22],byteorder='little')
				d['attr_idx_flg']=int.from_bytes(mft_body[start+22:start+23],byteorder='little')
				d['attr_padding']=int.from_bytes(mft_body[start+23:start+24],byteorder='little')
				name_offset=start+24
				#- Body of the attribute. In case of a resident attribute, this can be anything!
				attr_body=mft_body[start+d['attr_body_offset']:start+attr_len]
				#- Handling attribute name.
				if(d['attr_name_len']>0):
					d['attr_name']=mft_body[name_offset:name_offset+d['attr_name_len']].decode('utf-16')
				else:
					d['attr_name']=''
				
				#- Parsing the attribute  body:
				d['attr_body']={}
				d['attr_body']=self.parse_attribute_body(attr_type,attr_body,[d['attr_name']])

				#-rampa
				if('fn_filename' in d['attr_body']):
					mft_filename=d['attr_body']['fn_filename']

			out_l.append(d)
			start=start+d['attr_len']

		out_l.append(mft_filename)
		return out_l


	def attr_type_lookup(self,inp_attr_type):
		d={
		'0x10':'$STANDARD_INFORMATION',
		'0x20':'$ATTRIBUTE_LIST',
		'0x30':'$FILE_NAME',
		'0x40':'$VOLUME_VERSION',
		'0x40':'$OBJECT_ID',
		'0x50':'$SECURITY_DESCRIPTOR',
		'0x60':'$VOLUME_NAME',
		'0x70':'$VOLUME_INFORMATION',
		'0x80':'$DATA',
		'0x90':'$INDEX_ROOT ',
		'0xa0':'$INDEX_ALLOCATION ',
		'0xb0':'$BITMAP ',
		'0xc0':'$SYMBOLIC_LINK ',
		'0xc0':'$REPARSE_POINT',
		'0xd0':'$EA_INFORMATION',
		'0xe0':'$EA',
		'0xf0':'$PROPERTY_SET',
		'0x100':'$LOGGED_UTILITY_STREAM'
		}

		if not inp_attr_type in d:
			return 'UNKNOWN_ATTRIBUTE'
		else:
			return(d[inp_attr_type])



	def apply_fixup(self,mft_record,update_seq_array):
			#- TODO: NOt sure if I should get this from BPB
			tmp_rec_size = ParseMFT.MFT_RECORD_SIZE
			sector_size = ParseMFT.SECTOR_SIZE
			tmp_mft_data = b''
			counter=0

			#- Loop till you get through all the clusters
			while tmp_rec_size >=sector_size:
				#- start_size will begin at 0 and increment by sector offset. 
				start_size=int(sector_size*(counter/2))
				
				#- Part1 will be all but last 2 bytes of the sector. 
				part1=mft_record[start_size:(start_size+sector_size-2)]
				#- Part2 will be the corresponding bytes in the Update Sequence Array. 
				part2=update_seq_array[counter:counter+2]
				#- Once done processing the sector, reduce the tmp_rec_size
				tmp_rec_size = tmp_rec_size - sector_size
				#- Append the fixup applied sector to tmp_mft_data. 
				tmp_mft_data = tmp_mft_data + part1 + part2
				#- Increment the counter
				counter=counter+2
			
			#print('Fixup done')
			
			return tmp_mft_data


	def parse_data_runs(self,data_run_bytes):
		#- TODO - This can be generic like icat 
		bytes_to_skip=0
		counter=1
		data_run_list=[]
		prev_cluster_offset=0
		for x in data_run_bytes:
			if bytes_to_skip==0:
				#- Added to handle last data run (which is always 00)
				#- Ref: https://flatcap.org/linux-ntfs/ntfs/concepts/data_runs.html
				if int(x)==0:
					break

				x=format(x,'02x')
				val1=int(x[1])
				val2=int(x[0])

				#- Take val1 bytes, this will be the num_clusters
				num_clusters = int.from_bytes(data_run_bytes[counter:counter+val1], byteorder='little')
				#print(num_clusters)
				
				#- Take val2 bytes, this will be the cluster_offset
				#- Interpreting Cluster Offset as a 'Signed' integer as per: https://www.sciencedirect.com/topics/computer-science/starting-cluster
				cluster_offset = int.from_bytes(data_run_bytes[counter+val1:counter+val1+val2], byteorder='little', signed=True) + prev_cluster_offset
				#print(cluster_offset)

				prev_cluster_offset = cluster_offset

				#data_run_list.append([cluster_offset, num_clusters])
				data_run_list.append({'dr_offset':cluster_offset, 'dr_cluster_count':num_clusters})

				bytes_to_skip=val1 + val2
			else:
				bytes_to_skip=bytes_to_skip-1
			counter=counter+1

		#print(data_run_list)
		return data_run_list	
		#print(len(data_run_list))


	def take_mft_snapshot(self,drive_letter,target_path):
		source_drive=rf"\\.\{drive_letter}:"
		#- Open the file
		with open(source_drive,'rb') as f:
			#- We are actually reading the volume boot record. Using the same function to read MFT record for this as well. 
			#- End of the day you will get 1024 bytes from the offset, that's all. 
			first_bytes=self.read_mft_record(f,0)

			#- Get all the metadata you need to dump the $MFT file.
			boot_data=self.parse_boot_record(first_bytes)
			cluster_size=boot_data['cluster_size']
			mft_offset=boot_data['mft_offset']
			mft_record_zero = self.read_mft_record(f, mft_offset) 

			#-Getting the MFT record body for $MFT. This will have the attribute list. 
			rec_zero_body=self.parse_mft_record(mft_record_zero)['mft_body']

			for attribs in rec_zero_body:
				if(attribs['attr_type']=="0x80"):
					#print(' data attribute')
					#print(attribs)
					mft_data_run_list=attribs['attr_body']['data_runs']
					break

			#- Auto-generating filename along with timestamp for the snapshot. 
			now = datetime.now()
			timestamp=now.strftime('%Y-%m-%d-%H_%M_%S')
			snapshot_filename=target_path+ "MFT_"+str(timestamp) + ".bin"
			print(snapshot_filename)

			#- Open snapshot file in binary mode for writing
			snapshot_file = open(snapshot_filename, "wb")

			
			#- Walking through the Data Runs and writing bytes to the snapshot file
			for x in mft_data_run_list:
				#- Get the offset and the number of bytes required from that offset. 
				start_offset=x['dr_offset']*cluster_size
				total_bytes=x['dr_cluster_count']*cluster_size
				
				#- Seek to the offset in the $MFT file. 
				f.seek(start_offset)

				#- Read the total number of bytes required. 
				mft_bytes=f.read(total_bytes)

				#- Write the bytes read from $MFT into the snapshot file
				snapshot_file.write(mft_bytes)



	def process_mft_snapshot(self,file_name):
		l=[]
		with open(file_name,'rb') as f:
			counter=0
			while True:
				mft_bytes=self.read_mft_record(f,counter*ParseMFT.MFT_RECORD_SIZE)
				#print(mft_bytes)

				if len(mft_bytes) < ParseMFT.MFT_RECORD_SIZE:
					break

				#- Parsing each MFT record into a dictionary. 
				d=self.parse_mft_record(mft_bytes)

				#- Appending the dictionary to a list
				l.append(d)
				
				counter = counter +1

		#- Return the list containing processed MFT records
		return l


	#- TODO: just pass the drive letter and add the slashes later.
	def get_mft_record(self,drive_letter,mft_record_num):
		source_drive=rf"\\.\{drive_letter}:"
		if(not isinstance(mft_record_num,int) or mft_record_num<0):
			print("Invalid MFT record number: ", mft_record_num)
			exit()
		#- Open the drive
		with open(source_drive,'rb') as f:
			#- We are actually reading the volume boot record. Using the same function to read MFT record for this as well. 
			#- End of the day you will get 1024 bytes from the offset, that's all. 
			first_bytes=self.read_mft_record(f,0)

			#- Get all the metadata you need to dump the $MFT file.
			boot_data=self.parse_boot_record(first_bytes)
			cluster_size=boot_data['cluster_size']
			mft_offset=boot_data['mft_offset']
			mft_record_zero = self.read_mft_record(f, mft_offset) 

			#-Getting the MFT record body for $MFT. This will have the attribute list. 
			rec_zero_body=self.parse_mft_record(mft_record_zero)['mft_body']
			
			#- Get the data runs from the $MFT body 
			for attribs in rec_zero_body:
				if(attribs['attr_type']=="0x80"):
					#print(' data attribute')
					#print(attribs)
					mft_data_run_list=attribs['attr_body']['data_runs']
					break

			'''
			#- Auto-generating filename along with timestamp for the snapshot. 
			now = datetime.now()
			timestamp=now.strftime('%Y-%m-%d-%H_%M_%S')
			snapshot_filename=target_path+ "MFT_"+str(timestamp) + ".bin"
			print(snapshot_filename)
			
			#- Open snapshot file in binary mode for writing
			snapshot_file = open(snapshot_filename, "wb")
			'''
			seek_offset=(mft_record_num-1)*self.MFT_RECORD_SIZE
			seek_offset=(0 if seek_offset<0 else seek_offset)

			mft_record_bytes=b''

			#- Walking through the Data Runs and writing bytes to the snapshot file
			for x in mft_data_run_list:
				#- Get the offset and the number of bytes required from that offset. 
				start_offset=x['dr_offset']*cluster_size
				data_run_bytes=x['dr_cluster_count']*cluster_size

				#- The record we want is not in this data run
				if seek_offset>data_run_bytes:
					seek_offset=seek_offset-data_run_bytes
					continue 

				#- Seek to the offset in the $MFT file. 
				f.seek(start_offset)

				#- Read the total number of bytes in the data run. 
				mft_record_bytes=f.read(self.MFT_RECORD_SIZE)

			#print(mft_record_bytes)

			parsed_mft_record={}
			if mft_record_bytes!=b'':
				parsed_mft_record=self.parse_mft_record(mft_record_bytes,include_slack_space='N',denormalize_output='N')

			return(mft_record_bytes,parsed_mft_record)




