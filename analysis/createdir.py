import os

class GenerateDir:
	def __init__(self,pcap_name):
		self.pcap_name=pcap_name

	def makedir(self):
		try:
 			if not os.path.isdir(self.pcap_name):
  				os.mkdir('dir_%s'%(self.pcap_name))
  				os.system('cp %s dir_%s'%(self.pcap_name,self.pcap_name))
  				os.system('cp desc.html dir_%s'%(self.pcap_name))
  				os.chdir('dir_%s'%(self.pcap_name))
  				os.mkdir('Images')
		except OSError:
 			print('Already executed this pcap')
 			option = input('enter \'R\' to re analysis the file\n')
 			if option == 'R' or option =='r':
  				os.system('rm -r dir_%s'%(self.pcap_name))
  				os.mkdir('dir_%s'%(self.pcap_name))
  				os.system('cp %s dir_%s'%(self.pcap_name,self.pcap_name))
  				os.system('cp desc.html dir_%s'%(self.pcap_name))
  				os.chdir('dir_%s'%(self.pcap_name))
  				os.mkdir('Images')
 			else:
  				sys.exit(0)		
