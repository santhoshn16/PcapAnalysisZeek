from analysis.createdir import GenerateDir
from analysis.runzeek import RunZeek
from analysis.display import DisplayResults
def welcome():
	print("Network Analysis Started\n")
	

if __name__=="__main__":
	welcome()
	zp = '/home/ubuntu/zeek-3.1.3/'
	zc1 = '/home/ubuntu/zeek-3.1.3/scripts/policy/frameworks/files/extract-all-files.zeek'
	zc2 = '/home/ubuntu/zeek-3.1.3/scripts/policy/frameworks/files/detect-MHR.zeek'
	zc3 = '/home/ubuntu/zeek-3.1.3/scripts/policy/protocols/ssh/detect-bruteforcing.zeek'
	zc4 = '/home/ubuntu/zeek-3.1.3/learn/num.zeek '
	pcap_name = input('Enter Pcap Name\n')
	gd = GenerateDir(pcap_name)
	gd.makedir()
	rz = RunZeek(pcap_name,zp,zc1,zc2,zc3,zc4)
	rz.run()
	rz.fill_lists()
	rz.calculatemetrics()
	dr = DisplayResults(rz)
	dr.displayresults()
	
