from analysis.createdir import GenerateDir
from analysis.runzeek import RunZeek
from analysis.display import DisplayResults
def welcome():
	print("Network Analysis Started\n")
	

if __name__=="__main__":
	welcome()
	zp = '/home/cdac/tools/zeek/'
	zc1 = '/home/cdac/tools/zeek/scripts/policy/frameworks/files/extract-all-files.zeek'
	zc2 = '/home/cdac/tools/zeek/scripts/policy/frameworks/files/detect-MHR.zeek'
	zc3 = '/home/cdac/tools/zeek/scripts/policy/protocols/ssh/detect-bruteforcing.zeek'
	zc4 = '/home/cdac/tools/zeek/learn/num.zeek '
	zc5 = '/home/cdac/tools/zeek/learn/credentials.zeek'
	pcap_name = input('Enter Pcap Name\n')
	gd = GenerateDir(pcap_name)
	gd.makedir()
	rz = RunZeek(pcap_name,zp,zc1,zc2,zc3,zc4,zc5)
	rz.run()
	rz.fill_lists()
	rz.calculatemetrics()
	dr = DisplayResults(rz)
	dr.displayresults()
	
