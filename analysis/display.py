import webbrowser
import os

class DisplayResults:

	def __init__(self,rz):
		self.uid=rz.uid
		self.list1=rz.list1
		self.gapp=rz.gapp
		self.tpc=rz.tpc
		self.bytesexchanged=rz.bytesexchanged
		self.serversent=rz.serversent
		self.clientsent=rz.clientsent
		self.ratio=rz.ratio
		self.time=rz.time
		self.spc=rz.spc
		self.T=rz.T
		self.Alpha=rz.Alpha
		self.protocols=rz.protocols
		self.ipaddr=rz.ipaddr
		self.seripaddr=rz.seripaddr
		self.cliipaddr=rz.cliipaddr
		self.services=rz.services
		self.Metrics=rz.Metrics
		self.pcap=rz.pcap

	def generateHtml(self):
		#visualise data transfer
		os.system('touch images.html')
		inp = open('images.html','w')
		if 'Images' in os.listdir():
			newhtml="<html>\n"
			for item in os.listdir(os.path.join(os.getcwd(),'Images')):
				for i in self.uid:
					if i in item:
						ind = self.uid.index(i)
				newhtml += "<h2>"+self.seripaddr[ind]+" Transmitted to and Received from "+self.cliipaddr[ind]+"</h2>\n"
				newhtml += "<img src=Images/"+item+">\n"
			newhtml+= "</html>"
		inp.writelines(newhtml)
		inp.close()

		#Analysis Results in Html
		os.system("touch results")
		r=open("results","w")
		str1="Server Client Protocol Service Totalpackets Smallpackets(<20B) Gaps T Received(B) Sent(B) Received/sent Time(Sec) Alpha\n"
		r.write(str1)
		for i in range(len(self.uid)):
			str1 = str(self.seripaddr[i])+" "+(self.cliipaddr[i])+" "+str(self.protocols[i])+" "+str(self.services[i].strip())+" "+str(self.tpc[i])+" "+str(self.spc[i])+" "+str(self.gapp[i])+" "+str(self.T[i])+" "+str(self.serversent[i])+" "+str(self.clientsent[i])+" "+str(self.ratio[i])+" "+str(self.time[i]+" "+str(self.Alpha[i])+"\n")
			r.write(str1)
		r.close()

		os.system("touch result.html")
		filein = open("results", "r")
		fileout = open("result.html", "w")
		data = filein.read()
		data = data.split("\n")

		table = "<html>\n"+"<style>\n"+"table,th,td{\n"+"border:1px solid black;\n"+"border-collapse:collapse;\n"+"}\n"
		table = table + "th,td{\n"+"padding:10px;\n"+"text-align:center;\n"+"font-size:20;\n"+"}\n"+"</style>\n"
		table = table + "<table>\n"
		table = table + "<tr>\n"+"<caption><h2>Results based on consider points </h2></caption>\n"+"</tr>\n"

		# Create the table's column headers
		header = data[0].split(" ")
		table += "  <tr>\n"
		for column in header:
			table += "    <th>{0}</th>\n".format(column.strip())
		table += "  </tr>\n"

		# Create the table's row data
		for line in data[1:len(data)-1]:
			row = line.split(" ")
			table += "  <tr>\n"
			for column in row:
				table += "    <td >{0}</td>\n".format(column.strip())
			table += "  </tr>\n"

		table += "</table>\n"
		

		#table for file names
		if 'filenames.txt' in os.listdir():
			table += "<table>\n"
			filein1 = open('filenames.txt','r')
			table = table + "<tr>\n"+"<caption><h2>Files Extracted</h2></caption>\n"+"</tr>\n"
			data = filein1.read()
			data = data.split('\n')
			header = list()
			header.append('Addresses')
			header.append('Filenames')
			table += "<tr>\n"
			for column in header:
				if column == '':
					break
				table += "    <th>{0}</th>\n".format(column.strip())
			table += "  </tr>\n"

		# Create the table's row data
			for line in data[0:len(data)-1]:
				row = line.split("\t")
				for i in self.uid:
					if i == row[0]:
						pos = self.uid.index(i)
						row[0] = self.ipaddr[pos]
				table += "  <tr>\n"
				for column in row:
					table += "    <td >{0}</td>\n".format(column.strip())
				table += "  </tr>\n"
			table += "</table>\n"

		for i in os.listdir():
			if 'png' in i:
				if self.pcap in i:
					#table += "\n<h2>Interactiveness of connection</h2>\n"
					image = i
					table += "<img src=" + image +">\n"
		table += "<h2><a href="+"images.html"+" target ="+"_blank"+">VISUALIZE DATA TRANSFER</a></h2>\n"
		table += "<footer>\n<p><a href="+"desc.html"+" target ="+"_blank"+">CLICK HERE TO KNOW ABOUT TERMINOLOGY USED</a></p>\n</footer>\n"+"</html>\n"
		fileout.writelines(table)
		fileout.close()
		filein.close()
		#os.system("rm results")


	def displayresults(self):
		if 'extract_files' in os.listdir():
			os.system('cp -r extract_files files_%s'%(self.pcap))
			os.system('rm -r extract_files')
		###if you want to know from which uri files are being requested 
		#os.sysem('cat http.log| zeek-cut uid uri>filenames.txt')
		### un hash this if you want to show the file types being transferred
			os.system('cat files.log| zeek-cut conn_uids mime_type>filenames.txt')
			print('\nFiles have been extracted\n')
		else:
			print("\nFiles transfer not found\n")
		if 'http' in self.services:
			print("no of GET's in connection")
			os.system('cat http.log|grep GET|wc -l')
			print("no of POST's in connection")
			os.system('cat http.log|grep POST|wc -l')
		if 'ssh.log' in os.listdir():
			print('\nssh connections found, please check ssh.log for more information\n')
			print('\nUID Authentication_Status\n')
			os.system('cat ssh.log | zeek-cut uid auth_success')
		if 'telnet.log' in os.listdir():
			print('telnet connections found, please check log for more information')
			os.system('cat telnet.log')
		print('success')
		self.generateHtml()
		webbrowser.open("result.html")
		
