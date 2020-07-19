import os
import numpy as np
import matplotlib.pyplot as plt
import sys

class RunZeek:
	def __init__(self,pcap_name,zp,zc1,zc2,zc3,zc4):
		self.pcap=pcap_name
		#provide zeek root folder
		self.zeek_path = zp
		self.zeek_script1 = zc1
		self.zeek_script2 = zc2
		self.zeek_script3 = zc3
		self.zeek_script4 = zc4
		self.uid=list()
		self.list1=list()
		self.gapp=list()
		self.tpc=list()
		self.bytesexchanged=list()
		self.serversent=list()
		self.clientsent=list()
		self.ratio=list()
		self.time=list()
		self.spc=list()
		self.T=list()
		self.Alpha=list()
		self.protocols=list()
		self.ipaddr=list()
		self.seripaddr=list()
		self.cliipaddr=list()
		self.services=list()
		self.Metrics=list()

	def run(self):
		try:
			os.system('zeek -C -r %s %s %s %s %s> num.txt'%(self.pcap,self.zeek_script4,self.zeek_script1,self.zeek_script2,self.zeek_script3))
		except:
			print("please set zeek path in starter.py\n")
			sys.exit(0)
		os.system('cat conn.log|zeek-cut uid id.orig_h id.orig_p id.resp_h id.resp_p proto duration orig_ip_bytes resp_ip_bytes orig_pkts resp_pkts service|grep tcp >connections.txt')
		os.system("cat connections.txt | awk \'{ print $2\":\"$3}\' > ipsrc.txt")
		os.system("cat connections.txt | awk \'{ print $4\":\"$5}\' > ipdst.txt")
		os.system("cat connections.txt | awk \'{ print $7}\' > time.txt")


	def fill_lists(self):
		with open('num.txt','r') as f:
			data = f.read()
			data = data.split('\n')
			for i in data:
				l = i.split(' ')
				if l[0] == '':
					break
				if l[0] not in self.uid:
					self.uid.append(l[0])
			print("UID for connections\n",self.uid)
			for i in self.uid:
				if i == '':
					break
				for j in data:
					if j.split(' ')[0] == i:
						self.list1.append(j) 
			#print(len(list1))
 
		with open('connections.txt','r') as f:
			data = f.readlines()
			for i in self.uid:
				for l in data:
					j = l.split('\t')
					if i == j[0]:
						self.ipaddr.append(j[1]+':'+j[2]+'<->'+j[3]+':'+j[4])
						self.seripaddr.append(j[1]+':'+j[2])
						self.cliipaddr.append(j[3]+':'+j[4])
						self.tpc.append(int(j[9])+int(j[10]))
						self.bytesexchanged.append(int(j[7])+int(j[8]))
						self.serversent.append(int(j[8]))
						self.clientsent.append(int(j[7]))
						if int(j[7]) == 0 or j[7] == '-':
							self.ratio.append("nodata")
						else:
							self.ratio.append(int(int(j[8])/int(j[7])))
						self.time.append(j[6])
						self.protocols.append(j[5])
						self.services.append(j[11].strip())
		print('\nIP Addresses for UID\n',self.ipaddr)	
		

	def calculatemetrics(self):
		for i in self.uid:
			if i == '':
				break
			sor=list()
			res=list()
			orlen=list()
			reslen=list()
			ortime=list()
			restime=list()
			length=list()
			timestamp=list()
			small=0
			for j in self.list1:
				if j.split()[0] == i and j.split()[1] == 'T':
					sor.append(int(j.split(' ')[2]))
					orlen.append(int(j.split(' ')[3]))
					ortime.append(int(float(j.split(' ')[4])))
				if j.split()[0] == i and j.split()[1] == 'F':
					res.append(int(j.split(' ')[2]))
					reslen.append(int(j.split(' ')[3]))
					restime.append(int(float(j.split(' ')[4])))
				if j.split()[0] == i and int(j.split()[3]) <=20:
					small = small + 1
				if j.split()[0] == i :
					length.append(int(j.split(' ')[3]))
				if j.split()[0] == i :
					timestamp.append(float(j.split(' ')[4]))  

			#calculating T 
			self.spc.append(small)
			gap = 0
			c = 0
			for j in range(len(sor)-1):
				if(int(sor[j+1])-int(sor[j])) > 1400 :
				#if sor[j+1] != sor[j]:
					c = c+ int((int(sor[j+1])-int(sor[j]))/1400)
					#c = c + 1
			if len(sor) == 0:
				num = 0
			elif len(sor) == 1:
				num = 0 
			else: 
				num = int(sor[len(sor)-1]) - int(sor[1])
			num = int(num/1400)
			gap = gap +num- c   
			if len(res) == 0:
				num = 0
			elif len(res) == 1:
				num = 0 		
			else: 
				num = int(res[len(res)-1]) - int(res[1])
			num = int(num/1400)
			gap = gap + num
			self.gapp.append(gap) 
			pos = self.uid.index(i)
			self.T.append(float("{:.2f}".format((self.spc[pos]-gap-1)/self.tpc[pos])))

			#calculating Alpha
			c = 0
			ct = 0
			for j in range(len(length)-1) :
				if length[j] <=20 & length[j+1]<=20 :
					c = c+1
					if timestamp[j+1]-timestamp[j] < 2.0 :
						ct = ct + 1
			if c==0:
				self.Alpha.append(1)
			else:
				self.Alpha.append(float("{:.2f}".format(ct/c)))

			#visualsing data transferred
			try:
				maxtime = int(max(ortime)) if max(ortime)>max(restime) else int(max(restime))
			except(ValueError):
				print('\n\nNo payload data detected for this connection \n',self.ipaddr[self.uid.index(i)])
				continue
			temptime = [ts for ts in range(0, maxtime+1)]
			y_pos = np.array(temptime,dtype=float)
			temporig =list()
			tempresp =list()
			for k in range(len(temptime)):
				templen = 0
				for j in range(len(ortime)-1):
					if ortime[j] == k:
						templen=templen+orlen[j]
				temporig.append(templen)
			for k in range(len(temptime)):
				templen = 0
				for j in range(len(restime)-1):
					if restime[j] == k:
						templen=templen+reslen[j]
				tempresp.append(-templen)
			temporig = np.array(temporig,dtype=float)
			tempresp = np.array(tempresp,dtype=float)
			#fig=plt.get_current_fig_manager()
			#fig.resize(*fig.window.maxsize())
			fig = plt.figure(figsize=(19.20,10.80))
			plt.bar(y_pos, temporig)
			plt.bar(y_pos, tempresp)
			plt.xticks(y_pos, temptime)
			plt.xlabel("Packets over time")
			plt.ylabel("Packet size in bytes")
			plt.legend(["Bytes Transmitted", "Bytes Received"])
			plt.savefig('Images/{}.png'.format(i),bbox_inches='tight',dpi=100)
			#plt.show()

		for i in range(len(self.uid)):
			self.Metrics.append((self.Alpha[i]+self.T[i])/2) 
		fig=plt.figure()
		plt.axis([0,len(self.uid)-1,0.2,1])
		plt.plot(self.Metrics,'bo',linestyle='dashed')
		plt.xlabel('Connections')
		plt.ylabel('Avg of Metrics')
		plt.savefig('{}.png'.format(self.pcap))


	


