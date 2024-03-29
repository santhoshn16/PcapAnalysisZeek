import os
import numpy as np
import matplotlib.pyplot as plt
import sys,re

class RunZeek:
	def __init__(self,pcap_name,zp,zc1,zc2,zc3,zc4,zc5):
		self.pcap=pcap_name
		#provide zeek root folder
		self.zeek_path = zp
		self.zeek_script1 = zc1
		self.zeek_script2 = zc2
		self.zeek_script3 = zc3
		self.zeek_script4 = zc4
		self.zeek_script5 = zc5
		self.uid=list()
		self.nd=dict()
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
		self.avgsize=list()
		self.avginterval=list()

	def run(self):
		try:
			os.system('zeek -C -r %s %s %s %s %s %s> num.txt'%(self.pcap,self.zeek_script4,self.zeek_script1,self.zeek_script2,self.zeek_script3,self.zeek_script5))
			
		except:
			print("please set zeek path in starter.py\n")
			sys.exit(0)
		os.system('cat conn.log|zeek-cut uid id.orig_h id.orig_p id.resp_h id.resp_p proto duration orig_ip_bytes resp_ip_bytes orig_pkts resp_pkts service|grep tcp >connections.txt')
		os.system("cat connections.txt | awk \'{ print $2\":\"$3}\' > ipsrc.txt")
		os.system("cat connections.txt | awk \'{ print $4\":\"$5}\' > ipdst.txt")
		os.system("cat connections.txt | awk \'{ print $7}\' > time.txt")
		os.system("cat num.txt | awk \'{print $1}\' | sort | uniq > uid.txt")



	def fill_lists(self):
		with open('uid.txt','r') as f:
			data = f.read()
			data = data.split("\n")
			for i in data:
				if i == '':
					continue
				self.uid.append(i)
			print("UID for connections\n",self.uid)
 
		with open('num.txt','r') as f:
			data = f.read()
			data = data.split("\n")
			for i in range(len(self.uid)):
				if self.uid[i] == '':
					continue
				r = re.compile(r"%s"%self.uid[i])
				self.nd[self.uid[i]] = list(filter(r.match,data))
		
		#print(self.nd)
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
		f = open('num.txt','r')
		data = f.read()
		data = data.split("\n")
		for i in self.uid:
			sam = 'F'
			sam1 = 'F'
			l=0
			new_gap = 0
			if i == '':
				break
			orlen=list()
			reslen=list()
			ortime=list()
			restime=list()
			length=list()
			lengthforalpha=list()
			timestamp=list()
			timestampforalpha=list()
			small=0
			r = re.compile(r"%s"%i)
			self.nd[i] = list(filter(r.match,data))
			for j in self.nd[i]:
				if j.split()[0] == i and j.split()[1] == 'T':
					orlen.append(int(j.split(' ')[3]))
					ortime.append(int(float(j.split(' ')[4])))
				if j.split()[0] == i and j.split()[1] == 'F':
					reslen.append(int(j.split(' ')[3]))
					restime.append(int(float(j.split(' ')[4])))
				if j.split()[0] == i :
					timestamp.append(float(j.split(' ')[4]))
					length.append(int(j.split(' ')[3]))
					if j.split()[1] == 'T':
						lengthforalpha.append(int(j.split(' ')[3]))
						timestampforalpha.append(float(j.split(' ')[4]))
					if int(j.split()[3]) >20:
						if sam == 'T':						
							new_gap += 1
						sam = 'F'	
					if int(j.split()[3]) <=20:
						sam = 'T'
						small = small + 1
			#calculating T
			self.gapp.append(new_gap)
			self.spc.append(small)
			pos = self.uid.index(i)
			self.T.append(float("{:.2f}".format((self.spc[pos]-new_gap-1)/self.tpc[pos])))

			#avergae packet size
			self.avgsize.append(sum(length)/self.tpc[self.uid.index(i)])
			#avergae of packet intervals
			t=0
			for i5 in range(len(timestamp)-2):
				t+=timestamp[i5+1]-timestamp[i5]
			self.avginterval.append(t/len(timestamp))	

			
			#calculating Alpha
			c = 0
			ct = 0
			for j in range(len(lengthforalpha)-1) :
				if lengthforalpha[j] <=20 and lengthforalpha[j+1]<=20 :
					c = c+1
					if timestampforalpha[j+1]-timestampforalpha[j] > 0.01 and timestampforalpha[j+1]-timestampforalpha[j] < 2.0 :
						ct = ct + 1
						print(timestampforalpha[j])
			print(c,ct,len(lengthforalpha))
			if c==0 or c==1:
				self.Alpha.append(0)
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
			plt.clf()
			plt.hist(length,bins=50)
			plt.xlabel('Packet Sizes')
			plt.ylabel('Frequency of packets')
			plt.savefig('Hist/hist{}_{}.png'.format(self.uid.index(i),self.pcap))

		#interactiveness graph
		temp=[*range(1,len(self.uid)+1,1)]
		for i in range(len(self.uid)):
			self.Metrics.append((self.Alpha[i]+self.T[i])/2) 
		fig=plt.figure(figsize=(19.20,10.80))
		plt.axis([1,len(self.uid),0.2,1])
		plt.plot(temp,self.Metrics,'bo',linestyle='dashed')
		plt.xticks(temp,temp)
		plt.xlabel('Connections')
		plt.ylabel('Avg of Metrics')
		plt.title('Interactiveness of connections')
		plt.savefig('{}.png'.format(self.pcap))

		#avgpacketsize graph
		fig=plt.figure(figsize=(19.20,10.80))
		plt.axis([1,len(self.uid),0,1500])
		plt.bar(temp,self.avgsize,width=0.2)
		plt.xticks(temp,temp)
		plt.xlabel('Connections')
		plt.ylabel('Avg Packet Size(B)')
		plt.title('Connections vs Avg packet size')
		plt.savefig('avgsize_{}.png'.format(self.pcap))

		#avgintervalbetweenpackets
		fig=plt.figure(figsize=(19.20,10.80))
		plt.axis([1,len(self.uid),0,10])
		plt.bar(temp,self.avginterval,width=0.2)
		plt.xticks(temp,temp)
		plt.xlabel('Connections')
		plt.ylabel('Avg Packet Interval(sec)')
		plt.title('Connections vs Avg packet interval')
		plt.savefig('avginterval_{}.png'.format(self.pcap))

		f.close()
	


