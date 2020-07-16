import os
import sys
import webbrowser
import matplotlib.pyplot as plt
import numpy as np
#provide zeek root folder
zeek_path = '/home/ubuntu/zeek-3.1.3/'
zeek_script1 = '/home/ubuntu/zeek-3.1.3/scripts/policy/frameworks/files/extract-all-files.zeek'
zeek_script2 = '/home/ubuntu/zeek-3.1.3/scripts/policy/frameworks/files/detect-MHR.zeek'
zeek_script3 = '/home/ubuntu/zeek-3.1.3/scripts/policy/protocols/ssh/detect-bruteforcing.zeek'
zeek_script4 = '/home/ubuntu/zeek-3.1.3/learn/num.zeek '

#check if the pcap is already executed
pcap_name = input('enter pcap name')
try:
 if not os.path.isdir(pcap_name):
  os.mkdir('dir_%s'%(pcap_name))
  os.system('cp %s dir_%s'%(pcap_name,pcap_name))
  os.system('cp desc.html dir_%s'%(pcap_name))
  os.chdir('dir_%s'%(pcap_name))
except OSError:
 print('Already executed this pcap')
 option = input('enter \'R\' to re analysis the file')
 if option == 'R' or option =='r':
  os.system('rm -r dir_%s'%(pcap_name))
  os.mkdir('dir_%s'%(pcap_name))
  os.system('cp %s dir_%s'%(pcap_name,pcap_name))
  os.system('cp desc.html dir_%s'%(pcap_name))
  os.chdir('dir_%s'%(pcap_name))
 else:
  sys.exit(0)

os.system('zeek -r %s %s %s %s %s> num.txt'%(pcap_name,zeek_script4,zeek_script1,zeek_script2,zeek_script3))
os.system('cat conn.log|zeek-cut uid id.orig_h id.orig_p id.resp_h id.resp_p proto duration orig_ip_bytes resp_ip_bytes orig_pkts resp_pkts service|grep tcp >connections.txt')
os.system("cat connections.txt | awk \'{ print $2\":\"$3}\' > ipsrc.txt")
os.system("cat connections.txt | awk \'{ print $4\":\"$5}\' > ipdst.txt")
os.system("cat connections.txt | awk \'{ print $7}\' > time.txt")

uid=list()
list1=list()
gapp=list()
tpc=list()
bytesexchanged=list()
serversent=list()
clientsent=list()
ratio=list()
time=list()
spc=list()
T=list()
Alpha=list()
protocols=list()
ipaddr=list()
seripaddr=list()
cliipaddr=list()
services=list()
Metrics=list()

with open('num.txt','r') as f:
 data = f.read()
 data = data.split('\n')
 
 for i in data:
  l = i.split(' ')
  if l[0] == '':
   break
  if l[0] not in uid:
   uid.append(l[0])
 print("UID for connections\n",uid)
 for i in uid:
  if i == '':
   break
  for j in data:
   if j.split(' ')[0] == i:
    list1.append(j) 
 #print(len(list1))
 
with open('connections.txt','r') as f:
 data = f.readlines()
 for i in uid:
  for l in data:
   j = l.split('\t')
   if i == j[0]:
    ipaddr.append(j[1]+':'+j[2]+'<->'+j[3]+':'+j[4])
    seripaddr.append(j[1]+':'+j[2])
    cliipaddr.append(j[3]+':'+j[4])
    tpc.append(int(j[9])+int(j[10]))
    bytesexchanged.append(int(j[7])+int(j[8]))
    serversent.append(int(j[8]))
    clientsent.append(int(j[7]))
    if int(j[7]) == 0 or j[7] == '-':
     ratio.append("nodata")
    else:
     ratio.append(int(int(j[8])/int(j[7])))
    time.append(j[6])
    protocols.append(j[5])
    services.append(j[11].strip())
#print(time)
#print(bytesexchanged)
#print(ratio)
#print(tpc)
print('\nIP Addresses for UID\n',ipaddr)
#print(ipaddr)
os.system('mkdir -p Images')

for i in uid:
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
 for j in list1:
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
 spc.append(small)
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
 gapp.append(gap) 
 pos = uid.index(i)
 T.append(float("{:.2f}".format((spc[pos]-gap-1)/tpc[pos])))
 #calculating Alpha
 c = 0
 ct = 0
 for j in range(len(length)-1) :
   if length[j] <=20 & length[j+1]<=20 :
    c = c+1
    if timestamp[j+1]-timestamp[j] < 2.0 :
      ct = ct + 1
 if c==0:
  Alpha.append(1)
 else:
  Alpha.append(float("{:.2f}".format(ct/c)))

 #visualsing data transferred
 try:
  maxtime = int(max(ortime)) if max(ortime)>max(restime) else int(max(restime))
 except(ValueError):
  print('\n\nNo payload data detected for this connection \n',ipaddr[uid.index(i)])
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
 

os.system('touch images.html')
inp = open('images.html','w')
if 'Images' in os.listdir():
 newhtml="<html>\n"
 for item in os.listdir(os.path.join(os.getcwd(),'Images')):
  for i in uid:
   if i in item:
    ind = uid.index(i)
  newhtml += "<h2>"+ipaddr[ind]+"</h2>\n"
  newhtml += "<img src=Images/"+item+">\n"
 newhtml+= "</html>"
inp.writelines(newhtml)
inp.close()


for i in range(len(uid)):
 Metrics.append((Alpha[i]+T[i])/2) 
fig=plt.figure()
plt.axis([0,len(uid)-1,0.2,1])
plt.plot(Metrics)
plt.savefig('{}.png'.format(pcap_name))



if 'extract_files' in os.listdir():
 os.system('cp -r extract_files files_%s'%(pcap_name))
 os.system('rm -r extract_files')
 ###if you want to know from which uri files are being requested 
 #os.system('cat http.log| zeek-cut uid uri>filenames.txt')
 ### un hash this if you want to show the file types being transferred
 os.system('cat files.log| zeek-cut conn_uids mime_type>filenames.txt')
 print('\nFiles have been extracted\n')
else:
 print("\nFiles transfer not found\n")
if 'http' in services:
 print("no of GET's in connection")
 os.system('cat http.log|grep GET|wc -l')
 print("no of POST's in connection")
 os.system('cat http.log|grep POST|wc -l')
if 'ssh.log' in os.listdir():
 print('ssh connections found, please check ssh.log for more information')
 os.system('cat ssh.log | zeek-cut uid auth_success')
if 'telnet.log' in os.listdir():
 print('telnet connections found, please check log for more information')
 os.system('cat telnet.log')
print('success')
 






###HTML######


os.system("touch results")
r=open("results","w")
str1="Server Client Protocol Service Totalpackets Smallpackets(<20B) Gaps T Received(B) Sent(B) Received/sent Time(Sec) Alpha\n"
r.write(str1)
for i in range(len(uid)-1):
  str1 = str(seripaddr[i])+" "+(cliipaddr[i])+" "+str(protocols[i])+" "+str(services[i].strip())+" "+str(tpc[i])+" "+str(spc[i])+" "+str(gapp[i])+" "+str(T[i])+" "+str(serversent[i])+" "+str(clientsent[i])+" "+str(ratio[i])+" "+str(time[i]+" "+str(Alpha[i])+"\n")
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

table += "</table>\n"+"</html>\n"

table = table + "<html>\n"+"<style>\n"+"table,th,td{\n"+"border:1px solid black;\n"+"border-collapse:collapse;\n"+"}\n"
table = table + "th,td{\n"+"padding:10px;\n"+"text-align:center;\n"+"font-size:20;\n"+"}\n"+"</style>\n"
table = table + "<table>\n"


#table for file names
if 'filenames.txt' in os.listdir():
 filein1 = open('filenames.txt','r')
 table = table + "<tr>\n"+"<caption><h2>Files Extracted</h2></caption>\n"+"</tr>\n"
 data = filein1.read()
 data = data.split('\n')
 header = list()
 header.append('Addresses')
 header.append('Filenames')
 for column in header:
    if column == '':
     break
    table += "    <th>{0}</th>\n".format(column.strip())
 table += "  </tr>\n"



# Create the table's row data
 for line in data[0:len(data)-1]:
    row = line.split("\t")
    for i in uid:
     if i == row[0]:
      pos = uid.index(i)
      row[0] = ipaddr[pos]
    table += "  <tr>\n"
    for column in row:
        table += "    <td >{0}</td>\n".format(column.strip())
    table += "  </tr>\n"

 table += "</table>\n"


for i in os.listdir():
 if 'png' in i:
  if pcap_name in i:
   table += "\n<h2>Interactiveness of connection</h2>\n"
   image = i
   table += "<img src=" + image +">\n"

table += "<h2><a href="+"images.html"+" target ="+"_blank"+">VISUALIZE DATA TRANSFER</a></h2>\n"
table += "<footer>\n<p><a href="+"desc.html"+" target ="+"_blank"+">CLICK HERE TO KNOW ABOUT TERMINOLOGY USED</a></p>\n</footer>\n"+"</html>\n"

fileout.writelines(table)
fileout.close()
filein.close()
os.system("rm results")
webbrowser.open("result.html")
