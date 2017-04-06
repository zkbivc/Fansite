import sys
import re
import os
from datetime import datetime
from datetime import timedelta
import operator
import shlex

HostActive = dict()
ResBandWidth = dict()
BusyPeriod = dict()
TimeQ = []
DTprepop = datetime.now()
Visit_min = 0
BlockDict = dict()


def parse_line(strline):
    try:
        strp = shlex.split(strline)
    except:
        ID_quote1 = [i for i, ch in enumerate(strline) if ch == '\'']
        ID_quote2 = [i for i, ch in enumerate(strline) if ch == '\"']

        ## substitute quotes with 'a'
        all_ID = ID_quote1 + ID_quote2[1:-1]
        strlist = list(strline)
        for i in all_ID:
            strlist[i] = 'a'
        strline1 = ''.join(strlist)

        ## split
        strp = shlex.split(strline1)
                    
        ## substitute 'a' with quote
        if len(ID_quote1):
            strlist = list(strp[0])
            for i in ID_quote1:
                strlist[i] = '\''
            strp[0] = ''.join(strlist)

        if len(ID_quote2):
            if len(ID_quote2) > 2:
                ID_quote2 = [i-ID_quote2[0] for i in ID_quote2]
            ID_quote2.pop(0)
            ID_quote2.pop()
            strlist = list(strp[5])
            for i in ID_quote2:
                strlist[i-1] = '\"'
            strp[5] = ''.join(strlist)
    
    finally:
        strp.pop(1)                 ## remove '-'
        strp.pop(1)                 ## remove '-'
        strp[1] = strp[1][1:]
        strp[2] = strp[2][:-1]
        str3 = strp[3]
        i1 = strp[3].find(' ')
        i2 = strp[3].rfind(' ')
        strp = strp[0:3] + [str3[:i1], str3[i1+1 : i2], str3[i2+1:]] + strp[4:]
        if (not strp[-4]) and (strp[-3][:4]!='HTTP'):
            strp[-4], strp[-3] = strp[-3], strp[-4] 
        if strp[-1] == '-':   strp[-1] = '0'

    return strp

    

def Host_Active(Host):                  ## User activity, Feature-1
    global HostActive
    if Host in HostActive.keys():
        HostActive[Host] += 1
    else:
        HostActive[Host] = 1

def Resource_BandWidth(Res, Bytes):    ## Feature-2
    global ResBandWidth
    if Res in ResBandWidth.keys():
        ResBandWidth[Res] += Bytes
    else:
        ResBandWidth[Res] = Bytes


def Fill_BusyPeriod(VisitNum, TimePoint):
    global BusyPeriod
    global Visit_min

    if not BusyPeriod:
        BusyPeriod[TimePoint] = VisitNum
        Visit_min = VisitNum
    elif len(BusyPeriod) in range(1, 10):
        BusyPeriod[TimePoint] = VisitNum
        if Visit_min > VisitNum:
            Visit_min = VisitNum
    else:
        if Visit_min < VisitNum:
            
            sorted_BusyPeriod = sorted(BusyPeriod.items(), key = operator.itemgetter(1), reverse = True)
            Visit_min = sorted_BusyPeriod[1][1]

            id2del = sorted_BusyPeriod[0][0]
            for i in sorted_BusyPeriod:
                if i[0] > id2del:
                    id2del = i[0]
            del BusyPeriod[id2del]
            
            BusyPeriod[TimePoint] = VisitNum
        else:
            pass
        
 
def Busy_Period(DT, Zone, LastOne):     ## Feature-3
    global TimeQ
    global DTprepop

    if not LastOne:
        DTnew = datetime.strptime(DT+Zone, '%d/%b/%Y:%H:%M:%S%z')
        if not TimeQ:
            TimeQ.append(DTnew)
            DTprepop = DTnew
            
        else:
            if (DTnew - TimeQ[0]).total_seconds() > 3600:
                DTbegin = DTnew - timedelta(seconds=3600)
        
                while TimeQ[0] < DTbegin:
                    VisitNum = len(TimeQ)
                    
                    SecondPass = (TimeQ[0] - DTprepop).total_seconds()
                    if SecondPass > 10:     ## Save computation
                        SecondPass = 10
                    if  SecondPass > 1:
                        for i in range(1,int(SecondPass)):
                            Fill_BusyPeriod(VisitNum, DTprepop+timedelta(seconds=i))

                    Fill_BusyPeriod(VisitNum, TimeQ[0])

                    DTpop = TimeQ.pop(0)
                    while TimeQ and TimeQ[0] == DTpop:
                        TimeQ.pop(0)
                    DTprepop = DTpop

            TimeQ.append(DTnew)
            
                      
    else:
        while TimeQ:
            VisitNum = len(TimeQ)

            SecondPass = (TimeQ[0] - DTprepop).total_seconds()
            if SecondPass > 10:
                SecondPass = 10
            if  SecondPass > 1:
                for i in range(1,int(SecondPass)):
                    Fill_BusyPeriod(VisitNum, DTprepop+timedelta(seconds=i))

            Fill_BusyPeriod(VisitNum, TimeQ[0])

            DTpop = TimeQ.pop(0)
            while TimeQ and TimeQ[0] == DTpop:
                TimeQ.pop(0)
            DTprepop = DTpop

            

def Fill_BlockDict(strp):
    global BlockDict

    if strp[4] == '/login':
        DTnew = datetime.strptime(strp[1], '%d/%b/%Y:%H:%M:%S')
        if strp[-2] == '401':       ## failed login
            if strp[0] not in BlockDict.keys():
                BlockDict[strp[0]] = [DTnew]
            else:
                if (DTnew - BlockDict[strp[0]][0]).total_seconds() > 20.0:
                    BlockDict[strp[0]] = [DTnew]
                else:
                    if len(BlockDict[strp[0]]) == 1:
                        BlockDict[strp[0]].append(DTnew)
                    elif len(BlockDict[strp[0]]) == 2 :       ## begin blocked period
                        BlockDict[strp[0]].append(DTnew)
                    elif len(BlockDict[strp[0]]) == 3:        ## Still in blocked period
                        pass
                    else:
                        pass
        else:                       ## successful login
            if strp[0] in BlockDict.keys():
                del BlockDict[strp[0]]
                
    

def Block_Event(strp, strline, outputfile):          ## Feature-4. 
    global BlockDict
    
    DTnew = datetime.strptime(strp[1], '%d/%b/%Y:%H:%M:%S')
    
    if strp[0] in  BlockDict.keys() and len(BlockDict[strp[0]]) == 3 and (DTnew - BlockDict[strp[0]][1]).total_seconds() <= 300:
        with open(outputfile, 'a+') as f: f.write(strline)

    Fill_BlockDict(strp)
                
        
    

def process_line(FileList):
    iline = 0       ## Count line
    
    with open(FileList[1], 'r', encoding='ISO-8859-1') as f:

        for strline in f:

            iline += 1
            
            strp = parse_line(strline)
            
            if iline % 1E5 == 0:
                DT = datetime.now()
                print('Time:' + datetime.now().strftime('%H:%M:%S') + '  Line #:' + str(iline))

            ### Implement features
            Host_Active(strp[0])
            Resource_BandWidth(strp[4], int(strp[-1]))
            Busy_Period(strp[1], strp[2], False)
            Block_Event(strp, strline, FileList[5])

    Busy_Period(None, None, True)     ## is placed after reading iteration in order to dump
    


######### Main function ############################

if __name__ == "__main__":
	FileList = sys.argv

print('\n' + datetime.now().strftime('%H:%M:%S') + '\n')

process_line(FileList)

print('\n' + datetime.now().strftime('%H:%M:%S') + '\n')

### Feature-1: generate hosts.txt 
sorted_HostActive = sorted(HostActive.items(), key = operator.itemgetter(1), reverse = True)
print(sorted_HostActive[:10])
with open(FileList[2], 'w') as fw:
    for i in sorted_HostActive[:10]:
        fw.write(i[0] + ',' + str(i[1]) + '\n')

print('\n' + datetime.now().strftime('%H:%M:%S') + '\n')


### Feature-2: generate resources.txt
sorted_ResBandWidth = sorted(ResBandWidth.items(), key = operator.itemgetter(1), reverse = True)
print(sorted_ResBandWidth[:10])
with open(FileList[4], 'w') as fw:
    for i in sorted_ResBandWidth[:10]:
        fw.write(str(i[0]) + '\n')

print('\n' + datetime.now().strftime('%H:%M:%S') + '\n')


### Feature-3: generate hours.txt
sorted_BusyPeriod = sorted(BusyPeriod.items(), key = operator.itemgetter(1,0), reverse = True)
##print(sorted_BusyPeriod)
with open(FileList[3], 'w') as fw:
    i1 = 0
    while i1 < 9:
        i2 = i1 + 1
        while sorted_BusyPeriod[i2][1] == sorted_BusyPeriod[i1][1]:
            i2 += 1
        if i2 - i1 > 1:
            for i in sorted_BusyPeriod[i1:i2][::-1]:
                strTime = i[0].strftime('%d/%b/%Y:%H:%M:%S %z')
                fw.write(strTime + ',' + str(i[1]) + '\n')
                print(strTime + ', ' + str(i[1]))
            i1 = i2
        else:
            strTime = sorted_BusyPeriod[i1][0].strftime('%d/%b/%Y:%H:%M:%S %z')
            fw.write(strTime + ',' + str(sorted_BusyPeriod[i1][1]) + '\n')
            print(strTime + ', ' + str(sorted_BusyPeriod[i1][1]))
            i1 += 1
    strTime = sorted_BusyPeriod[-1][0].strftime('%d/%b/%Y:%H:%M:%S %z')
    fw.write(strTime + ',' + str(sorted_BusyPeriod[i1][1]) + '\n')
    print(strTime + ', ' + str(sorted_BusyPeriod[i1][1]))        


print('\n' + datetime.now().strftime('%H:%M:%S') + '\n')
