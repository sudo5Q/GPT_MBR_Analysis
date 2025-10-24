# Author: Ahmed Alqahtani
# MBR analysis tool


# Usage:
# Switces:
# -t : 
# analysis types:
# mbr
# gpt

#!/usr/bin/env python3
import struct
import hashlib
import json
import sys


# Extracting input 
firstArgVar = sys.argv[1]
secondArgVar = sys.argv[2]
thirdArgVar = sys.argv[3]
fourthArgVar = sys.argv[4]
mbrOrGpt = 0



#--------- {Validating the input} ------------

# -t
if firstArgVar != "-t":
    print("incorrect input -t was not written")
    quit()

# analysis type
if secondArgVar == "mbr":
    mbrOrGpt = 1
elif secondArgVar == "gpt":
    mbrOrGpt = 2
else:
    print("input error (analysis type was not specified correctly)")
    quit()

if thirdArgVar != "-f":
    print("incorrect input -f was not written")
    quit()
    
    


# -------------------------{Checksums}---------------------------------
md5Checksum = "MD5-" + fourthArgVar + ".txt"
sha256Checksum = "SHA-256-" + fourthArgVar + ".txt"
with open(fourthArgVar,"rb") as f:
    bytes = f.read()
    hashOfSHA256 = hashlib.sha256(bytes).hexdigest();
    hashOfMD5 = hashlib.md5(bytes).hexdigest();
    f.close()    

f2 = open(sha256Checksum, "w")
f2.write(hashOfSHA256)
f2.close()

f2 = open(md5Checksum, "w")
f2.write(hashOfMD5)
f2.close()



# -------------------------{MBR analysis}----------------------

if mbrOrGpt == 1:
    
    
    # ----------- { First Partition } ---------------------------
    # some changes here
    
    intLBA = int(bytes[457:458].hex() + bytes[456:457].hex() + bytes[455:456].hex() + bytes[454:455].hex(), base=16)
    
    
    partition1Type = bytes[450:451].hex()
    partition1LBA = intLBA  
    sizeUse = bytes[461:462].hex() + bytes[460:461].hex() + bytes[459:460].hex() + bytes[458:459].hex()  # 
    partition1Size = int(sizeUse, base=16) 
    addUse = partition1LBA + 496
    
    partition116Byte = bytes[addUse:addUse + 1].hex() + " " + bytes[addUse+1:addUse + 2].hex() + " " + bytes[addUse+2:addUse + 3].hex() + " " + bytes[addUse+3:addUse + 4].hex() + " " + bytes[addUse+4:addUse + 5].hex() + " " + bytes[addUse+5:addUse + 6].hex() + " " + bytes[addUse+6:addUse + 7].hex() + " " + bytes[addUse+7:addUse + 8].hex() + " " + bytes[addUse+8:addUse + 9].hex() + " " + bytes[addUse+9:addUse + 10].hex() + " " + bytes[addUse+10:addUse + 11].hex() + " " + bytes[addUse+11:addUse + 12].hex() + " " + bytes[addUse+12:addUse + 13].hex() + " " + bytes[addUse+13:addUse + 14].hex() + " " + bytes[addUse+14:addUse + 15].hex() + " " + bytes[addUse+15:addUse + 16].hex() 
    
    thejFile = open('PartitionTypes.json', 'r')
    jsondata = thejFile.read()
    jData = json.loads(jsondata)
    print()
    for i in range(len(jData)):
        if partition1Type == jData[i].get("hex"):
            part1Type = jData[i].get("desc")
    
    print('('+ partition1Type+')',part1Type+', %d, %d' %(intLBA, partition1Size*512))
    
    
    #----------------{ Second partition } ----------------------------------
    
    intLBA2 = int(bytes[473:474].hex() + bytes[472:473].hex() + bytes[471:472].hex()+ bytes[470:471].hex(), base=16)


    partition2Type = bytes[466:467].hex()
    partition2LBA = intLBA2 
    sizeUse2 = bytes[477:478].hex() + bytes[476:477].hex() + bytes[475:476].hex() + bytes[474:475].hex()  # 
    partition2Size = int(sizeUse2, base=16)  # Size in decimal
    addUse2 = partition2LBA + 496


    partition216Byte = bytes[addUse2:addUse2 + 1].hex() + " " + bytes[addUse2+1:addUse2 + 2].hex() + " " + bytes[addUse2+2:addUse2 + 3].hex() + " " + bytes[addUse2+3:addUse2 + 4].hex() + " " + bytes[addUse2+4:addUse2 + 5].hex() + " " + bytes[addUse2+5:addUse2 + 6].hex() + " " + bytes[addUse2+6:addUse2 + 7].hex() + " " + bytes[addUse2+7:addUse2 + 8].hex() + " " + bytes[addUse2+8:addUse2 + 9].hex() + " " + bytes[addUse2+9:addUse2 + 10].hex() + " " + bytes[addUse2+10:addUse2 + 11].hex() + " " + bytes[addUse2+11:addUse2 + 12].hex() + " " + bytes[addUse2+12:addUse2 + 13].hex() + " " + bytes[addUse2+13:addUse2 + 14].hex() + " " + bytes[addUse2+14:addUse2 + 15].hex() + " " + bytes[addUse2+15:addUse2 + 16].hex() 

    
    for i in range(len(jData)):
        if partition2Type == jData[i].get("hex"):
            part2Type = jData[i].get("desc")
        

    print('('+ partition2Type+')',part2Type+', %d, %d' %(intLBA2, partition2Size*512))
    
    
    
    #----------------{ Third partition } ----------------------------------
    
    intLBA3 = int(bytes[489:490].hex() + bytes[488:489].hex() + bytes[487:488].hex()+ bytes[486:487].hex(), base=16)



    partition3Type = bytes[482:483].hex()
    partition3LBA = intLBA3
    sizeUse3 = bytes[493:494].hex() + bytes[492:493].hex() + bytes[491:492].hex() + bytes[490:491].hex()   
    partition3Size = int(sizeUse3, base=16)  # Size in decimal
    addUse3 = partition3LBA + 496


    partition316Byte = bytes[addUse3:addUse3 + 1].hex() + " " + bytes[addUse3+1:addUse3 + 2].hex() + " " + bytes[addUse3+2:addUse3 + 3].hex() + " " + bytes[addUse3+3:addUse3 + 4].hex() + " " + bytes[addUse3+4:addUse3 + 5].hex() + " " + bytes[addUse3+5:addUse3 + 6].hex() + " " + bytes[addUse3+6:addUse3 + 7].hex() + " " + bytes[addUse3+7:addUse3 + 8].hex() + " " + bytes[addUse3+8:addUse3 + 9].hex() + " " + bytes[addUse3+9:addUse3 + 10].hex() + " " + bytes[addUse3+10:addUse3 + 11].hex() + " " + bytes[addUse3+11:addUse3 + 12].hex() + " " + bytes[addUse3+12:addUse3 + 13].hex() + " " + bytes[addUse3+13:addUse3 + 14].hex() + " " + bytes[addUse3+14:addUse3 + 15].hex() + " " + bytes[addUse3+15:addUse3 + 16].hex() 


    for i in range(len(jData)):
        if partition3Type == jData[i].get("hex"):
            part3Type = jData[i].get("desc")
        

    print('('+ partition3Type+')',part3Type+', %d, %d' %(intLBA3, partition3Size*512))
    
    
    #----------------{ fourth partition } ----------------------------------
    intLBA4 = int(bytes[505:506].hex() + bytes[504:505].hex() + bytes[503:504].hex()+ bytes[502:503].hex(), base=16)


    partition4Type = bytes[498:499].hex()
    partition4LBA = intLBA4 
    sizeUse4 = bytes[509:510].hex() + bytes[508:509].hex() + bytes[507:508].hex() + bytes[506:507].hex()   
    partition4Size = int(sizeUse4, base=16)  # Size in decimal
    addUse4 = partition4LBA + 496


    partition416Byte = bytes[addUse4:addUse4 + 1].hex() + " " + bytes[addUse4+1:addUse4 + 2].hex() + " " + bytes[addUse4+2:addUse4 + 3].hex() + " " + bytes[addUse4+3:addUse4 + 4].hex() + " " + bytes[addUse4+4:addUse4 + 5].hex() + " " + bytes[addUse4+5:addUse4 + 6].hex() + " " + bytes[addUse4+6:addUse4 + 7].hex() + " " + bytes[addUse4+7:addUse4 + 8].hex() + " " + bytes[addUse4+8:addUse4 + 9].hex() + " " + bytes[addUse4+9:addUse4 + 10].hex() + " " + bytes[addUse4+10:addUse4 + 11].hex() + " " + bytes[addUse4+11:addUse4 + 12].hex() + " " + bytes[addUse4+12:addUse4 + 13].hex() + " " + bytes[addUse4+13:addUse4 + 14].hex() + " " + bytes[addUse4+14:addUse4 + 15].hex() + " " + bytes[addUse4+15:addUse4 + 16].hex() 


    for i in range(len(jData)):
        if partition4Type == jData[i].get("hex"):
            part4Type = jData[i].get("desc")
        

    print('('+ partition4Type+')',part4Type+', %d, %d' %(intLBA4, partition4Size*512))
    
    
    #----------------{ printing last 16 digits} ----------------------------------
    print("Partition number: 1")
    print("Last 16 bytes of boot record:", partition116Byte)

    print("Partition number: 2")
    print("Last 16 bytes of boot record:", partition216Byte)

    print("Partition number: 3")
    print("Last 16 bytes of boot record:", partition316Byte)

    print("Partition number: 4")
    print("Last 16 bytes of boot record:", partition416Byte)
    
# -------------------------{GPT analysis}----------------------
else:
    
    print()
    #-------------------- { Partition 1 } ------------------------------
    
    #Partition GUID
    
    part1GUID = bytes[1024:1040].hex()
    
    startLbaDec1 = int(bytes[1063:1064].hex() + bytes[1062:1063].hex() + bytes[1061:1062].hex() + bytes[1060:1061].hex() + bytes[1059:1060].hex() + bytes[1058:1059].hex() + bytes[1057:1058].hex() + bytes[1056:1057].hex(), base=16)
    endLbaDec1 = int(bytes[1071:1072].hex() + bytes[1070:1071].hex() + bytes[1069:1070].hex() + bytes[1068:1069].hex() + bytes[1067:1068].hex() + bytes[1066:1067].hex() + bytes[1065:1066].hex() + bytes[1064:1065].hex(), base=16)
    
    
    print("Partition number: 1")
    print("Partition Type GUID :", part1GUID.upper())
    print("Starting LBA address in hex:", hex(startLbaDec1))
    print("ending LBA address in hex:", hex(endLbaDec1))
    print("starting LBA address in Decimal:", startLbaDec1)
    print("ending LBA address in Decimal:", endLbaDec1)
    
    
    
    
    
    print()
    #------------------------------------------------[Partition 2]--------------------------------------------------
    part2GUID = bytes[1152:1168].hex()
    
    startLbaDec2 = int(bytes[1191:1192].hex() + bytes[1190:1191].hex() + bytes[1189:1190].hex() + bytes[1188:1189].hex() + bytes[1187:1188].hex() + bytes[1186:1187].hex() + bytes[1185:1186].hex() + bytes[1184:1185].hex(), base=16)
    endLbaDec2 = int(bytes[1199:1200].hex() + bytes[1198:1199].hex() + bytes[1197:1198].hex() + bytes[1196:1197].hex() + bytes[1195:1196].hex() + bytes[1194:1195].hex() + bytes[1193:1194].hex() + bytes[1192:1193].hex(), base=16)
    
    
    print("Partition number: 2")
    print("Partition Type GUID :", part2GUID.upper())
    print("Starting LBA address in hex:", hex(startLbaDec2))
    print("ending LBA address in hex:", hex(endLbaDec2))
    print("starting LBA address in Decimal:", startLbaDec2)
    print("ending LBA address in Decimal:", endLbaDec2)
    
    
    
    print()
    #------------------------------------------------[Partition 3]--------------------------------------------------
    part3GUID = bytes[1280:1296].hex()
    
    startLbaDec3 = int(bytes[1319:1320].hex() + bytes[1318:1319].hex() + bytes[1317:1318].hex() + bytes[1316:1317].hex() + bytes[1315:1316].hex() + bytes[1314:1315].hex() + bytes[1313:1314].hex() + bytes[1312:1313].hex(), base=16)
    endLbaDec3 = int(bytes[1327:1328].hex() + bytes[1326:1327].hex() + bytes[1325:1326].hex() + bytes[1324:1325].hex() + bytes[1323:1324].hex() + bytes[1322:1323].hex() + bytes[1321:1322].hex() + bytes[1320:1321].hex(), base=16)
    
    
    print("Partition number: 3")
    print("Partition Type GUID :", part3GUID.upper())
    print("Starting LBA address in hex:", hex(startLbaDec3))
    print("ending LBA address in hex:", hex(endLbaDec3))
    print("starting LBA address in Decimal:", startLbaDec3)
    print("ending LBA address in Decimal:", endLbaDec3)
    
    
    
    
    print()
    #------------------------------------------------[Partition 4]--------------------------------------------------
    part4GUID = bytes[1408:1424].hex()
    
    
    startLbaDec4 = int(bytes[1447:1448].hex() + bytes[1446:1447].hex() + bytes[1445:1446].hex() + bytes[1444:1445].hex() + bytes[1443:1444].hex() + bytes[1442:1443].hex() + bytes[1441:1442].hex() + bytes[1440:1441].hex(), base=16)
    endLbaDec4 = int(bytes[1455:1456].hex() + bytes[1454:1455].hex() + bytes[1453:1454].hex() + bytes[1452:1453].hex() + bytes[1451:1452].hex() + bytes[1450:1451].hex() + bytes[1449:1450].hex() + bytes[1448:1449].hex(), base=16)
    
    
    print("Partition number: 4")
    print("Partition Type GUID :", part4GUID.upper())
    print("Starting LBA address in hex:", hex(startLbaDec4))
    print("ending LBA address in hex:", hex(endLbaDec4))
    print("starting LBA address in Decimal:", startLbaDec4)
    print("ending LBA address in Decimal:", endLbaDec4)
    
