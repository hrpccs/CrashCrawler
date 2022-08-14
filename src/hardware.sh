#! /bin/bash

echo "=====================Basic System Information==========================="
echo "---------------------------OS Information-------------------------------"
#操作系统名称
system_name=`head -n 1 /etc/issue | awk '{print $1,$2}'`
echo "System Name: 		$system_name"

#操作系统位数
systembit=`getconf LONG_BIT`
echo "System Bits: 		$systembit"

#操作系统内核版本
system_kernel=`uname -r`
echo "Kernel Version: 	$system_kernel"
echo "---------------------------CPU Information-------------------------------"
#CPU型号
cpu_model=`cat /proc/cpuinfo | grep "model name" | awk -F ':' '{print $2}' | sort | uniq`
echo "Basic CPU Informaton:  $cpu_model"
#CPU架构
cpu_architecture=`uname -m`
echo "CPU_Architecture:	$cpu_architecture"

#物理CPU个数
cpu_phy_num=`cat /proc/cpuinfo | grep "physical id" | sort | uniq | wc -l`
#CPU核数
cpu_core_num=`cat /proc/cpuinfo | grep "cpu cores" | uniq | awk -F ': ' '{print $2}'`
#逻辑CPU个数
cpu_proc_num=`cat /proc/cpuinfo | grep "processor" | uniq | wc -l`
echo "Physical CPUs Number: 	$cpu_phy_num"
echo "Cores Per CPU:		$cpu_core_num"
echo "Logical CPUs Number:	$cpu_proc_num"

##L1d缓存
cpu_l1d_cache=`lscpu | grep -i 'L1d 缓存\|L1d cache'`
echo "$cpu_l1d_cache"

##L1i缓存
cpu_l1i_cache=`lscpu | grep -i 'L1i 缓存\|L1i cache'`
echo "$cpu_l1i_cache"

##L2缓存
cpu_l2_cache=`lscpu | grep -i 'L2 缓存\|L2 cache'`
echo "$cpu_l2_cache"

##L3缓存
cpu_l3_cache=`lscpu | grep -i 'L3 缓存\|L3 cache'`
echo "$cpu_l3_cache"

echo "---------------------------Memory Information----------------------------"
#单位转换函数
function convert_unit()
{
	result=$1
	if [ $result -ge  1048576 ]
	then
		value=1048576 #1024*1024	
		result_gb=$(awk 'BEGIN{printf"%.2f\n",'$result' / '$value'}') #将KB转换成GB，并保留2位小数
		echo $result_gb"GB"
	elif [ $result -ge  1024 ]
	then
		value=1024 	
		result_mb=$(awk 'BEGIN{printf"%.2f\n",'$result' / '$value'}') #将KB转换成MB，并保留2位小数
		echo $result_mb"MB"
	else
		echo $result"KB"
	fi
}
#单位:KB
MemTotal=$(cat /proc/meminfo | awk '/^MemTotal/{print $2}') #内存总量
MemFree=$(cat /proc/meminfo | awk '/^MemFree/{print $2}')   #空闲内存
MemUsed=$(expr $MemTotal - $MemFree)  #已用内存

##计算内存占用率
Mem_Rate=$(awk 'BEGIN{printf"%.2f\n",'$MemUsed' / '$MemTotal' *100}') #保留小数点后2位

MemShared=$(cat /proc/meminfo | awk '/^Shmem/{print $2}') #共享内存
Buffers=$(cat /proc/meminfo | awk '/^Buffers/{print $2}') #文件缓冲区
Cached=$(cat /proc/meminfo | awk '/^Cached/{print $2}') #用于高速缓冲存储器

SwapTotal=$(cat /proc/meminfo | awk '/^SwapTotal/{print $2}') #交换区总量
SwapFree=$(cat /proc/meminfo | awk '/^SwapFree/{print $2}') #空闲交换区
Mapped=$(cat /proc/meminfo | awk '/^Mapped/{print $2}') #已映射

##虚拟内存
VmallocUsed=$(cat /proc/meminfo | awk '/^VmallocUsed/{print $2}') #已使用的虚拟内存


#物理内存容量
meminfo=`sudo dmidecode | grep "^[[:space:]]*Size.*MB$" | uniq -c | sed 's/ \t*Size: /\*/g' | sed 's/^ *//g'`
echo "Memory Information:	$meminfo"
echo "Total Memory:		$(convert_unit $MemTotal)"
echo "Memory Balance:		$(convert_unit $MemFree)"
echo "Memory Usage(%):	$Mem_Rate%"
echo "Virtual Memory Usage:	$(convert_unit $VmallocUsed)"

echo "---------------------------Disk Information------------------------------"
#磁盘型号
disk_model=`fdisk -l | grep "Disk model" | awk -F : '{print $2}' | sed 's/^ //'`
echo "Disk Model:		$disk_model"

usesum=0
totalsum=0
disknum=`df -hlT |wc -l `
for((n=2;n<=$disknum;n++))
do
	use=$(df -k |awk NR==$n'{print int($3)}')
	pertotal=$(df -k |awk NR==$n'{print int($2)}')
	usesum=$[$usesum+$use]		#计算已使用的总量
	totalsum=$[$totalsum+$pertotal]	#计算总量
done
freesum=$[$totalsum-$usesum]
diskutil=$(awk 'BEGIN{printf"%.2f\n",'$usesum' / '$totalsum'*100}')
freeutil=$(awk 'BEGIN{printf"%.2f\n",100 - '$diskutil'}')

#磁盘总量
if [ $totalsum -ge 0 -a $totalsum -lt 1024 ];then
echo "Totol Disk:		$totalsum K"

elif [ $totalsum -gt 1024 -a  $totalsum -lt 1048576 ];then
	totalsum=$(awk 'BEGIN{printf"%.2f\n",'$totalsum' / 1024}')
echo "Totol Disk:		$totalsum M"

elif [ $totalsum -gt 1048576 ];then
	totalsum=$(awk 'BEGIN{printf"%.2f\n",'$totalsum' / 1048576}')
echo "Totol Disk:		$totalsum G"

fi

# #磁盘已使用总量
# if [ $usesum -ge 0 -a $usesum -lt 1024 ];then
# echo "$usesum K"

# elif [ $usesum -gt 1024 -a  $usesum -lt 1048576 ];then
# 	usesum=$(awk 'BEGIN{printf"%.2f\n",'$usesum' / 1024}')
# echo "$usesum M"

# elif [ $usesum -gt 1048576 ];then
# 	usesum=$(awk 'BEGIN{printf"%.2f\n",'$usesum' / 1048576}')
# echo "$usesum G"

# fi

#磁盘未使用总量
if [ $freesum -ge 0 -a $freesum -lt 1024 ];then
echo "Disk Balance:		$freesum K"

elif [ $freesum -gt 1024 -a  $freesum -lt 1048576 ];then
	freesum=$(awk 'BEGIN{printf"%.2f\n",'$freesum' / 1024}')
echo "Disk Balance:		$freesum M"

elif [ $freesum -gt 1048576 ];then
	freesum=$(awk 'BEGIN{printf"%.2f\n",'$freesum' / 1048576}')
echo "Disk Balance:		$freesum G"
fi
#磁盘空闲率
echo "Disk Usage(%):		$freeutil%"

echo "--------------------------Other Information------------------------------"

#显卡型号
graphicscardmodel=`lspci | grep -i 'VGA' | sed '2d' | cut -f3 -d ":" | sed 's/([^>]*)//g'`
echo "Graphics Card Model:   $graphicscardmodel"

#显卡生产商
graphicscardmanufacturer=`lspci | grep -i 'VGA'| sed '2d'| awk '{ print $5,$6 }'`

#主板厂商
boardmanufacturer=`sudo dmidecode | grep -A 10 "Base Board Information" |grep "Manufacturer" | awk -F ':' '{print $2}'`
echo "Mainboard Manufacturer:$boardmanufacturer"

#主板名称
boardname=`sudo dmidecode | grep -A 10 "Base Board Information" |grep "Product Name" | awk -F ':' '{print $2}'`
echo "Mainboard Model:       $boardname"

#BIOS厂商
biosvendor=`sudo dmidecode | grep -A 28 "BIOS Information" | grep 'Vendor' | awk -F ':' '{print $2}'`
echo "BIOS Vendor:	       $biosvendor"

#BIOS版本
biosversion=`sudo dmidecode | grep -A 28 "BIOS Information" | grep 'Version' | awk -F ':' '{print $2}'`
echo "BIOS Version:	       $biosversion"

#BIOS发行日期
biosrelease=`sudo dmidecode | grep -A 28 "BIOS Information" | grep 'Release' | awk -F ':' '{print $2}'`
echo "BIOS Release Time:     $biosrelease"

#网卡信息
netcardinfo=`lspci | grep -i eth | head -n +1 | awk -F : '{print $3}' | sed 's/^ //'`
echo "Netcard Info:		$netcardinfo"
