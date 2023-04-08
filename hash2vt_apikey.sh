#!/bin/bash
#--------------------------------------------------------------------------------
#	hashs2vt_apikey.sh (For Linux)
#	Creator: Zi_WaF
#	Group: Centre for Cybersecurity
#	whatis: 	hashs2vt_apikey.sh	To scan multiple hashes to identify its malicious level via virustotal.com
#				<api key file>	file that contains api key (Private) when signed up with VirusTotal Community. (see https://support.virustotal.com/hc/en-us/articles/115002100149-API)
#				<hash list>	 file that contains list of hashes for scanning.
#
#	To run: bash hash2vt_apikey.sh <api key file> <hash list>
#--------------------------------------------------------------------------------
rm -r /tmp/templist.txt /tmp/templist2.txt /tmp/templist3.txt 2>/dev/null
function trap_all(){  	# set up for any interruptions and exit program cleanly
		rm -r /tmp/templist.txt /tmp/templist2.txt /tmp/templist3.txt 2>/dev/null
		echo -e "\nProgram interrupted."
		exit
}
function check_hash(){	# check all hashes if it is malicious
	if [ -z "$1" ] || [ -z "$2" ]
	then
		echo -e "Incomplete input.\nExample: \033[0;36mbash hash2vt_apikey.sh <api key file> <hash list>\033[0m"	 # if no arguments was passed
		exit
	else
		# checkhing hash type
		c=1
		while read line
		do
			hsh_len=$(echo -n $line | wc -c)
			htype=$(case $hsh_len in
						32)	echo -n "(MD5)     " ;;
						40) echo -n "(SHA1)    " ;;
						64) echo -n "(SHA256)  " ;;
						128) echo -n "(SHA512) " ;;
						*) echo -e "(\033[0;33mUnknown hash type. Not Supported.\033[0m)"; continue ;;
					esac)
			if [ $c -le 3 ]
			then
				# scan hash via virustotal.com, only limited to 4 scans per minute due to Virus Total Policy
				# api key from virustotal.com is required
				
				#echo "$(curl -s -X POST "https://www.virustotal.com/vtapi/v2/file/report?apikey=$(cat $1)&resource=$line" | awk -F 'total\":' '{print$2}' | awk '{printf "Malicious: \033[1m" $3"\033[0m positives out of total "$1 " Scans. Percentage: \033[1m%.2f%\033[0m\n",100*($3/$1)}' |  tr -d "," )  ($line) $htype" | tee -a /tmp/templist.txt # https://stackoverflow.com/questions/64886429/awk-if-0-divided-by-x-output-0
				echo "$(curl -s -X POST "https://www.virustotal.com/vtapi/v2/file/report?apikey=$(cat $1)&resource=$line")" > /tmp/templist.txt
				if [ -z "$(cat /tmp/templist.txt | grep "\"response_code\": 0")" ]
				then
					echo -e "$(cat /tmp/templist.txt | awk -F 'total\":' '{print$2}' | awk '{printf "Malicious: \033[1m" $3"\033[0m positives out of total "$1 " Scans. Percentage: \033[1m%.2f%\033[0m\n",100*($3/$1)}' |  tr -d "," ) $line $htype" | tee -a /tmp/templist2.txt
				else
					echo -e "Response Code: \"0\". Not present in VirusTotal's dataset. $line $htype" | tee -a /tmp/templist2.txt
				fi
				c=$((c+1))
			else
				secs=60
				#echo "$(curl -s -X POST "https://www.virustotal.com/vtapi/v2/file/report?apikey=$(cat $1)&resource=$line" | awk -F 'total\":' '{print$2}' | awk '{printf "Malicious: \033[1m" $3"\033[0m positives out of total "$1 " Scans. Percentage: \033[1m%.2f%\033[0m\n",100*($3/$1)}' |  tr -d "," )  ($line) $htype" | tee -a /tmp/templist.txt 
				if [ -z "$(cat /tmp/templist.txt | grep "\"response_code\": 0")" ]
				then
					echo -e "$(cat /tmp/templist.txt | awk -F 'total\":' '{print$2}' | awk '{printf "Malicious: \033[1m" $3"\033[0m positives out of total "$1 " Scans. Percentage: \033[1m%.2f%\033[0m\n",100*($3/$1)}' |  tr -d "," ) $line $htype" | tee -a /tmp/templist2.txt
				else
					echo -e "Response Code: \"0\". Not present in VirusTotal's dataset. $line $htype" | tee -a /tmp/templist2.txt
				fi
				echo -e "\033[1;33m\e[1mPlease wait... Limitation due to Virus Total Policy. (only 4 scans per minute)\e[0m\033[0m"
				sleep 3	
				while [ $secs -gt 0 ]; do echo -ne "\033[1;33m\e[1m $secs seconds remaining...\033[0m\r"; sleep 1;: $((secs--));done
				sleep 1
				c=1
			fi
						
		done < $2
		echo -e "\033[0;32m\e[1m       <<< Complete >>>                                    \e[0m\033[0m"
		echo "If you like to scan another file, please wait for 1 minute before running the script again."
		
		
		total=$(cat /tmp/templist2.txt | wc -l)
		mal=$(cat /tmp/templist2.txt | grep ^Malicious | sort -k 9 -Vr | wc -l)
		unknown=$(cat /tmp/templist2.txt | grep -v Malicious | wc -l)
		echo -e "\033[0;32m\e[1m\n--- Summary ---\nTotal Scan (virustotal.com): $total Hash\e[0m\033[0m" >> /tmp/templist3.txt
		echo -e "\033[1m\e[4mMalicious Level Scan: $mal Hash (High to Low %)\e[0m\033[0m" >> /tmp/templist3.txt
		cat /tmp/templist2.txt | grep ^Malicious | sort -k 9 -Vr >> /tmp/templist3.txt
		
		echo -e "\033[1m\e[4m\nUnknown Hash | Scan Error | Input Error ($unknown Hash)\e[0m\033[0m" >> /tmp/templist3.txt
		cat /tmp/templist2.txt | grep -v Malicious >> /tmp/templist3.txt
				
		cat /tmp/templist3.txt | tee saved_result.txt
		echo -e "\nResult saved in current folder as \033[1m'saved_result.txt'\033[0m."
		rm -r /tmp/templist.txt /tmp/templist2.txt /tmp/templist3.txt 2>/dev/null
	fi
}
trap "trap_all" 2
check_hash $1 $2
