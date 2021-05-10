#!/bin/bash
# Name - script.sh
# Author - cn-25 under GPL v2.x+
# Usage - Read filenames from a text file and take action on $file 
# ----------------------------------------------------------------
# Note: An easier way is to run: nmap -sV --script ssl-enum-ciphers -p 443 <host>

echo "----------------------------------------------------------------"
echo -e "Starting Script..."
set +e
in="${1:-hostnames.txt}"
 
[ ! -f "$in" ] && { echo "$0 - File $in not found."; exit 1; }
COUNT=1
while IFS= read -r file
do
	ENUM=""
	ENUM_TLS=""
	ENUM_SH=""
	ENUM_SH_Fail=""
	ENUM_WAF=""
	AZURE_SITE=""
	echo "----------------------------------------------------------------"
	echo -e "Host #$COUNT"
	echo "Host Name: $file"

	#Check if requires prefix "https://" in order to redirect
	#Note: The "gtimeout" utility is for macos. If Linux, use "timeout"
	# do /usr/local/bin/gtimeout 10 curl -s -I -L $file >/dev/null
	# if [ $? -eq 0]; then
	# 	echo OK
	# else
	# 	echo FAIL
	# 	file="https://$file"
	# 	echo "Name changed: "$file
	# fi

	# Send data to temp
	curl -s -S -I -L $file > output.txt

	# Initial Checks 1
	if cat output.txt | grep -q "Server:"
		then 
			# echo -e "Enumeration Possible: Server";
			ENUM="${ENUM} HTTP Header includes 'Server', "
			cat output.txt | grep -m 1 "Server"
	fi

	# Initial Checks 2
	if cat output.txt | grep -q "X-Powered-By:"
		then 
			# echo -e "Enumeration Possible: X-Powered-By";
			ENUM="${ENUM} HTTP Header includes 'X-Powered-By'"
			cat output.txt | grep -m 1 "X-Powered-By"
	fi

	# Check if Apache is running
	if cat output.txt | grep -q "Apache" 
		then 
			# echo -e "Enumeration Possible: Apache";
			ENUM="${ENUM} Apache, "
	fi
	# Check if IIS is running
	if cat output.txt | grep -q "IIS"
		then 
			# echo -e "Enumeration Possible: IIS";
			ENUM="${ENUM} IIS, " 
	fi
	# Check if ASP is running
	if cat output.txt | grep -q "ASP"
		then 
			# echo -e "Enumeration Possible: ASP";
			ENUM="${ENUM} ASP, "
	fi

	# Check if Drupal is running
	if cat output.txt | grep -q "Drupal"
		then 
			# echo -e "Enumeration Possible: Drupal";
			ENUM="${ENUM} Drupal, "
	fi

	# Check if PHP is running
	if cat output.txt | grep -q "PHP"
		then 
			# echo -e "Enumeration Possible: PHP";
			ENUM="${ENUM} PHP, "
	fi
	# Check if WordPress is running
	if cat output.txt | grep -q "wp"
		then 
			# echo -e "Enumeration Possible: WordPress";
			ENUM="${ENUM} WordPress, " 
	fi
	
	echo "Possible Enumeration: $ENUM"

	# Check for WAF
	if cat output.txt | grep -q "cf-ray"
		then 
			ENUM_WAF="${ENUM_WAF} CloudFlare"
	fi
	if cat output.txt | grep -q "x-amz-cf"
		then 
			ENUM_WAF="${ENUM_WAF} Amazon CloudFront"
	fi
	echo "The following WAF has been detected: ${ENUM_WAF}"

	# Check Hosting Provider
	if cat output.txt | grep -q "azure-sitename:"
		then
			echo "Azure DCs Detected:"
			cat output.txt | grep -m 1 "azure-sitename:"
	fi
	if cat output.txt | grep -q "amz"
		then
			echo "Site is hosted in AWS"
	fi


	# Check if SSLv2/v3 or TLS < 1.2
	
	wget --secure-protocol=TLSv1 --no-check-certificate $file -o TLS.txt
	if cat TLS.txt | grep -q "connected"
		then 
			ENUM_TLS="${ENUM_TLS} TLSv1.0, "
	fi
	echo "" > TLS.txt

	wget --secure-protocol=TLSv1_1 --no-check-certificate $file -o TLS.txt
	if cat TLS.txt | grep -q "connected"
		then 
			ENUM_TLS="${ENUM_TLS} TLSv1.1, "
	fi
	echo "" > TLS.txt

	# wget --secure-protocol=SSLv2 --no-check-certificate $file -o TLS.txt
	# if cat TLS.txt | grep -q "connected"
	# 	then 
	# 		ENUM_TLS="${ENUM_TLS} SSLv2, "
	# fi
	# echo "" > TLS.txt

	# wget --secure-protocol=SSLv3 --no-check-certificate $file -o TLS.txt
	# if cat TLS.txt | grep -q "connected"
	# 	then 
	# 		ENUM_TLS="${ENUM_TLS} SSLv3, "
	# fi
	echo "Obsolete Connection Protocols: $ENUM_TLS"

	#Check Security Headers
	if cat output.txt | grep -q "content-security-policy:"
		then 
			ENUM_SH="${ENUM_SH} CSP Set, "
	else
		ENUM_SH_Fail="${ENUM_SH_Fail} CSP Not Set, "
	fi

	if cat output.txt | grep -q "referrer-policy:"
		then 
			ENUM_SH="${ENUM_SH} Referrer Policy Set, "
	else
		ENUM_SH_Fail="${ENUM_SH_Fail} Referrer Policy Not Set, "
	fi

	if cat output.txt | grep -q "x-frame-options:"
		then 
			ENUM_SH="${ENUM_SH} X-Frame Options Set, "
	else
		ENUM_SH_Fail="${ENUM_SH_Fail} X Frame Options Not Set, "
	fi

	if cat output.txt | grep -q "x-xss-protection:"
		then 
			ENUM_SH="${ENUM_SH} X-XSS Set, "
	else
		ENUM_SH_Fail="${ENUM_SH_Fail} X-XSS Not Set, "
	fi

	if cat output.txt | grep -q "strict-transport-security:"
		then 
			ENUM_SH="${ENUM_SH} STS Set, "
	else
		ENUM_SH_Fail="${ENUM_SH_Fail} Strict Transport Security Not Set, "
	fi

	if cat output.txt | grep -q "x-content-type-options:"
		then 
			ENUM_SH="${ENUM_SH} X-Content-Type-Options Set, "
	else
		ENUM_SH_Fail="${ENUM_SH_Fail} X-Content-Type-Options Not Set, "
	fi

	echo "Security Headers Set: $ENUM_SH"
	echo "Security Headers Not Set: $ENUM_SH_Fail"
	((COUNT=COUNT + 1))
	echo "" > output.txt
	echo "                                                                "
done < "${in}"
