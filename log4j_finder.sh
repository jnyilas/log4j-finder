#!/bin/bash

## Joe Nyilas
## 16-DEC-2021
## Oracle ACS
## This is an unpublished work.

# A quick attempt to locate and identify vulnerable log4j installations.

## Usage:
#  ./log4j_finder.sh DIR DIR ...

# e.g.
# > bash log4j_finder.sh /tmp /usr
# 
# /tmp/apache-log4j-2.16.0-bin/log4j-core-2.16.0-tests.jar is not vulnerable
# /tmp/apache-log4j-2.16.0-bin/log4j-core-2.16.0-javadoc.jar is not vulnerable
# /tmp/apache-log4j-2.16.0-bin/log4j-core-2.16.0-sources.jar is not vulnerable
#      Found suspect JndiManager.class in /tmp/apache-log4j-2.16.0-bin/log4j-core-2.16.0.jar
#      Owner is: spongebob
#      ba1cf8f81e7b31c709768561ba8ab558: Good! log4j 2.16.0
##

# JndiManager.class (source: https://github.com/nccgroup/Cyber-Defence/blob/master/Intelligence/CVE-2021-44228/modified-classes/md5sum.txt)
log4j_bad_hashes="
    04fdd701809d17465c17c7e603b1b202: log4j 2.9.0 - 2.11.2
    21f055b62c15453f0d7970a9d994cab7: log4j 2.13.0 - 2.13.3
    3bd9f41b89ce4fe8ccbf73e43195a5ce: log4j 2.6 - 2.6.2
    415c13e7c8505fb056d540eac29b72fa: log4j 2.7 - 2.8.1
    5824711d6c68162eb535cc4dbf7485d3: log4j 2.12.0 - 2.12.1
    6b15f42c333ac39abacfeeeb18852a44: log4j 2.1 - 2.3
    8b2260b1cce64144f6310876f94b1638: log4j 2.4 - 2.5
    a193703904a3f18fb3c90a877eb5c8a7: log4j 2.8.2
    f1d630c48928096a484e4b95ccb162a0: log4j 2.14.0 - 2.14.1
    5d253e53fa993e122ff012221aa49ec3: log4j 2.15.0
    ba1cf8f81e7b31c709768561ba8ab558: Good! log4j 2.16.0"

# JndiManager.class (source: https://repo.maven.apache.org/maven2/org/apache/logging/log4j/log4j-core/2.16.0/log4j-core-2.16.0.jar)
#log4j_good_hashs="
#ba1cf8f81e7b31c709768561ba8ab558: log4j 2.16.0"

for i in "$@"; do
	# create array of files in a special way to handle
        # localization encoding and special characters (esp. 
        # whitespace) using a null byte (\0) array
        flist=()
	while read -r -d ''; do
		flist+=("$REPLY")
	done < <(find "$i" -name log4j-core\*.jar -print0)

done
for f in "${flist[@]}"; do
	chk=$(zipinfo "$f" | grep JndiManager.class)
		if [[ -z "${chk}" ]]; then
			echo "$f is not vulnerable"
		else
			owner=$(stat -c %U "$f")
			chk=$(unzip -p  "$f" *JndiManager.class | md5sum | cut -d ' ' -f1)
			echo "    Found suspect JndiManager.class in $f"
			echo "    Owner is: $owner"
			echo "${log4j_bad_hashes}" | grep "$chk"
		fi
done
