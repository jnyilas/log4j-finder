# log4j-finder
Find vulnerable Log4j installations

A Python3 script to scan the filesystem to find Log4j2 that is vulnerable to Log4Shell (CVE-2021-44228 & CVE-2021-45046). It scans recursively to locate suspect jar files on disk and compares them to published checksum of vulnerable log4j versions.


## Usage
    % ./log4j_finder.sh DIR DIR ...
   
### E.G.
    > bash log4j_finder.sh /tmp /usr

 /tmp/apache-log4j-2.16.0-bin/log4j-core-2.16.0-tests.jar is not vulnerable
 /tmp/apache-log4j-2.16.0-bin/log4j-core-2.16.0-javadoc.jar is not vulnerable
 /tmp/apache-log4j-2.16.0-bin/log4j-core-2.16.0-sources.jar is not vulnerable
      Found suspect JndiManager.class in /tmp/apache-log4j-2.16.0-bin/log4j-core-2.16.0.jar
      Owner is: spongebob
      ba1cf8f81e7b31c709768561ba8ab558: Good! log4j 2.16.0
