# Java-Deserialization-Cheat-Sheet
A cheat sheet for pentesters about Java Native Binary Deserialization vulnerabilities

Please, use **#javadeser** hash tag for tweets.

###  Table of content
- [Overview](#overview)
- [Main talks & presentations & docs](#main-talks--presentations--docs)
- [Payload generators](#payload-generators)
- [Exploits](#exploits)
- [Detect](#detect)
- [Vulnerable apps (without public sploits/need more info)](#vulnerable-apps-without-public-sploitsneed-more-info)
- [Protection](#protection)
- [For Android](#for-android)
- [Other serialization types](#other-serialization-types)

### Overview
- [From Foxgloves Security](http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/) 

### Main talks & presentations & docs
##### Marshalling Pickles 
by [@frohoff](https://twitter.com/frohoff) & [@gebl](https://twitter.com/gebl)

- [Video](https://www.youtube.com/watch?v=KSA7vUkXGSg) 
- [Slides](http://www.slideshare.net/frohoff1/appseccali-2015-marshalling-pickles)
- [Other stuff](http://frohoff.github.io/appseccali-marshalling-pickles/ )

##### Exploiting Deserialization Vulnerabilities in Java 
by [@matthias_kaiser](https://twitter.com/matthias_kaiser)

- [Video](https://www.youtube.com/watch?v=VviY3O-euVQ)

##### Serial Killer: Silently Pwning Your Java Endpoints
by [@pwntester](http://twitter.com/pwntester) & [@cschneider4711](http://twitter.com/cschneider4711)

- [Slides](https://www.rsaconference.com/writable/presentations/file_upload/asd-f03-serial-killer-silently-pwning-your-java-endpoints.pdf)
- [White Paper](http://community.hpe.com/hpeb/attachments/hpeb/off-by-on-software-security-blog/722/1/HPE-SR%20whitepaper%20java%20deserialization%20RSA2016.pdf)
- [Bypass Gadget Collection](https://github.com/pwntester/SerialKillerBypassGadgetCollection)

##### Deserialize My Shorts: Or How I Learned To Start Worrying and Hate Java Object Deserialization  
by [@frohoff](https://twitter.com/frohoff) & [@gebl](https://twitter.com/gebl)

- [Slides](http://www.slideshare.net/frohoff1/deserialize-my-shorts-or-how-i-learned-to-start-worrying-and-hate-java-object-deserialization)

##### Deserialization for other languages
by [@pwntester](http://twitter.com/pwntester)

- [PoC for Scala, Grovy](https://github.com/pwntester/JVMDeserialization)

##### Java Deserialization Vulnerabilities - The Forgotten Bug Class 
by [@matthias_kaiser](https://twitter.com/matthias_kaiser)

- [Slides](http://www.slideshare.net/codewhitesec/java-deserialization-vulnerabilities-the-forgotten-bug-class)


### Payload generators 
##### yososerial 
[https://github.com/frohoff/ysoserial](https://github.com/frohoff/ysoserial)

[Lastest release of ysoserial](https://github.com/frohoff/ysoserial/releases/download/v0.0.4/ysoserial-0.0.4-all.jar)

RCE via:

- Apache Commons Collections <= 3.1
- Apache Commons Collections <= 4.0
- Groovy <= 2.3.9
- Spring Core <= 4.1.4 (?)
- JDK <=7u21
- Apache Commons BeanUtils 1.9.2 + Commons Collections <=3.1 + Commons Logging 1.2 (?)

Additional tools:
- [JavaSerialKiller](https://github.com/NetSPI/JavaSerialKiller) - access to ysoserial in Burp extension 

How it works:
- [https://blog.srcclr.com/commons-collections-deserialization-vulnerability-research-findings/](https://blog.srcclr.com/commons-collections-deserialization-vulnerability-research-findings/)
- [http://gursevkalra.blogspot.ro/2016/01/ysoserial-commonscollections1-exploit.html](http://gursevkalra.blogspot.ro/2016/01/ysoserial-commonscollections1-exploit.html)

##### ACEDcup 
[https://github.com/GrrrDog/ACEDcup](https://github.com/GrrrDog/ACEDcup)

File uploading via:
- Apache Commons FileUpload <= 1.3 (CVE-2013-2186) and Oracle JDK < 7u40 

##### JNDI RCE
[https://github.com/zerothoughts/jndipoc](https://github.com/zerothoughts/jndipoc)

How it works:
- [JNDI remote code injection](http://zerothoughts.tumblr.com/post/137769010389/fun-with-jndi-remote-code-injection)

RCE via JNDI:

- When we control an adrress for lookup of JNDI (context.lookup(address))

##### Universal billion-laughs DoS 
[https://gist.github.com/coekie/a27cc406fc9f3dc7a70d](https://gist.github.com/coekie/a27cc406fc9f3dc7a70d)

Won't fix DoS via default Java classes

##### Universal Heap overflows DoS using Arrays and HashMaps  
[https://github.com/topolik/ois-dos/](https://github.com/topolik/ois-dos/)

How it works:
- [Java Deserialization DoS - payloads](http://topolik-at-work.blogspot.ru/2016/04/java-deserialization-dos-payloads.html)

Won't fix DoS via default Java classes

### Exploits 

no spec tool - You don't need a special tool (just Burp/ZAP + payload) 

##### RMI 
- *Protocol*
- *Default - 1099/tcp for rmiregistry*

[yososerial](#yososerial) (works only against a RMI registry service)

##### JMX 
- *Protocol based on RMI*

[yososerial](#yososerial)

##### T3 of Oracle Weblogic
- *Protocol*
- *Default - 7001/tcp on localhost interface*
- [CVE-2015-4852](https://www.vulners.com/search?query=CVE-2015-4852)

[loubia](https://github.com/metalnas/loubia) (tested on 11g and 12c, supports t3s)

[JavaUnserializeExploits](https://github.com/foxglovesec/JavaUnserializeExploits) (doesn't work for all Weblogic versions)

##### Websphere 
- *wsadmin*
- *Default port - 8880/tcp*
- [CVE-2015-7450](https://www.vulners.com/search?query=CVE-2015-7450)

[JavaUnserializeExploits](https://github.com/foxglovesec/JavaUnserializeExploits)

[serialator](https://github.com/roo7break/serialator)

##### JBoss 
- *http://jboss_server/invoker/JMXInvokerServlet*
- *Default port - 8080/tcp*
- [CVE-2015-7501](https://www.vulners.com/search?query=CVE-2015-7501)

[JavaUnserializeExploits](https://github.com/foxglovesec/JavaUnserializeExploits)

[https://github.com/njfox/Java-Deserialization-Exploit](https://github.com/njfox/Java-Deserialization-Exploit)

[serialator](https://github.com/roo7break/serialator)

##### Jenkins 
- *Jenkins CLI*
- *Default port - High number/tcp*
- [CVE-2015-8103](https://www.vulners.com/search?query=CVE-2015-8103)

[JavaUnserializeExploits](https://github.com/foxglovesec/JavaUnserializeExploits)

##### Restlet
- *<= 2.1.2*
- *When Rest API accepts serialized objects (uses ObjectRepresentation)*

no spec tool

##### OpenNMS
- RMI

[yososerial](#yososerial)

##### Progress OpenEdge RDBMS
- RMI

[yososerial](#yososerial)

#####  Commvault Edge Server 
- [CVE-2015-7253](https://www.vulners.com/search?query=CVE-2015-7253)
- Serialized object in cookie

no spec tool

##### Symantec Endpoint Protection Manager 
- */servlet/ConsoleServlet?ActionType=SendStatPing*
- [CVE-2015-6555](https://www.vulners.com/search?query=CVE-2015-6555)

[serialator](https://github.com/roo7break/serialator)

### Detect 
##### Code review 
- *ObjectInputStream.readObject*
- *ObjectInputStream.readUnshared*
- Tool: [Find Security Bugs](http://find-sec-bugs.github.io/)

##### Traffic
- *Magic bytes 'ac ed 00 05' bytes*
- *'rO0' for Base64*

##### Burp plugins 
- [Java Deserialization Scanner ](https://github.com/federicodotta/Java-Deserialization-Scanner)
- [SuperSerial](https://github.com/DirectDefense/SuperSerial)
- [SuperSerial-Active](https://github.com/DirectDefense/SuperSerial-Active)

### Vulnerable apps (without public sploits/need more info)  

##### JSF ViewState
##### JMS (Java Messaging System)
##### Spring Service Invokerts (HTTP, JMS, RMI...)
##### SAP P4
- [from slides](#java-deserialization-vulnerabilities---the-forgotten-bug-class)
- 
##### Apache SOLR 
- [SOLR-8262](https://issues.apache.org/jira/browse/SOLR-8262)
- 5.1 <= version <=5.4
- /stream handler uses Java serialization for RPC 

##### Apache Shiro 
- [SHIRO-550](https://issues.apache.org/jira/browse/SHIRO-550)
- encrypted cookie (with the hardcoded key)

##### ActiveMQ
- [*CVE-2015-5254*](http://activemq.apache.org/security-advisories.data/CVE-2015-5254-announcement.txt)
- *<= 5.12.1*
- [*Explanation of the vuln*](https://srcclr.com/security/deserialization-untrusted-data/java/s-1893)
- [CVE-2015-7253](https://www.vulners.com/search?query=2015-7253)

##### Atlassian Bamboo 1
- [CVE-2015-6576](https://confluence.atlassian.com/x/Hw7RLg)
-  *2.2 <= version < 5.8.5*
- *5.9.0 <= version < 5.9.7*

##### Atlassian Bamboo 2
- [*CVE-2015-8360*](https://confluence.atlassian.com/bamboo/bamboo-security-advisory-2016-01-20-794376535.html)
- *2.3.1 <= version < 5.9.9*
- Bamboo JMS port (port 54663 by default)

##### Spring AMPQ
- [CVE-2016-2173](http://pivotal.io/security/cve-2016-2173)
- *1.0.0 <= version < 1.5.5

##### Jenkins 2
- [CVE-2016-0788](https://www.vulners.com/search?query=CVE-2016-0788)

##### Apache HBase 
- [HBASE-14799](https://issues.apache.org/jira/browse/HBASE-14799)

##### Apache Camel 
- [CVE-2015-5348](https://www.vulners.com/search?query=CVE-2015-5348)

##### Oracle Hyperion 
- [from slides](#java-deserialization-vulnerabilities---the-forgotten-bug-class)

##### Red Hat JBoss BPM Suite
- [RHSA-2016-0539](http://rhn.redhat.com/errata/RHSA-2016-0539.html)
- [CVE-2016-2510](https://www.vulners.com/search?query=CVE-2016-2510)

##### VMWare vCenter/vRealize (various) 
- [CVE-2015-6934](https://www.vulners.com/search?query=CVE-2015-6934)

##### Cisco (various)
- [List of vulnerable products](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151209-java-deserialization)
- [CVE-2015-6420](https://www.vulners.com/search?query=CVE-2015-6420)

##### Lexmark Markvision Enterprise 
- [CVE-2016-1487](http://support.lexmark.com/index?page=content&id=TE747&locale=en&userlocale=EN_US)

#####  McAfee ePolicy Orchestrator 
- [CVE-2015-8765](https://www.vulners.com/search?query=CVE-2015-8765)

#####  HP Operations Orchestration
- [CVE-2016-1997](https://www.vulners.com/search?query=CVE-2016-1997)

#####  HP Asset Manager
- [CVE-2016-2000](https://www.vulners.com/search?query=CVE-2016-2000)
 
##### HP Service Manager
- [CVE-2016-1998](https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05054565)

##### HP Operations Manager
- [CVE-2016-1985](https://h20565.www2.hpe.com/hpsc/doc/public/display?calledBy=Search_Result&docId=emr_na-c04953244&docLocale=en_US)

##### HP Release Control
- [CVE-2016-1999](https://h20565.www2.hpe.com/hpsc/doc/public/display?calledBy=Search_Result&docId=emr_na-c05063986&docLocale=en_US)

##### HP Continuous Delivery Automation
- [CVE-2016-1986](https://h20565.www2.hpe.com/hpsc/doc/public/display?calledBy=Search_Result&docId=emr_na-c04958567&docLocale=en_US)

##### Adobe Experience Manager 
- [CVE-2016-0958](https://www.vulners.com/search?query=CVE-2016-0958)

#####  Unify OpenScape (various) 
- [CVE-2015-8237](https://www.vulners.com/search?query=CVE-2015-8237)
- RMI (30xx/tcp)
- [CVE-2015-8238](https://www.vulners.com/search?query=CVE-2015-8238)
- js-soc protocol (4711/tcp)

##### Apache TomEE
- [CVE-2015-8581](https://www.vulners.com/search?query=CVE-2015-8581)
- [CVE-2016-0779](https://www.vulners.com/search?query=CVE-2016-0779)

##### IBM Congnos BI 
- [CVE-2012-4858](https://www.vulners.com/search?query=CVE-2012-4858)

##### ForgeRock OpenAM 
- *9-9.5.5, 10.0.0-10.0.2, 10.1.0-Xpress, 11.0.0-11.0.3 and 12.0.0*
- [201505-01](https://forgerock.org/2015/07/openam-security-advisory-201505/)

##### F5 (various) 
- [sol30518307](https://support.f5.com/kb/en-us/solutions/public/k/30/sol30518307.html)

##### Hitachi (various) 
- [HS16-010](http://www.hitachi.co.jp/Prod/comp/soft1/global/security/info/vuls/HS16-010/index.html)
- [0328_acc](http://www.hitachi.co.jp/products/it/storage-solutions/global/sec_info/2016/0328_acc.html)

##### Apache OFBiz
- [CVE-2016-2170](https://blogs.apache.org/ofbiz/date/20160405)
 
##### NetApp (various)
- [CVE-2015-8545](https://kb.netapp.com/support/index?page=content&id=9010052)

##### Apache Tomcat
##### Apache Batchee
##### Apache JCS
##### Apache OpenJPA
##### Apache OpenWebBeans

### Protection 
- [Look-ahead Java deserialization](http://www.ibm.com/developerworks/library/se-lookahead/ )
- [NotSoSerial](https://github.com/kantega/notsoserial)
- [SerialKiller](https://github.com/ikkisoft/SerialKiller)
- [ValidatingObjectInputStream](https://issues.apache.org/jira/browse/IO-487)
- [Some protection bypasses](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet/blob/master/README.md#serial-killer-silently-pwning-your-java-endpoints)

### For Android 
- [One Class to Rule Them All: 0-Day Deserialization Vulnerabilities in Android](https://www.usenix.org/conference/woot15/workshop-program/presentation/peles)
- [Android Serialization Vulnerabilities Revisited](https://www.rsaconference.com/events/us16/agenda/sessions/2455/android-serialization-vulnerabilities-revisited)

### Other serialization types
##### XMLEncoder 
- [http://blog.diniscruz.com/2013/08/using-xmldecoder-to-execute-server-side.html](http://blog.diniscruz.com/2013/08/using-xmldecoder-to-execute-server-side.html)

##### XStream 
- [http://www.pwntester.com/blog/2013/12/23/rce-via-xstream-object-deserialization38/](http://www.pwntester.com/blog/2013/12/23/rce-via-xstream-object-deserialization38/)
- [http://blog.diniscruz.com/2013/12/xstream-remote-code-execution-exploit.html](http://blog.diniscruz.com/2013/12/xstream-remote-code-execution-exploit.html)
- [https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-2-xstream](https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-2-xstream)

##### Kryo
- [https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-1-kryo](https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-1-kryo)
