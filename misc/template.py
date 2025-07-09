JAVACARD_XML = """<?xml version="1.0" encoding="UTF-8"?>
<javacard-app xmlns="http://java.sun.com/xml/ns/javacard"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://java.sun.com/xml/ns/javacard ../../../../docs/schemas/internal/applet-app_3_0.xsd"
       version="3.0">
</javacard-app>"""


APPLET_XML = """<?xml version="1.0" encoding="UTF-8"?>
<applet-app xmlns="http://java.sun.com/xml/ns/javacard"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://java.sun.com/xml/ns/javacard ../../../../docs/schemas/internal/applet-app_3_0.xsd"
       version="3.0">
  <applet>
    <description>HelloWorldApplet</description>
    <display-name>HelloWorldApplet</display-name>
    <applet-class>helloworldPackage.HelloWorldApplet</applet-class>
    <applet-AID>//aid/4444444444/01</applet-AID>
  </applet>
</applet-app>"""

MANIFEST_MF = f"""Manifest-Version: 1.0
Created-By: 21.0.7 (Ubuntu)
Runtime-Descriptor-Version: 3.0
Application-Type: classic-applet
Classic-Package-AID: //aid/4444444444/
Sealed: true

Name: helloworldPackage
Java-Card-CAP-Creation-Time: Mon Jul 07 13:05:47 CEST 2025
Java-Card-Converter-Version:  [v25.0]
Java-Card-Converter-Provider: Oracle Corporation
Java-Card-CAP-File-Version: 2.1
Java-Card-Package-Version: 1.0
Java-Card-Package-Name: helloworldPackage
Java-Card-Package-AID: 0x44:0x44:0x44:0x44:0x44
Java-Card-Applet-1-Name: HelloWorldApplet
Java-Card-Applet-1-AID: 0x44:0x44:0x44:0x44:0x44:0x01
Java-Card-Imported-Package-1-AID: 0xa0:0x00:0x00:0x00:0x62:0x01:0x01
Java-Card-Imported-Package-1-Version: 1.6
Java-Card-Imported-Package-2-AID: 0xa0:0x00:0x00:0x00:0x62:0x00:0x01
Java-Card-Imported-Package-2-Version: 1.0
Java-Card-Integer-Support-Required: FALSE

"""
