# Shibboleth IdP Authn Flow Discovery

[![License](http://img.shields.io/:license-mit-blue.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://travis-ci.org/CSCfi/shibboleth-idp-authn-discovery.svg?branch=master)](https://travis-ci.org/CSCfi/shibboleth-idp-authn-discovery)

## Overview

This module implements a simple authentication method selection flow for [Shibboleth Identity Provider v4](https://wiki.shibboleth.net/confluence/display/IDP4/Home). The module can be used for first displaying all
the available authentication flows and then proceeding with the user-selected authentication flow.

## Prerequisities and compilation

- Java 11+
- [Apache Maven 3](https://maven.apache.org/)

```
mvn package
```

After successful compilation, the _target_ directory contains _shibboleth-idp-authn-discovery-<version>.zip_.

## Deployment

After compilation, the module's JAR files must be deployed to the IdP Web
application. Also, the module's authentication flow, its bean definitions and view (user interface) must
be deployed to the IdP. Depending on the IdP installation, the module deployment may be achieved for instance 
with the following sequence:

```
unzip target/shibboleth-idp-authn-discovery-<version>.zip
cp shibboleth-idp-authn-discovery-<version>/edit-webapp/WEB-INF/lib/* /opt/shibboleth-idp/edit-webapp/WEB-INF/lib
cp -r shibboleth-idp-authn-discovery-<version>/flows/* /opt/shibboleth-idp/flows
cp shibboleth-idp-authn-discovery-<version>/views/* /opt/shibboleth-idp/conf/views
cd /opt/shibboleth-idp
sh bin/build.sh
```

The final command will rebuild the _war_-package for the IdP application.

Finally, you will need to add the new authentication flow definition to _/opt/shibboleth-idp/conf/authn/general-authn.xml_ as the first authentication bean definition:

```
<bean id="authn/Disco" parent="shibboleth.AuthenticationFlow"
            p:nonBrowserSupported="false" p:forcedAuthenticationSupported="true"/>
```
