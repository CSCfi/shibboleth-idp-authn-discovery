# Shibboleth IdP Authn Flow Discovery

> **Warning**
> This module is developed and has been used only in-house and that reflects on level of GH documentation.
> The documentation is just some notes to a reader assumed to be familiar with Shibboleth and just wants to have a go with this module. 

[![License](http://img.shields.io/:license-mit-blue.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://travis-ci.org/CSCfi/shibboleth-idp-authn-discovery.svg?branch=master)](https://travis-ci.org/CSCfi/shibboleth-idp-authn-discovery)

## Overview

This module implements a simple authentication method selection flow for [Shibboleth Identity Provider v5](https://shibboleth.atlassian.net/wiki/spaces/IDP5/overview). The module can be used for first displaying all
the available authentication flows and then proceeding with the user-selected authentication flow.

## Prerequisities and compilation

- Java 17+
- [Apache Maven 3](https://maven.apache.org/)

```
mvn package
```

After successful compilation, the _target_ directory contains _shibboleth-idp-authn-discovery-<version>.zip_.

## Deployment

> **Note**
> Release [2.0.0](https://github.com/CSCfi/shibboleth-idp-authn-discovery/releases/tag/2.0.0) is for Shib Idp v5. Not truly tested yet! Fresh from the oven!
> Release [1.0.0-rc2](https://github.com/CSCfi/shibboleth-idp-authn-discovery/releases/tag/1.0.0-rc2) is for Shib Idp v4. There is version Releases [1.1.0](https://github.com/CSCfi/shibboleth-idp-authn-discovery/releases/tag/1.1.0) but it seems not be used - so no guarantees on it.

Either compile the module yourself or use assets from releases. The module deployment is done by unpacking the archive to Shibboleth directory and and rebuilding the WAR file:

```
cd /opt/shibboleth-idp
tar -xf path/to/shibboleth-idp-authn-discovery-<version>.tar.gz  --strip-components=1
bin/build.sh
```

The final command will rebuild the _war_-package for the IdP application.

## Configuration walktrough 

### Introduction and activation
First you will need to introduce the new authentication flow definition in _/opt/shibboleth-idp/conf/authn/general-authn.xml_ by adding it to _shibboleth.AvailableAuthenticationFlows_

```
<util:list id="shibboleth.AvailableAuthenticationFlows">
    <bean id="authn/Disco" parent="shibboleth.AuthenticationFlow" p:passiveAuthenticationSupported="true" p:forcedAuthenticationSupported="true"/>
    <!-- If list contains already beans there is no reason to remove them. -->
</util:list>
```

then activate the flow in _conf/authn/authn.properties_
```
# Example of three active flows
idp.authn.flows = Disco|SAML|Password
```
add finally following to to any of your active properties files, for instance to _idp.properties_.

```
idp.discovery.authority.properties = %{idp.home}/conf/authn/discovery.properties
```
Depending on your IdP authentication flow configuration the previous may be enough. If so user is first  presented with Discovery view to select between available authentication flows that would be 'Password' and 'SAML' in this example case. If however user is not presented first the Discovery view and 'Disco' flow you need to study the [Shibboleth authentication flow selection mechanism](https://shibboleth.atlassian.net/wiki/spaces/IDP4/pages/1265631603/AuthenticationFlowSelection) and then configure 'Disco' so that it will be the selected flow.

### Managing flows available for Relying Party
Discovery will show all available authentication flows. If you need to limit the flows shown per RP that can and must be done by whatever means Shibboleth offers to solve that. Following example would list only 'SAML' in Discovery options for the group of SPs.

```
<util:list id="shibboleth.RelyingPartyOverrides">
    <!-- The relying parties that we allow to use Only Disco and SAML authentication. -->
    <bean parent="RelyingPartyByName" c:relyingPartyIds="%{idp.relayingparty.disable.password}">
      <property name="profileConfigurations">
        <list>
          <bean parent="SAML2.SSO" p:authenticationFlows="#{{'Disco','SAML'}}"/>
         </list>
      </property>
    </bean>
</util:list>    
```
### Managing upstream providers
Your IdP SAML flow may be configured to use single upstream discovery url or entity. In that case it is enough for Discovery view to show it as one selectable item and  signal that 'SAML' is the next flow to perform. Upstream provider is determined by the static 'SAML' flow configuration in that case. However If you have multiple upstream discovery urls or entities, as you often do, that is not enough. First you must express somehow to to 'Disco' flow that 'SAML' is not just one selectable item but many. That can be done _conf/authn/discovery.properties_.

You may define Authenticating Authority values per flow in _discovery.properties_. For each value 'Disco' will present separate selectable item in discovery view.

```
authn/SAML = Authority1, Authority2, Authority3
```
This may also be defined per relying party by prefixing the flow name with relying party identifier.

```
authn/SAML = Authority1, Authority2, Authority3
https\://sp.example.com/shibboleth.authn/SAML = Authority1, Authority2
```
The result would be showing two selectable 'SAML' items to relying party 'https//sp.example.com/shibboleth' and three to all others. Next thing to solve is how this selection is carried to 'SAML' flow so that it understands it.

The Authenticating Authority is here treated only as a string and any semantics it has is what we give to it. Now, lets do following configuration instead:

```
authn/SAML = discovery:https://ds.example.com/DS, entity:https://idp.example.com/IDP 
```

Discovery view will have now two items for user to select from, one having Authenticating Authority as 'discovery:https://ds.example.com/DS' and second as 'entity:https://idp.example.com/IDP'. This is something we can now use in 'SAML' flow by implementing beans 'shibboleth.authn.SAML.discoveryFunction' and 'shibboleth.authn.discoveryURLStrategy'.

> **Warning**
> The following bean snippets are from IdP v4. May not work as such in v5.

> **Note**
> Decision use Authenticating Authority and Hinted Name to pass the data can easily be argued.
> It has been enough this far to know it works for us.


```
<bean id="shibboleth.authn.SAML.discoveryFunction" parent="shibboleth.ContextFunctions.Scripted" factory-method="inlineScript">
      <constructor-arg>
        <value>
          <![CDATA[
          logger = Java.type("org.slf4j.LoggerFactory").getLogger("shibboleth.authn.SAML.discoveryFunction");
          logger.debug("DiscoveryFunction selecting entity id (or passing discovery information)");
          entityId = null;
          authnContext = input.getSubcontext("net.shibboleth.idp.authn.context.AuthenticationContext");
          selection = null;
          if (authnContext.getAuthenticatingAuthority() != null){
              // User seems to have been presented with Disco
              selection = authnContext.getAuthenticatingAuthority();
              logger.debug("User selection by Disco for Authenticating Authority is {}", selection);
              if (selection.split("entity:").length == 2){
                  entityId = selection.split("entity:")[1];
                  logger.debug("DiscoveryFunction passing {} as upstream idp", entityId);
              } else if (selection.split("discovery:").length == 2) {
                  // Borrowing Hinted Name to pass data to discoveryURLStrategy.
                  authnContext.setHintedName(selection);
                  logger.debug("DiscoveryFunction storing {} as upstream discovery", selection.split("discovery:")[1]);
              }
          }
          entityId;
          ]]>
        </value>
      </constructor-arg>
</bean>
    
<bean id="shibboleth.authn.discoveryURLStrategy" parent="shibboleth.ContextFunctions.Scripted" factory-method="inlineScript">
      <constructor-arg>
        <value>
          <![CDATA[
          logger = Java.type("org.slf4j.LoggerFactory").getLogger("shibboleth.authn.discoveryURLStrategy");
          logger.debug("DiscoveryURLStrategy selecting discovery service");
          discoveryURL = null;
          authnContext = input.getSubcontext("net.shibboleth.idp.authn.context.AuthenticationContext");
          logger.debug("User selection for Discovery Service is {}", authnContext.getHintedName());
          if (authnContext.getHintedName() != null && authnContext.getHintedName().split("discovery:").length == 2){
              discoveryURL = authnContext.getHintedName().split("discovery:")[1];
              logger.debug("DiscoveryURLStrategy passing {} as upstream discovery url", discoveryURL);
          }
          discoveryURL;
          ]]>
        </value>
      </constructor-arg>
</bean>
```
