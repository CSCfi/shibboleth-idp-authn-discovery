# Shibboleth IdP Authn Flow Discovery

> **Warning**
> This module is developed and has been used only in-house and that reflects on level of GH documentation. None of our admins ever read this anyway.
> The documentation is just some notes to a reader assumed to be familiar with Shibboleth and just wants to have a go with this module. 

[![License](http://img.shields.io/:license-mit-blue.svg)](https://opensource.org/licenses/MIT)

## Overview

This module implements a simple authentication method selection flow for [Shibboleth Identity Provider v5](https://shibboleth.atlassian.net/wiki/spaces/IDP5/overview). The module can be used for first displaying all
the available authentication flows and then proceeding with the user-selected authentication flow.

### Example of selection view
![Näyttökuva 2024-09-18 kello 8 29 01](https://github.com/user-attachments/assets/e95e518d-e1b1-456e-a346-a06d6ad56439)


## Compilation

- Java 17+
- [Apache Maven 3](https://maven.apache.org/)

```
mvn package
```

## Deployment

> **Note**
> Latest release is for Shib Idp v5.
> Release [1.0.0-rc2](https://github.com/CSCfi/shibboleth-idp-authn-discovery/releases/tag/1.0.0-rc2) is for Shib Idp v4.

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
add finally add following to any of your active properties files, for instance to _idp.properties_.

```
idp.discovery.authority.properties = %{idp.home}/conf/authn/discovery.properties
```
Depending on your IdP configuration the previous may be enough. If that is the case, user is first presented with Discovery view to select between available authentication flows that would be 'Password' and 'SAML' in this example case. If however user is not presented first the Discovery view and 'Disco'-flow  is not executed, you need to study the [Shibboleth authentication flow selection mechanism](https://shibboleth.atlassian.net/wiki/spaces/IDP4/pages/1265631603/AuthenticationFlowSelection) and then configure 'Disco'-flow so that it will be the selected flow.

### Managing flows available for Relying Party
Discovery view will show all available authentication flows for user to choose from. If you need to limit the flows shown for instance per RP or request that can be done by whatever means Shibboleth offers. Following example would list only 'SAML' in Discovery options for the group of SPs.

> ⚠️ **Deprecated:** `setAuthenticationFlows` is deprecated in Shibboleth 5.2.0.

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
## Version 2.1.0 Features
### Version 2.1.0 and remembering user prior selection
Discovery can now be set to remember user prior selection bypassing Disco view. If you set java properties 
```
idp.discovery.storeSelection = true
```
discovery will store user's selection to session and use it automatically on subsequent execution. If prior selection is not applicable Disco view is shown. 

### Version 2.1.0 and JSON configuration
Version 2.1.0 provides alternate way to configure discovery items as JSON and a helper to apply details of selected item in later stages. Here is an example of such configuration for a setup where we want to direct all requests for MFA authentication configuration to handle.

> **Note**
> Giving the JSON inline in the `idp.discovery.authorities` property still works exactly as it always has. As of version 2.3.0 the same JSON can instead be read from a file or an URL and refreshed while the IdP runs; see [Version 2.3.0 and discovery configuration resolvers](#version-230-and-discovery-configuration-resolvers).

```
idp.discovery.authorities = { \
  "default": { \
    "authn/MFA": [ \
      { \
        "aaType": "discovery", \
        "acr": "https://example.com/LoginMethodOne", \
        "aaValue": "https://wayf.com/WAYF", \
        "name": "MethodOne" \
      }, \
      { \
        "aaType": "discovery", \
        "acr": "https://example.com/LoginMethodOneMFA", \
        "aaValue": "https://wayf.com/WAYF", \
        "hidden": true \
      }, \
      { \
        "aaType": "entity", \
        "acr": "https://example.com/LoginMethodTwo", \
        "aaValue": "https://idp.com/idp" \
      }, \
      { \
        "aaType": "issuer", \
        "acr": "https://example.com/LoginMethodThree", \
        "aaValue": "https://issuer.com/issuer" \
      }, \
      { \
        "acr": "https://example.com/LoginLocalPassword" \
      }, \
      { \
        "acr": "https://example.com/LoginLocalPasswordMFA", \
        "hidden": true \
      }, \
      { \
        "acr": "https://example.com/LoginCandourID", \
        "flow": "authn/candourid" \
      } \
    ] \
  }, \
  "https://rp.with.specific.needs.com": { \
    "authn/MFA": [ \
      { \
        "aaType": "discovery", \
        "acr": "https://example.com/LoginMethodOne", \
        "aaValue": "https://wayf.com/WAYF" \
      }, \
      { \
        "acr": "https://example.com/LoginLocalPassword" \
      } \
    ] \
  } \
}
```
The top-level `"default"` key is required. Other top-level keys are optional relying party ids used to override the default for that RP.

Let's go item by by what we have configured here. Each of the JSON Objects in the "authn/MFA" array represent a Authenticating Authority information to be shown in Discovery for user to select. Notice that most of the fields have meaning only because scripts running in later phases apply the information and act accordingly. The fields of the object are

*   acr
    * Mandatory string. Authentication Context Class value for the item. This is used by our scripts as if the original authentication request had this value. We want shibboleth internal machinery work the same way regardless the original request had the acr or if it was chosen by user in discovery view.
*   aaType
    * Optional string. Type of the Authenticating Authority. We use types 'issuer','discovery' and 'entity' in scripts to direct user to OIDC Issuer, SAML Discovery or SAML Entity. 
*   aaValue
    * Optional string. Value of Authenticating Authority. We set there value of 'issuer', 'discovery' or 'entity' for scripts to later apply.
*   name
    * Optional string. Helper to for instance resolve logo or text for the item in Discovery view.
*   flow
    * Optional string. Helper to direct user to next flow in MFA configuration.
*   hidden
    * Optional boolean. If set to true, item is not shown in Discovery. Information can still be used by scripts to match requested acr values to upstream providers.   
```
{ \
  "aaType": "discovery", \
  "acr": "https://example.com/LoginMethodOne", \
  "aaValue": "https://wayf.com/WAYF", \
  "name": "MethodOne" \
}
``` 
This will appear to disco as one selectable item. Here is now a example discovery.vm that uses this new structure. Notice the use of helper DiscoveryAuthenticatingAuthority to parse the Authenticating Authority information and resolve the name to show correct image and helper texts. Please note also the example template most likely does not work as is. 

```
#set ($flowList = $authenticationDiscoveryContext.getFlowsWithAuthorities())
#set ($DiscoveryAuthenticatingAuthority=$flowList.class.forName('fi.csc.shibboleth.authn.conf.DiscoveryAuthenticatingAuthority'))
<!DOCTYPE html>
<html>
  #set ($discoFlowId = $authenticationContext.getAttemptedFlow().getId())
  <head>
    <meta charset="utf-8">
    <title>#springMessageText("idp.title", "Web Login Service")</title>
    <link rel="stylesheet" type="text/css" href="$request.getContextPath()/css/main.css">
  </head>
  <body>
    <div class="wrapper">
      <div class="container">
        <header>
          <img src="$request.getContextPath()#springMessage("idp.logo")" alt="#springMessageText("idp.logo.alt-text", "logo")">
        </header>
        <div class="content">
          <div class="column one">
            #foreach ($mapEntry in $flowList)
              #if ($mapEntry.second)
               #set ($messageKey = $mapEntry.first + "." + $mapEntry.second + ".message")
               #set ($link = $flowExecutionUrl + "&j_authnflow=" + $mapEntry.first + "&j_authnauthority="+ $mapEntry.second + "&_eventId_proceed=_eventId_proceed")
               #set ($name = $DiscoveryAuthenticatingAuthority.parseB64UrlEncoded($mapEntry.second).getName())
               #set ($imageName = "/images/" + $name + ".png")
               #set ($propertyName = "discovery-name." + $name)
               <c-login-button tabindex="" href="$link#if($csrfToken)&${csrfToken.parameterName}=${csrfToken.token}#{else}#end" src="$imageName" alt="#springMessageText($propertyName, $name)">
              #springMessageText($propertyName, "Login")
              </c-login-button>
              #end
            #end
          </div>
        </div>
      </div>
      <footer>
    <div class="container container-footer">
          <p class="footer-text">#springMessageText("idp.footer", "Insert your footer text here.")</p>
        </div>
      </footer>
    </div>
  </body>
</html>
``` 

### Version 2.1.0 and MFA configuration
Discovery can still be configured to signal any flow as next flow. There are obvious benefits for having only two active flows though, Disco and MFA. Having all authentication orchestrated by MFA configuration means that we have also one single location to manage information provided by Disco flow. As a result JSON configuration can be used not only as a way to describe what is shown in Discovery but also to limit what ACR values can be used by RP.

> **Warning**
> The following bean snippets are example and should not be used as is.

```
<bean id="discovery.authorities" class="java.lang.String" c:_0="%{idp.discovery.authorities}" />
```

```
<!--
        Your first step in MFA configuration that selects next flow by AA information provided by Disco or AA that matches requested principal.
        Script assumes RPs may request for only one ACR (that is how we run it).
-->
<bean id="selectFirstFactor" parent="shibboleth.ContextFunctions.Scripted" factory-method="inlineScript" p:customObject-ref="discovery.authorities">
    <constructor-arg>
        <value>
            <![CDATA[
                
                nextFlow = null;
                logger = Java.type("org.slf4j.LoggerFactory").getLogger("net.shibboleth.idp.authn");
                authCtx = input.getSubcontext("net.shibboleth.idp.authn.context.AuthenticationContext");
                var discoveryAuthenticatingAuthority = null; 
                if (authCtx.getAuthenticatingAuthority() != null){
                    // User seems to have been presented with Disco. We resolve discoveryAuthenticatingAuthority from Disco selection.
                    // Based on what is provided in JSON configuration as acr we set requested principal.

                    //Downstream protocol determines the principal type.
                    AuthenticationContextClassReferencePrincipal = "http://shibboleth.net/ns/profiles/oidc/sso/browser".equals(input.getProfileId()) ?
                                                               Java.type("net.shibboleth.oidc.authn.principal.AuthenticationContextClassReferencePrincipal"):
                                                               Java.type("net.shibboleth.idp.saml.authn.principal.AuthnContextClassRefPrincipal");
                    
                    selection = authCtx.getAuthenticatingAuthority();
                    DiscoveryAuthenticatingAuthority = Java.type("fi.csc.shibboleth.authn.conf.DiscoveryAuthenticatingAuthority");
                    discoveryAuthenticatingAuthority = DiscoveryAuthenticatingAuthority.parseB64UrlEncoded(selection);
                    var principal = new AuthenticationContextClassReferencePrincipal(discoveryAuthenticatingAuthority.getAcr());
                    logger.info("User selection matched to ACR {}", principal);
                    ArrayList = Java.type("java.util.ArrayList");
                    var principals = new ArrayList();
                    principals.add(principal);

                    RequestedPrincipalContext = Java.type("net.shibboleth.idp.authn.context.RequestedPrincipalContext");
                    requestedPrincipalContext = new RequestedPrincipalContext();
                    requestedPrincipalContext.setPrincipalEvalPredicateFactoryRegistry(authCtx.getPrincipalEvalPredicateFactoryRegistry());
                    requestedPrincipalContext.setOperator("exact");
                    requestedPrincipalContext.setRequestedPrincipals(principals);
                    authCtx.addSubcontext(requestedPrincipalContext, true);
                } else {
                    // RP has bypassed Disco by setting ACR  matching MFA configuration.
                    // We verify client has JSON configuration matching ACR and resolve discoveryAuthenticatingAuthority 
                    DiscoveryConfiguration = Java.type("fi.csc.shibboleth.authn.conf.DiscoveryConfiguration");
                    var discoveryConfiguration = DiscoveryConfiguration.parse(custom);
                    var RelyingPartyIdLookupFunction = Java.type("net.shibboleth.profile.context.navigate.RelyingPartyIdLookupFunction");
                    var relyingPartyIdLookupFunction = new RelyingPartyIdLookupFunction();
                    rpId = relyingPartyIdLookupFunction.apply(input);
                    var discoveryFlows = discoveryConfiguration.getFlowMap().containsKey(rpId)
                      ? discoveryConfiguration.getFlowMap().get(rpId)
                      : discoveryConfiguration.getFlowMap().get("default");
                    var requestedPrincipalContext = authCtx.getSubcontext("net.shibboleth.idp.authn.context.RequestedPrincipalContext");
                    if (requestedPrincipalContext != null) {
                        requestedPrincipals = requestedPrincipalContext.getRequestedPrincipals();
                        if (requestedPrincipals != null) {
                            iterator = requestedPrincipals.iterator();
                            while (iterator.hasNext()) {
                                principal = iterator.next();
                                logger.debug("selectFirstFactor matching {}", principal);
                                flows = discoveryFlows.getAuthorityMap().keySet().iterator();
                                while (flows.hasNext()){
                                    flow = flows.next();
                                    authorities = discoveryFlows.getAuthorityMap().get(flow).iterator();
                                    while (authorities.hasNext()){
                                        authority = authorities.next();
                                        if (principal.getName().equals(authority.getAcr())) {
                                            discoveryAuthenticatingAuthority = authority;
                                            break;
                                        }
                                    }
                                    if (discoveryAuthenticatingAuthority != null) {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                // Now we have discoveryAuthenticatingAuthority unless request is unsupported for RP.
                // 1st way to pick next flow. Resolve it from JSON configuration optional field 'flow'.
                if (discoveryAuthenticatingAuthority != null && discoveryAuthenticatingAuthority.getFlow() != null) {
                    nextFlow = discoveryAuthenticatingAuthority.getFlow();
                }

                // 2nd way to pick next flow. Use ACR value.
                if (discoveryAuthenticatingAuthority != null && discoveryAuthenticatingAuthority.getFlow() == null) {
                    switch (discoveryAuthenticatingAuthority.getAcr()) {
                      
                      case "yourAcrOne":
                      case "yourAcrTwo":
                        nextFlow = "authn/OIDCRelyingParty";
                        break;
                      
                      default:
                        nextFlow = "authn/SAML";
                    }
                }
                // RP has asked for ACR that is not supported.
                if (nextFlow == null){
                    logger.error("selectFirstFactor unable to pick method for requested acr");
                    mfaCtx = authCtx.getSubcontext("net.shibboleth.idp.authn.context.MultiFactorAuthenticationContext");
                    mfaCtx.setEvent("RequestUnsupported");
                }
                logger.debug("selectFirstFactor picked {} as next flow", nextFlow);
                nextFlow;
            ]]>
        </value>
    </constructor-arg>
</bean>
```
### Version 2.1.0 and upstream providers for OIDC and SAML authentication flows
The new helper classes are in these examples used to parse upstream Authenticating Authority information for SAML and OIDC authentication flows. There are two possibilities again. Either user has already selected the AA information by using the Disco or Disco has been bypassed by using ACR in the request. In the latter case _csc.discoveryFunction_ searches for matching AA JSON configuration per requested principal. As a result bean is able to return issuer or entity id value, or in the case of discovery, null is returned and discovery url is stored for _shibboleth.authn.discoveryURLStrategy_ to return it for saml flow.

> **Warning**
> The following bean snippets are example and should not be used as is.

```
<bean id="csc.discoveryFunction" parent="shibboleth.ContextFunctions.Scripted" factory-method="inlineScript" p:customObject-ref="discovery.authorities">
  <constructor-arg>
    <value>
      <![CDATA[
      logger = Java.type("org.slf4j.LoggerFactory").getLogger("csc.discoveryFunction");
      logger.debug("DiscoveryFunction selecting entity id (or passing discovery information)");
      entityId = null;
      authnContext = input.getSubcontext("net.shibboleth.idp.authn.context.AuthenticationContext");
      requestedPrincipalContext = authnContext.getSubcontext("net.shibboleth.idp.authn.context.RequestedPrincipalContext");
      selection = null;
      if (authnContext.getAuthenticatingAuthority() != null){
          // User seems to have been presented with Disco
          selection = authnContext.getAuthenticatingAuthority();
          logger.debug("User selection by Disco for Authenticating Authority is {}", selection);
      }else{
          // We try to match ACR to discovery configuration to find out upstream, 
          DiscoveryConfiguration = Java.type("fi.csc.shibboleth.authn.conf.DiscoveryConfiguration");
          var discoveryConfiguration = DiscoveryConfiguration.parse(custom);
          var RelyingPartyIdLookupFunction = Java.type("net.shibboleth.profile.context.navigate.RelyingPartyIdLookupFunction");
          var relyingPartyIdLookupFunction = new RelyingPartyIdLookupFunction();
          rpId = relyingPartyIdLookupFunction.apply(input);
          var discoveryFlows = discoveryConfiguration.getFlowMap().containsKey(rpId)
            ? discoveryConfiguration.getFlowMap().get(rpId)
            : discoveryConfiguration.getFlowMap().get("default");
          if (requestedPrincipalContext != null){
              for (index = 0; index < requestedPrincipalContext.getRequestedPrincipals().length; index++) {
                  p = requestedPrincipalContext.getRequestedPrincipals()[index];
                  logger.debug("Relying party {} asked for principal with name {}", rpId, p.getName());
                  //Look for p.getName() in discoveryFlows
                  flows = discoveryFlows.getAuthorityMap().keySet().iterator();
                  while (flows.hasNext()){
                      flow = flows.next();
                      authorities = discoveryFlows.getAuthorityMap().get(flow).iterator();
                      while (authorities.hasNext()){
                          authority = authorities.next();
                          if (p.getName().equals(authority.getAcr())) {
                              selection = authority.toB64UrlEncoded();
                              break;
                          }
                      }
                      if (selection != null) {
                          break;
                      }
                  }
                  if (selection != null){
                      logger.debug("User selection by ACR for Authenticating Authority is {}", selection);
                  }else{ 
                      logger.warn("Missing ACR mapping for requested ACR {} by relying party {}.", p.getName(), rpId);
                  }
              }
          }
      }
      if (selection != null){
          DiscoveryAuthenticatingAuthority = Java.type("fi.csc.shibboleth.authn.conf.DiscoveryAuthenticatingAuthority");
          var discoveryAuthenticatingAuthority = DiscoveryAuthenticatingAuthority.parseB64UrlEncoded(selection);
          if ("discovery".equals(discoveryAuthenticatingAuthority.getType())) {
              // Borrowing Hinted Name to pass data to discoveryURLStrategy.
              var dsUrl = discoveryAuthenticatingAuthority.getValue();
              authnContext.setHintedName(dsUrl);
              logger.debug("DiscoveryFunction storing {} as upstream discovery", dsUrl);
          } else {
              entityId = discoveryAuthenticatingAuthority.getValue();
              logger.debug("DiscoveryFunction passing {} as upstream idp", entityId);
          }
      }
      entityId;
      ]]>
    </value>
  </constructor-arg>
</bean>

<bean id="shibboleth.authn.SAML.discoveryFunction" parent="csc.discoveryFunction"/>
<bean id="shibboleth.authn.oidc.rp.discoveryFunction" parent="csc.discoveryFunction"/>

<bean id="shibboleth.authn.discoveryURLStrategy" parent="shibboleth.ContextFunctions.Scripted" factory-method="inlineScript">
  <constructor-arg>
    <value>
      <![CDATA[
      logger = Java.type("org.slf4j.LoggerFactory").getLogger("shibboleth.authn.discoveryURLStrategy");
      logger.debug("DiscoveryURLStrategy selecting discovery service");
      discoveryURL = null;
      authnContext = input.getSubcontext("net.shibboleth.idp.authn.context.AuthenticationContext");
      logger.debug("User selection for Discovery Service is {}", authnContext.getHintedName());
      if (authnContext.getHintedName() != null){
          discoveryURL = authnContext.getHintedName();
          logger.debug("DiscoveryURLStrategy passing {} as upstream discovery url", discoveryURL);
      }
      discoveryURL;
      ]]>
    </value>
  </constructor-arg>
</bean>

```
## Version 2.2.0 Features
### Version 2.2.0 and automatically select single items
In the case there would be only one item for Discovery to display the selection can be made automatic by setting 
```
idp.discovery.autoSelectSingleItem = true
```
### Version 2.2.0 and ignoring flows
Discovery can be instructed to ignore specific flows. The list of ignored flows can be set by comma limited list that has default value
```
idp.discovery.ignoredFlows = authn/Disco
```


## Version 2.3.0 Features
### Version 2.3.0 and discovery configuration resolvers

**File(s):** _conf/global.xml_
**Format:** Native Spring

#### Overview

The JSON discovery configuration can be read from a file or fetched over HTTP by a _discovery configuration resolver_ instead of being pasted inline into `idp.discovery.authorities`. Resolvers follow the paradigm Shibboleth itself uses for metadata: the source is read once at startup, re-read periodically in the background, and the configuration currently in effect is replaced only by one that has been fetched and parsed successfully. The JSON is the same either way; a file simply holds it without the property name and the line continuations.

Three resolvers are provided, all configured in _conf/global.xml_ under the bean id `shibboleth.authn.Discovery.ConfigurationResolver`. Disco uses the first of these that is configured:

1. the resolver bean, if one by that name exists,
2. the `idp.discovery.authorities` property, holding the JSON inline,
3. the _discovery.properties_ file described above, which is not JSON at all.

Nothing changes for a deployment that does not define a resolver bean.

Every resolver takes the properties below, in addition to those of its own type. The source itself is a constructor argument rather than a property.

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| id | String | | Required. Also set it as a bean property, since the resolver uses it in its log messages and it is the name `reload-service` is given |
| refreshInterval | Duration | PT1H | How often the source is checked. Zero or negative disables background refresh, leaving a forced reload as the only way to pick up changes |
| failedRefreshInterval | Duration | PT5M | How soon a failed cycle is retried |
| backgroundTaskTimer | Bean ID | | Optional first constructor argument, before the source. A `java.util.Timer` to schedule refreshes on. Each resolver creates a private daemon timer if none is given |

#### File-Based

`FilesystemDiscoveryConfigurationResolver` reads the configuration from a local file, re-reading it when its modification time moves. It takes the file as its constructor argument and adds no properties of its own.

**Example** — _conf/global.xml_

```
<bean id="shibboleth.authn.Discovery.ConfigurationResolver"
    class="fi.csc.shibboleth.authn.conf.FilesystemDiscoveryConfigurationResolver"
    c:file="%{idp.home}/conf/authn/discovery-authorities.json"
    p:id="shibboleth.authn.Discovery.ConfigurationResolver"
    p:refreshInterval="PT15M" />
```

#### HTTP-Based

`FileBackedHTTPDiscoveryConfigurationResolver` fetches the configuration over HTTP and keeps a copy of every successfully parsed response in a local backup file. It takes three constructor arguments, the HTTP client, the URL and the backup file path, and adds no properties of its own.

Fetches are conditional, so an unchanged source costs nothing beyond the request.

**Example** — _conf/global.xml_

```
<bean id="discovery.HttpClient" parent="shibboleth.HttpClientFactory"
    p:connectionTimeout="PT10S"
    p:socketTimeout="PT10S" />

<bean id="shibboleth.authn.Discovery.ConfigurationResolver"
    class="fi.csc.shibboleth.authn.conf.FileBackedHTTPDiscoveryConfigurationResolver"
    c:client-ref="discovery.HttpClient"
    c:url="https://config.example.com/discovery-authorities.json"
    c:backupFilePath="%{idp.home}/metadata/discovery-authorities-backup.json"
    p:id="shibboleth.authn.Discovery.ConfigurationResolver"
    p:refreshInterval="PT1H"
    p:failedRefreshInterval="PT5M" />
```

#### Signed JWT

`SignedJWTDiscoveryConfigurationResolver` behaves exactly like the HTTP resolver, and takes the same three constructor arguments, except that it sends `Accept: application/jwt` and refuses anything whose signature does not verify. The bytes kept in the backup file are the token as received, so a configuration recovered from backup is signature checked just like a freshly fetched one.

Supported, but optional except where noted, bean properties are:

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| verifier | Bean ID | | Required. The `SignedJWTVerifier` holding the verification keys |
| configurationClaim | String | | Unset means the whole payload is the configuration object. Set it to nest the configuration under a claim of that name instead |
| acceptHeader | String | application/jwt | The value sent in the Accept header |

The verifier is a bean of its own. Its properties are:

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| credentials | List&lt;Credential&gt; | | Required. The public keys a signature may be verified against. Every credential whose key type suits the algorithm is tried in turn |
| signatureAlgorithms | List&lt;String&gt; | RS256, RS384, RS512, ES256, ES384, ES512 | Narrow it to what the signer actually uses. Only these asymmetric algorithms are supported; `none` and the HMAC algorithms are always refused, and the token's own `alg` header can never select something outside the list |
| requireExpiration | Boolean | false | When true a token without an `exp` claim is refused. `exp` and `nbf` are always honoured when present |
| clockSkew | Duration | PT30S | Tolerance applied to `exp` and `nbf` |

**Example** — _conf/global.xml_

```
<bean id="discovery.HttpClient" parent="shibboleth.HttpClientFactory"
    p:connectionTimeout="PT10S"
    p:socketTimeout="PT10S" />

<bean id="discovery.SigningKey" parent="shibboleth.BasicX509CredentialFactoryBean"
    p:certificateResource="%{idp.home}/credentials/discovery-signing.crt" />

<bean id="discovery.JWTVerifier" class="fi.csc.shibboleth.authn.conf.SignedJWTVerifier"
    p:signatureAlgorithms="#{{'RS256'}}">
    <property name="credentials">
        <list>
            <ref bean="discovery.SigningKey" />
        </list>
    </property>
</bean>

<bean id="shibboleth.authn.Discovery.ConfigurationResolver"
    class="fi.csc.shibboleth.authn.conf.SignedJWTDiscoveryConfigurationResolver"
    c:client-ref="discovery.HttpClient"
    c:url="https://config.example.com/discovery-authorities.jwt"
    c:backupFilePath="%{idp.home}/metadata/discovery-authorities-backup.jwt"
    p:id="shibboleth.authn.Discovery.ConfigurationResolver"
    p:refreshInterval="PT1H"
    p:verifier-ref="discovery.JWTVerifier" />
```

##### Supplying the verification key

The verification keys go on the verifier as a list of credentials. Any credential the IdP can build will do, and the three ways below can be mixed freely in one list.

###### From a JWK

Requires the OP plugin, whose own credential bean this is.

```
<bean id="discovery.SigningKey" parent="shibboleth.JWKCredential"
    p:resource="%{idp.home}/credentials/discovery-signing.jwk" />
```

###### From an X.509 certificate

Only the public key inside it is used; the validity dates and the issuer are not checked.

```
<bean id="discovery.SigningKey" parent="shibboleth.BasicX509CredentialFactoryBean"
    p:certificateResource="%{idp.home}/credentials/discovery-signing.crt" />
```

###### From a PEM public key

```
<bean id="discovery.SigningKey" parent="shibboleth.BasicResourceCredentialFactoryBean"
    p:publicKeyInfo="%{idp.home}/credentials/discovery-signing.pub" />
```

###### Putting them on the verifier

The `credentials` list takes as many as you like, of whatever mixture of the above. Every key in it is tried until one verifies the signature, which is what lets an old and a new signing key be trusted at the same time while a rollover propagates.

```
<bean id="discovery.OldSigningKey" parent="shibboleth.BasicX509CredentialFactoryBean"
    p:certificateResource="%{idp.home}/credentials/discovery-signing-old.crt" />

<bean id="discovery.NewSigningKey" parent="shibboleth.BasicResourceCredentialFactoryBean"
    p:publicKeyInfo="%{idp.home}/credentials/discovery-signing-new.pub" />

<bean id="discovery.JWTVerifier" class="fi.csc.shibboleth.authn.conf.SignedJWTVerifier">
    <property name="credentials">
        <list>
            <ref bean="discovery.OldSigningKey" />
            <ref bean="discovery.NewSigningKey" />
        </list>
    </property>
</bean>
```

#### Updating the scripts

The scripts shown under [Version 2.1.0 and MFA configuration](#version-210-and-mfa-configuration) take the JSON as a string and parse it on every invocation. With a resolver they take the resolver instead and ask it for the configuration in effect, which is already parsed and kept up to date in the background. Nothing else in those scripts changes.

Drop the string bean

```
<bean id="discovery.authorities" class="java.lang.String" c:_0="%{idp.discovery.authorities}" />
```

and point `p:customObject-ref` at the resolver

```
<bean id="selectFirstFactor" parent="shibboleth.ContextFunctions.Scripted" factory-method="inlineScript"
    p:customObject-ref="shibboleth.authn.Discovery.ConfigurationResolver">
```

then replace the two lines that parse the string

```
DiscoveryConfiguration = Java.type("fi.csc.shibboleth.authn.conf.DiscoveryConfiguration");
var discoveryConfiguration = DiscoveryConfiguration.parse(custom);
```

with one that asks the resolver

```
var discoveryConfiguration = custom.resolve();
```

The same two edits apply to `csc.discoveryFunction`. `discoveryConfiguration` is the same object either way, so `getFlowMap()` and everything after it stays as it is.

#### Forcing a reload

To re-read the source without waiting for the next cycle and without restarting, pass the resolver's bean id to

```
bin/reload-service.sh -id shibboleth.authn.Discovery.ConfigurationResolver
```

Access is governed by the `idp.service.reload` access control policy.

A forced reload runs the same cycle the background timer runs, so a failure leaves the running configuration alone. Setting `refreshInterval` to zero and reloading by hand is a legitimate combination if you would rather no polling happened at all.

#### What the publisher has to produce

This is the contract a third party needs in order to publish a configuration this resolver will accept. Nothing beyond it is required, and nothing beyond it is inspected.

**The token.** A JWS in compact serialization: three base64url segments joined by dots, no line breaks. Leading and trailing whitespace is trimmed, so a trailing newline in the file is fine.

**The header.**

*   `alg` is required and must be one of `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`. `none`, the HMAC algorithms and the PSS algorithms are refused, and the header cannot select anything the deployer has not allowed.
*   `crit` must not be present. Any `crit` at all is refused, including an empty one.
*   `typ`, `kid`, `x5c` and everything else are ignored. Include them if it suits you. In particular a certificate in `x5c` is **not** used to establish trust, because a certificate carried inside the token being verified proves nothing on its own; trust comes only from the key the deployer configures out of band.

**The payload.** The discovery configuration object itself, byte for byte what the JSON file would hold. Nothing else may be in it: with the default settings every top-level name is read as a relying party id, so an `iss` or an `exp` alongside the configuration is an error rather than a no-op.

```
{
  "default": { "authn/MFA": [ { "acr": "https://example.com/LoginMethodOne" } ] },
  "https://sp.example.com/shibboleth": { "authn/MFA": [ { "acr": "https://example.com/LoginLocal" } ] }
}
```

If you want the usual JWT claims, nest the configuration under a claim instead and tell the deployer to set `p:configurationClaim` to its name.

```
{
  "iss": "https://config.example.com",
  "iat": 1757462400,
  "exp": 1757548800,
  "discovery": { "default": { "authn/MFA": [ { "acr": "https://example.com/LoginMethodOne" } ] } }
}
```

**Claims that are checked.** Only `exp` and `nbf`, and only when present, each as a NumericDate in seconds. A token is refused once `exp` is more than the configured clock skew in the past, or while `nbf` is more than the skew in the future. `iss`, `aud`, `sub`, `iat` and `jti` are **not** validated by this module, so do not rely on them for access control. There is no replay detection and no certificate chain building; the deployer's configured public key is the whole of the trust decision.

**Rolling the signing key over.** Publish the new key alongside the old one first and let the deployers pick it up, then start signing with the new key, then withdraw the old one. Every configured key is tried in turn, so both verify during the overlap.

#### Reference

Beans defined by this module, for use in _conf/global.xml_, are:

| Name | Type | Description |
| --- | --- | --- |
| shibboleth.authn.Discovery.ConfigurationResolver | DiscoveryConfigurationResolver | The bean id Disco looks for. Define it as one of the three resolver classes below |
| fi.csc.shibboleth.authn.conf.FilesystemDiscoveryConfigurationResolver | class | Reads the configuration from a local file |
| fi.csc.shibboleth.authn.conf.FileBackedHTTPDiscoveryConfigurationResolver | class | Fetches the configuration over HTTP, with a local backup |
| fi.csc.shibboleth.authn.conf.SignedJWTDiscoveryConfigurationResolver | class | Fetches the configuration as a signed JWT over HTTP, with a local backup |
| fi.csc.shibboleth.authn.conf.SignedJWTVerifier | class | Holds the verification keys and the algorithms accepted for a signed JWT |

Properties related to Disco, all of them older than this release, are:

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| idp.discovery.authorities | String | | The JSON inline. Used only when no resolver bean is defined |
| idp.discovery.authority.properties | String | | Path of the legacy _discovery.properties_ file. Used only when neither of the above is configured |
| idp.discovery.autoSelectSingleItem | Boolean | false | Bypass the Disco view when there is only one item to select |
| idp.discovery.ignoredFlows | String | authn/Disco | Comma delimited list of flows to keep out of the Disco view |
| idp.discovery.storeSelection | Boolean | false | Remember the user's selection in the session |


# More helpers
Following library offers some helpers we use in our proxies. New keys to upstream acr translation, managing multiple upstream OIDC credentials etc.

https://github.com/CSCfi/shibboleth-idp-plugin-csc-library
