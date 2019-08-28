# Trafic Management

## Quota [Doc](https://docs.apigee.com/api-platform/reference/policies/quota-policy#elements)

configure the number of request messages that an API proxy allows over a period of time

```xml
<Quota name="QuotaPolicy">
  <Interval>5</Interval>
  <TimeUnit>hour</TimeUnit>
  <Allow count="99"/>
</Quota>
```

## SpikeArrest [Doc](https://docs.apigee.com/api-platform/reference/policies/spike-arrest-policy#elements)

protects against traffic spikes with the <Rate> element. This element throttles the number of requests processed by an API proxy and sent to a backend, protecting against performance lags and downtime.

```xml
<SpikeArrest name="SpikeArrest">
<Rate>12pm</Rate>
<Identifier ref="client_id" />
<MessageWeight ref="request.header.weight" />
</SpikeArrest>
```

## ResponseCache [Doc](https://docs.apigee.com/api-platform/reference/policies/response-cache-policy#element_reference)

Caches data from a backend resource, reducing the number of requests to the resource

```xml
<ResponseCache name="ResponseCache">
    <CacheKey>
        <KeyFragment ref="request.queryparam.w" />
    </CacheKey>
    <ExpirySettings>
        <TimeoutInSec>600</TimeoutInSec>
    </ExpirySettings>
</ResponseCache>
```

## LookupCache [Doc](https://docs.apigee.com/api-platform/reference/policies/lookup-cache-policy#element_reference)

Configures how cached values should be retrieved at runtime. It is used in conjunction with the Populate Cache policy (for writing entries) and the Invalidate Cache policy (for invalidating entries).

```xml
<LookupCache async="false" continueOnError="false" enabled="true" name="Lookup-Cache-1">
    <DisplayName>Lookup Cache 1</DisplayName>
    <Properties/>
    <CacheKey>
        <Prefix/>
        <KeyFragment ref=""/>
    </CacheKey>
    <!-- Omit this element if you're using the included shared cache. -->
    <CacheResource/>
    <CacheLookupTimeoutInSeconds/>
    <Scope>Exclusive</Scope>
    <AssignTo>flowVar</AssignTo>
</LookupCache>
```

## Populate Cache [Doc](https://docs.apigee.com/api-platform/reference/policies/populate-cache-policy#element_reference)

Configures how cached values should be written at runtime. It's used in conjunction with the Lookup Cache policy (for reading cache entries) and the Invalidate Cache policy (for invalidating entries).

```xml
<PopulateCache async="false" continueOnError="false" enabled="true" name="Populate-Cache-1">
    <DisplayName>Populate Cache 1</DisplayName>
    <Properties/>
    <CacheKey>
        <Prefix/>
        <KeyFragment ref=""/>
    </CacheKey>
    <!-- Omit this element if you're using the included shared cache. -->
    <CacheResource/>
    <Scope>Exclusive</Scope>
    <ExpirySettings>
        <TimeoutInSec>300</TimeoutInSec>
    </ExpirySettings>
    <Source>flowVar</Source>
</PopulateCache>
```

## Invalidate Cache [Doc](https://docs.apigee.com/api-platform/reference/policies/invalidate-cache-policy#element_reference)

Configures how the cached values should be purged from the cache.

```xml
<InvalidateCache async="false" continueOnError="false" enabled="true" name="policy-name">
    <DisplayName>Policy Name</DisplayName>
    <CacheKey>
        <Prefix>prefix_string</Prefix>
        <KeyFragment ref="variable_reference"/>
        <KeyFragment>fragment_string</KeyFragment>
    </CacheKey>
    <!-- Omit this element if you're using the included shared cache. -->
    <CacheResource>cache_to_use</CacheResource>
    <Scope>scope_enumeration</Scope>
    <CacheContext>
        <APIProxyName>application_that_added_the_entry</APIProxyName>
        <ProxyName>proxy_for_which_data_was_cached</ProxyName>
        <TargetName>endpoint_for_which_data_was_cached</TargetName>
    </CacheContext>
    <PurgeChildEntries>true_to_purge_all_child_entries</PurgeChildEntries>
</InvalidateCache>
```

## Reset Quota [Doc](https://docs.apigee.com/api-platform/reference/policies/reset-quota-policy#elementreference)

Use to dynamically modify the remaining number of requests allowed by the target Quota policy. You typically use this policy to decrease the current quota count of the target Quota policy rather than waiting for the quota count to reset.

```xml
<ResetQuota name="resetQuota">
   <Quota name="MyQuotaPolicy">
      <Identifier name="_default">
         <Allow>100</Allow>
      </Identifier>
   </Quota>
</ResetQuota>
```

# Mediation

## XMLtoJSON [Doc](https://docs.apigee.com/api-platform/reference/policies/xml-json-policy#elements)

This policy converts messages from the extensible markup language (XML) format to JavaScript Object Notation (JSON), giving you several options for controlling how messages are converted

```xml
<XMLToJSON name="ConvertToJSON">
  <Options>
  </Options>
  <OutputVariable>response</OutputVariable>
  <Source>response</Source>
</XMLToJSON>
```

## JSONtoXML [Doc](https://docs.apigee.com/api-platform/reference/policies/json-xml-policy#elements)

This policy converts messages from the JavaScript Object Notation (JSON) format to extensible markup language (XML), giving you several options for controlling how messages are converted.

```xml
<JSONToXML name="jsontoxml">
    <Source>request</Source>
    <OutputVariable>request</OutputVariable>
</JSONToXML>
```

## RaiseFault [Doc](https://docs.apigee.com/api-platform/reference/policies/raise-fault-policy#elementreference)

Generates a custom message in response to an error condition. Use Raise Fault to define a fault response that is returned to the requesting app when a specific condition arises.

```xml
<RaiseFault name="404">
 <IgnoreUnresolvedVariables>true</IgnoreUnresolvedVariables>
 <FaultResponse>
   <Set>
     <StatusCode>404</StatusCode>
     <ReasonPhrase>The resource requested was not found</ReasonPhrase>
   </Set>
 </FaultResponse>
</RaiseFault>
```

## XSLTransform [Doc](https://docs.apigee.com/api-platform/reference/policies/xsl-transform-policy#elements)

The XSL Transform policy applies custom Extensible stylesheet language transformations (XSLT) to XML messages, letting you transform them from XML to another format, such as XML, HTML, or plain text. The policy is often used to integrate applications that support XML, but that require different XML-formats for the same data.

```xml
<XSL name="TransformXML">
  <ResourceURL>xsl://my_transform.xsl</ResourceURL>
  <Source>request</Source>
</XSL>
```

## SOAPMessageValidation [Doc](https://docs.apigee.com/api-platform/reference/policies/message-validation-policy)

The SOAPMessageValidation policy does the following:

* Validates any XML message against their XSD schemas
* Validates SOAP messages against a WSDL definition
* Determines well-formedness of JSON and XML messages

While the name of this policy in the UI is "SOAP Message Validation", the policy validates more than just SOAP messages. This section refers to the policy as the "Message Validation policy".

```xml
<MessageValidation continueOnError="false"
    enabled="true" name="validateXMLRequest">
  <DisplayName>My XML Validator</DisplayName>
  <Properties/>
  <Source>request</Source>
  <ResourceURL>xsd://note-schema.xsd</ResourceURL>
</MessageValidation>
```

## AssignMessage [Doc](https://docs.apigee.com/api-platform/reference/policies/assign-message-policy)

The Assign Message policy changes or creates new request and response messages during the API proxy Flow. The policy lets you perform the following actions on those messages: Add, Copy, Remove and Set.

```xml
<AssignMessage continueOnError="false" enabled="true" name="add-headers-1">
  <Add>
    <Headers>
      <Header name="user-agent">{request.user.agent}</Header>
    </Headers>
  </Add>
  <AssignTo createNew="false" transport="http" type="request"/>
</AssignMessage>
```

## ExtractVariables [Doc](https://docs.apigee.com/api-platform/reference/policies/extract-variables-policy#elementreference)

The Extract Variables policy extracts content from a request or response and sets the value of a variable to that content. You can extract any part of the message, including headers, URI paths, JSON/XML payloads, form parameters, and query parameters. The policy works by applying a text pattern to the message content and, upon finding a match, sets a variable with the specified message content.

```xml
<ExtractVariables name="ExtractVariables-3">
   <Source>response</Source>
   <JSONPayload>
      <Variable name="latitude" type="float">
         <JSONPath>$.results[0].geometry.location.lat</JSONPath>
      </Variable>
      <Variable name="longitude" type="float">
         <JSONPath>$.results[0].geometry.location.lng</JSONPath>
      </Variable>
   </JSONPayload>
   <VariablePrefix>geocoderesponse</VariablePrefix>
</ExtractVariables>
```

## AccessEntity [Doc](https://docs.apigee.com/api-platform/reference/policies/access-entity-policy#elements)

Retrieves entity profiles you specify from the Apigee Edge data store. The policy places the profile in a variable whose name follows the format AccessEntity.{policy_name}. You can use AccessEntity to access profiles for the following entities: App, API product, Company, Company developer, Consumer key, Developer.


```xml
<AccessEntity name="GetDeveloperProfile">
  <!-- This is the type entity whose profile we need to pull from the Edge datastore. -->
  <EntityType  value="developer"/>
  <!-- We tell the policy to use the API key (presented as query parameter) to identify the developer. -->
  <EntityIdentifier ref="request.queryparam.apikey" type="consumerkey"/> 
</AccessEntity>

<ExtractVariables name="SetDeveloperProfile">
  <!-- The source element points to the variable populated by AccessEntity policy. 
  The format is <policy-type>.<policy-name>.
  In this case, the variable contains the whole developer profile. -->
  <Source>AccessEntity.GetDeveloperProfile</Source> 
  <VariablePrefix>developer</VariablePrefix>
  <XMLPayload>
    <Variable name="email" type="string"> 
        <!-- You parse elements from the developer profile using XPath. -->
      <XPath>/Developer/Email</XPath>
    </Variable>
  </XMLPayload>
</ExtractVariables>
```

## KeyValueMapOperations [Doc](https://docs.apigee.com/api-platform/reference/policies/key-value-map-operations-policy#elementreference)

Provides policy-based access to a Key Value Map (KVM) store available in Apigee Edge. Key/value pairs can be stored, retrieved, and deleted from named existing maps by configuring KeyValueMapOperations policies that specify PUT, GET, or DELETE operations.

### Put
```xml
<KeyValueMapOperations async="false" continueOnError="false" enabled="true" name="CreateFooKVM" mapIdentifier="FooKVM">
  <DisplayName>CreateFooKVM</DisplayName>
  <ExpiryTimeInSecs>86400</ExpiryTimeInSecs>
  <Scope>environment</Scope>
  <Put>
    <Key>
      <Parameter>FooKey_1</Parameter>
    </Key>
    <Value>foo</Value>
    <Value>bar</Value>
  </Put>
</KeyValueMapOperations>
```
### Get
```xml
<KeyValueMapOperations mapIdentifier="FooKVM" async="false" continueOnError="false" enabled="true" name="GetKVM">
  <DisplayName>GetKVM</DisplayName>
  <ExpiryTimeInSecs>86400</ExpiryTimeInSecs>
  <Scope>environment</Scope>
  <Get assignTo="foo_variable" index="2">
    <Key>
      <Parameter>FooKey_1</Parameter>
    </Key>
  </Get>
</KeyValueMapOperations>
```

# Security

## XMLThreatProtection [Doc](https://docs.apigee.com/api-platform/reference/policies/xml-threat-protection-policy#elementreference)

Address XML vulnerabilities and minimize attacks on your API. Optionally, detect XML payload attacks based on configured limits. Screen against XML threats using the following approaches:
* Validate messages against an XML schema (.xsd)
* Evaluate message content for specific blacklisted keywords or patterns
* Detect corrupt or malformed messages before those messages are parsed

	Note: This policy executes only if the Content-Type of the request or response header is set to application/xml.


```xml
<XMLThreatProtection async="false" continueOnError="false" enabled="true" name="XML-Threat-Protection-1">
   <DisplayName>XML Threat Protection 1</DisplayName>
   <ValueLimits>
      <Text>15</Text>
      <Attribute>10</Attribute>
      <NamespaceURI>10</NamespaceURI>
      <Comment>10</Comment>
      <ProcessingInstructionData>10</ProcessingInstructionData>
   </ValueLimits> 
</XMLThreatProtection>
```

## JSONThreatProtection [Doc](https://docs.apigee.com/api-platform/reference/policies/json-threat-protection-policy#elementreference)

Minimizes the risk posed by content-level attacks by enabling you to specify limits on various JSON structures, such as arrays and strings.

	Note: This policy executes only if the Content-Type of the request or response header is set to application/json.

```xml
<JSONThreatProtection async="false" continueOnError="false" enabled="true" name="JSON-Threat-Protection-1">
   <DisplayName>JSON Threat Protection 1</DisplayName>
   <ArrayElementCount>20</ArrayElementCount>
   <ContainerDepth>10</ContainerDepth>
   <ObjectEntryCount>15</ObjectEntryCount>
   <ObjectEntryNameLength>50</ObjectEntryNameLength>
   <Source>request</Source>
   <StringValueLength>500</StringValueLength>
</JSONThreatProtection>
```

## RegularExpressionProtection [Doc](https://docs.apigee.com/api-platform/reference/policies/regular-expression-protection#elementreference)

Extracts information from a message (for example, URI Path, Query Param, Header, Form Param, Variable, XML Payload, or JSON Payload) and evaluates that content against predefined regular expressions. If any specified regular expressions evaluate to true, the message is considered a threat and is rejected.

```xml
<RegularExpressionProtection async="false" continueOnError="false" enabled="true" name="Regular-Expression-Protection-1">
    <DisplayName>Regular Expression Protection 1</DisplayName>
    <Source>response</Source>
 	<FormParam name="a-form-param">
		<Pattern>[\s]*(?i)((delete)|(exec)|(drop\s*table)|(insert)|(shutdown)|(update)|(\bor\b))</Pattern>
	</FormParam>
</RegularExpressionProtection>
```

## OAuthV2 [Doc](https://docs.apigee.com/api-platform/reference/policies/oauthv2-policy#elementreference)


OAuthV2 is a multi-faceted policy for performing OAuth 2.0 grant type operations. This is the primary policy used to configure OAuth 2.0 endpoints on Apigee Edge.

### Policie
```xml
<OAuthV2 async="false" continueOnError="false" enabled="true" name="GenerateAccessToken">
    <DisplayName>GenerateAccessToken</DisplayName>
    <ExternalAuthorization>false</ExternalAuthorization>
    <Operation>GenerateAccessToken</Operation>

    <SupportedGrantTypes>
      <GrantType>password</GrantType>
    </SupportedGrantTypes>

    <GenerateResponse enabled="true"/>
</OAuthV2>
<OAuthV2 async="false" continueOnError="false" enabled="true" name="GenerateAuthorizationCode">
    <DisplayName>GenerateAuthCode</DisplayName>
    <FaultRules/>
    <Properties/>
    <Attributes/>
    <ExternalAuthorization>false</ExternalAuthorization>
    <Operation>GenerateAuthorizationCode</Operation>
    <SupportedGrantTypes/>
    <GenerateResponse enabled="false"/>
    <Tokens/>
</OAuthV2>
```

### Proxy

```xml
<ProxyEndpoint name="default">
    <Description/>
    <PreFlow name="PreFlow">
        <Request/>
        <Response/>
    </PreFlow>
    <Flows>
        <Flow name="generate-access-token">
            <Description/>
            <Request>
                <Step>
                    <FaultRules/>
                    <Name>GenerateAccessToken</Name>
                </Step>
            </Request>
            <Response/>
            <Condition>(proxy.pathsuffix MatchesPath &quot;/token&quot;) and (request.verb = &quot;POST&quot;)</Condition>
        </Flow>

        <Flow name="generate-auth-code">
            <Description/>
            <Request>
                <Step>
                    <FaultRules/>
                    <Name>GenerateAuthorizationCode</Name>
                </Step>
            </Request>
            <Response/>
            <Condition>(proxy.pathsuffix MatchesPath &quot;/authorize&quot;) and (request.verb = &quot;POST&quot;)</Condition>
        </Flow>
    </Flows>
    <PostFlow name="PostFlow">
        <Request/>
        <Response/>
    </PostFlow>
    <HTTPProxyConnection>
        <BasePath>/oauth-doc</BasePath>
        <VirtualHost>default</VirtualHost>
        <VirtualHost>secure</VirtualHost>
    </HTTPProxyConnection>
    <RouteRule name="noroute"/>
</ProxyEndpoint>
```

## GetOAuthV2Info [Doc](https://docs.apigee.com/api-platform/reference/policies/get-oauth-v2-info-policy)

Gets attributes of access tokens, refresh tokens, authorization codes, and client app attributes and populates variables with the values of those attributes. Whenever token validation occurs, variables are automatically populated with the values of token attributes

```xml
<GetOAuthV2Info name="MyTokenAttrsPolicy">
  <AccessToken ref="request.queryparam.access_token"></AccessToken>
</GetOAuthV2Info>
```

```js
var scope = context.getVariable('oauthv2accesstoken.MyTokenAttrsPolicy.scope');
```

## OAauthV1a [Doc](https://docs.apigee.com/api-platform/reference/policies/oauth-10-policy)

OAuth 1.0a defines a standard protocol that enables app users to authorize apps to consume APIs on their behalf, without requiring app users to disclose their passwords to the app in the process.

```xml
<OAuthV1 name="OAuthV1-GenerateAccessToken-1">
  <Operation>GenerateAccessToken</Operation>
  <URL ref="flow.variable">{value}</URL>
  <GenerateResponse enabled="true">
    <Format>FORM_PARAM | XML</Format>
  </GenerateResponse>
  <GenerateErrorResponse enabled="true">
    <Format>FORM_PARAM | XML</Format>
    <Realm>http://oauth.apigee.com/oauth/1/</Realm>
  </GenerateErrorResponse>
</OAuthV1>
```


## Verify API key 

The Verify API Key policy lets you enforce verification of API keys at runtime, letting only apps with approved API keys access your APIs.

```xml
<VerifyAPIKey name="APIKeyVerifier">
    <APIKey ref="request.header.x-apikey" />
</VerifyAPIKey>

<FaultRule name="FailedToResolveAPIKey">
    <Step>
        <Name>AM-FailedToResolveAPIKey</Name>
    </Step>
    <Condition>(fault.name Matches "FailedToResolveAPIKey") </Condition>
</FaultRule>
```

## Access Control [Doc](https://docs.apigee.com/api-platform/reference/policies/access-control-policy#elements)

lets you allow or deny access to your APIs by specific IP addresses.

```xml
<AccessControl name="ACL">
  <IPRules noRuleMatchAction = "ALLOW">
    <MatchRule action = "DENY">
      <SourceAddress mask="32">198.51.100.1</SourceAddress>
    </MatchRule>
  </IPRules>
</AccessControl>
```



## Validate SAML Assertion [Doc](https://docs.apigee.com/api-platform/reference/policies/saml-assertion-policy)

The SAML policy type enables API proxies to validate SAML assertions that are attached to inbound SOAP requests. The SAML policy validates incoming messages that contain a digitally-signed SAML assertion, rejects them if they are invalid, and sets variables that allow additional policies, or the backend services itself, to further validate the information in the assertion.
```xml
<ValidateSAMLAssertion name="SAML" ignoreContentType="false">
  <Source name="request">
    <Namespaces>
      <Namespace prefix='soap'>http://schemas.xmlsoap.org/soap/envelope/</Namespace>
      <Namespace prefix='wsse'>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd</Namespace>
      <Namespace prefix='saml'>urn:oasis:names:tc:SAML:2.0:assertion</Namespace>
    </Namespaces>
    <XPath>/soap:Envelope/soap:Header/wsse:Security/saml:Assertion</XPath>
  </Source>
  <TrustStore>TrustStoreName</TrustStore>
  <RemoveAssertion>false</RemoveAssertion>
</ValidateSAMLAssertion>
```

## Generate SAML Assertion [Doc](https://docs.apigee.com/api-platform/reference/policies/saml-assertion-policy)

The SAML policy type enables API proxies to attach SAML assertions to outbound XML requests. Those assertions are then available to enable backend services to apply further security processing for authentication and authorization.

```xml
<GenerateSAMLAssertion name="SAML" ignoreContentType="false">
  <CanonicalizationAlgorithm />
  <Issuer ref="reference">Issuer name</Issuer>
  <KeyStore>
    <Name ref="reference">keystorename</Name>
    <Alias ref="reference">alias</Alias>
  </KeyStore>
  <OutputVariable>
    <FlowVariable>assertion.content</FlowVariable>
    <Message name="request">
      <Namespaces>
        <Namespace prefix="test">http://www.example.com/test</Namespace>
      </Namespaces>
      <XPath>/envelope/header</XPath>
    </Message>
  </OutputVariable>
  <SignatureAlgorithm />
  <Subject ref="reference">Subject name</Subject>
  <Template ignoreUnresolvedVariables="false">
    <!-- A lot of XML goes here, in CDATA, with {} around
         each variable -->
  </Template>
</GenerateSAMLAssertion>
```
