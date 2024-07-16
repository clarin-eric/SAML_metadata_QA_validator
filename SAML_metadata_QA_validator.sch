<?xml version="1.0" encoding="UTF-8"?>
<sch:schema
    xmlns:sch="http://purl.oclc.org/dsdl/schematron"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:fn="http://www.w3.org/2005/xpath-functions"
    queryBinding="xslt2">
    <sch:ns
        uri="http://www.w3.org/2000/09/xmldsig#"
        prefix="ds"/>
    <sch:ns
        uri="http://www.w3.org/2005/xpath-functions"
        prefix="fn"/>
    <sch:ns
        uri="urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol"
        prefix="idpdisc"/>
    <sch:ns
        uri="urn:oasis:names:tc:SAML:profiles:SSO:request-init"
        prefix="init"/>
    <sch:ns
        uri="about:SAML_metadata_QA_validator"
        prefix="local"/>
    <sch:ns
        uri="urn:oasis:names:tc:SAML:2.0:metadata"
        prefix="md"/>
    <sch:ns
        uri="urn:oasis:names:tc:SAML:metadata:attribute"
        prefix="mdattr"/>
    <sch:ns
        uri="urn:oasis:names:tc:SAML:metadata:rpi"
        prefix="mdrpi"/>
    <sch:ns
        uri="urn:oasis:names:tc:SAML:metadata:ui"
        prefix="mdui"/>
    <sch:ns
        uri="urn:oasis:names:tc:SAML:2.0:assertion"
        prefix="saml"/>
    <sch:ns
        uri="http://www.w3.org/2001/XMLSchema"
        prefix="xs"/>
    <xsl:function
        name="local:is_mailto_URI"
        as="xs:boolean">
        <xsl:param
            name="mailto_URI"
            as="xs:anyURI"/>
        <xsl:sequence
            select="fn:matches($mailto_URI cast as xs:string, 'mailto:[^@]+@[^@]+')"/>
    </xsl:function>
    <xsl:function
        name="local:has_Entity_Category"
        as="xs:boolean">
        <xsl:param
            name="attribute_value"
            as="xs:anyURI"/>
        <xsl:param
            name="context"
            as="element()"/>
        <xsl:sequence
            select="fn:exists($context/md:Extensions/mdattr:EntityAttributes/saml:Attribute[@Name='http://macedir.org/entity-category' and @NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri']/saml:AttributeValue[text()=$attribute_value cast as xs:string])"/>
    </xsl:function>
    <xsl:function
        name="local:check_mdui_elements"
        as="xs:anyAtomicType+">
        <xsl:param
            name="language_code"
            as="xs:string"/>
        <xsl:param
            name="context"
            as="element()"/>
        <xsl:variable
            name="description"
            select="$context/md:Extensions/mdui:UIInfo/mdui:Description[@xml:lang=$language_code]/text()"
            as="xs:string?"/>
        <xsl:variable
            name="display_name"
            select="$context/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang=$language_code]/text()"
            as="xs:string?"/>
        <xsl:variable
            name="description_length"
            select="fn:string-length($description)"
            as="xs:integer"/>
        <xsl:variable
            name="display_name_length"
            select="fn:string-length($display_name)"
            as="xs:integer"/>
        <xsl:sequence
            select="(not(empty($description)) and not(empty($display_name)) and $display_name_length >= 5 and $display_name_length &lt;= 40 and $description_length >= 20 and $description_length &lt;= 100, $display_name, $display_name_length, $description, $description_length)"/>
    </xsl:function>
    <xsl:function
        name="local:is_https_URL"
        as="xs:boolean">
        <xsl:param
            name="URL"
            as="xs:anyURI"/>
        <xsl:sequence
            select="fn:starts-with($URL, 'https://')"/>
    </xsl:function>
    <xsl:function
        name="local:is_http_URL"
        as="xs:boolean">
        <xsl:param
            name="URL"
            as="xs:anyURI"/>
        <xsl:sequence
            select="fn:starts-with($URL, 'http://')"/>
    </xsl:function>
    <xsl:function
        name="local:is_HTTP_URL"
        as="xs:boolean">
        <xsl:param
            name="URL"
            as="xs:anyURI"/>
        <xsl:sequence
            select="local:is_http_URL($URL) or local:is_https_URL($URL)"/>
    </xsl:function>
    <sch:title>SAML metadata QA validator</sch:title>
    <sch:pattern>
        <sch:title>GÉANT Data Protection Code of Conduct Entity Category</sch:title>
        <sch:rule
            context="md:EntityDescriptor[md:SPSSODescriptor]">
            <sch:let
                name="entityID"
                value="@entityID"/>
            <sch:let
                name="DP_CoCo_EC"
                value="'http://www.geant.net/uri/dataprotection-code-of-conduct/v1' cast as xs:anyURI"/>
            <sch:assert
                test="local:has_Entity_Category($DP_CoCo_EC, .)">
                <sch:value-of
                    select="$entityID"/>
                There is no node ‘md:Extensions/mdattr:EntityAttributes/saml:Attribute[@Name='http://macedir.org/entity-category' and @NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri']/saml:AttributeValue/text()’, or no such node has the value 'http://www.geant.net/uri/dataprotection-code-of-conduct/v1'.
                <sch:emph>Completely a requirement for the GÉANT Data Protection Code of Conduct Entity Category. Completely a guideline for the CLARIN Service Provider Federation. </sch:emph>
            </sch:assert>
        </sch:rule>
    </sch:pattern>
    <sch:pattern>
        <sch:title>REFEDS Research and Scholarship Entity Category</sch:title>
        <sch:rule
            context="md:EntityDescriptor[md:SPSSODescriptor]">
            <sch:let
                name="entityID"
                value="@entityID"/>
            <sch:let
                name="REFEDS_EC"
                value="'http://refeds.org/category/research-and-scholarship' cast as xs:anyURI"/>
            <sch:assert
                test="local:has_Entity_Category($REFEDS_EC, .)">
                <sch:value-of
                    select="$entityID"/>
                There is no node ‘md:Extensions/mdattr:EntityAttributes/saml:Attribute[@Name='http://macedir.org/entity-category' and @NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri']/saml:AttributeValue/text()’, or no such node has the value 'http://refeds.org/category/research-and-scholarship'.
                <sch:emph>Completely a requirement for the GÉANT Data Protection Code of Conduct Entity Category. Completely a guideline for the CLARIN Service Provider Federation. </sch:emph>
            </sch:assert>
        </sch:rule>
    </sch:pattern>
    <sch:pattern>
        <sch:title>Logo</sch:title>
        <sch:rule
            context="md:EntityDescriptor/md:SPSSODescriptor">
            <sch:let
                name="entityID"
                value="../@entityID"/>
            <sch:let
                name="Logo_nodes"
                value="for $URL in md:Extensions/mdui:UIInfo/mdui:Logo/text() return $URL cast as xs:anyURI"/>
            <sch:assert
                test="exists($Logo_nodes) and (every $URL in $Logo_nodes satisfies local:is_https_URL($URL))">
                <sch:value-of
                    select="$entityID"/>
                Missing element(s) ‘md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Logo’ or any of their values is not a valid URL with https scheme. 
                <sch:emph>Completely a requirement for eduID.cz registration. Completely a requirement for SURFconext registration. Completely a guideline for the CLARIN Service Provider Federation. </sch:emph>
            </sch:assert>
            <!-- TODO: Perform logo dimensions validation. -->
        </sch:rule>
    </sch:pattern>
    <sch:pattern
        abstract="true"
        id="mdui_text">
        <sch:title>Metadata Extensions for Login and Discovery User Interface: texts</sch:title>
        <sch:rule
            context="md:EntityDescriptor/md:SPSSODescriptor">
            <sch:let
                name="entityID"
                value="../@entityID"/>
            <sch:let
                name="result"
                value="local:check_mdui_elements($language_code, .)"/>
            <sch:assert
                test="$result[1]">
                <sch:value-of
                    select="$entityID"/>
                Invalid or missing ‘mdui:Description’ and/or ‘mdui:DisplayName’ under ‘md:SPSSODescriptor/md:Extensions/mdui:UIInfo’ in language with code ‘<sch:value-of
                    select="$language_code"/>’, or display name (= ‘<sch:value-of
                    select="$result[2]"/>’) length (= <sch:value-of
                    select="$result[3]"/>) &lt; 5 or &gt; 33, or description (= ‘<sch:value-of
                    select="$result[4]"/>’) length (= <sch:value-of
                    select="$result[5]"/>) &lt; 20 or &gt; 100.
                <sch:emph>Partially a requirement for DFN-AAI registration. Partially a requirement for the GÉANT Data Protection Code of Conduct Entity Category. Completely a guideline for the CLARIN Service Provider Federation. </sch:emph>
            </sch:assert>
        </sch:rule>
    </sch:pattern>
    <sch:pattern>
        <sch:title>Metadata Extensions for Login and Discovery User Interface: URLs</sch:title>
        <sch:rule
            context="md:EntityDescriptor/md:SPSSODescriptor">
            <sch:let
                name="entityID"
                value="../@entityID"/>
            <sch:assert
                test="every $URL in md:Extensions/mdui:UIInfo/mdui:PrivacyStatementURL[xml:lang='en']/text() satisfies local:is_HTTP_URL($URL)">
                <sch:value-of
                    select="$entityID"/>
                Invalid or missing ‘mdui:PrivacyStatementURL’ under ‘md:SPSSODescriptor/md:Extensions/mdui:UIInfo’, both with attribute ‘xml:lang='en'’, or any of their values are not valid HTTP URLs. 
                <sch:emph>Completely a requirement for the GÉANT Data Protection Code of Conduct Entity Category (2.3). Completely a guideline for the CLARIN Service Provider Federation. Please ensure that your privacy policy author(s) follow(s) https://wiki.refeds.org/display/CODE/Privacy+policy+guidelines+for+Service+Providers .</sch:emph>
            </sch:assert>
            <sch:assert
                test="every $URL in md:Extensions/mdui:UIInfo/mdui:InformationURL[xml:lang='en']/text() satisfies local:is_HTTP_URL($URL)">
                <sch:value-of
                    select="$entityID"/>
                Invalid or missing ‘mdui:InformationURL’ under ‘md:SPSSODescriptor/md:Extensions/mdui:UIInfo’, both with attribute ‘xml:lang='en'’, or any of their values are not valid HTTP URLs. 
                <sch:emph>Completely a requirement for the REFEDS Research and Scholarship Entity Category (4.3.3). Completely a guideline for the CLARIN Service Provider Federation. </sch:emph>
            </sch:assert>
        </sch:rule>
    </sch:pattern>
    <sch:pattern
        is-a="mdui_text"
        id="mdui_text_en">
        <sch:param
            name="language_code"
            value="'en'"/>
    </sch:pattern>
    <sch:pattern>
        <sch:title>Specification of the provided service and requested attributes</sch:title>
        <sch:rule
            context="md:EntityDescriptor/md:SPSSODescriptor">
            <sch:let
                name="entityID"
                value="../@entityID"/>
            <sch:let
                name="SAML_2_requested_attributes_nodes"
                value="md:AttributeConsumingService[md:ServiceName/@xml:lang='en' and md:RequestedAttribute[@NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri'] and md:ServiceDescription/@xml:lang='en']/md:RequestedAttribute[@NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri']"/>
            <sch:assert
                test="exists($SAML_2_requested_attributes_nodes)">
                <sch:value-of
                    select="$entityID"/>
                Invalid or missing ‘md:SPSSODescriptor/md:AttributeConsumingService’, or missing children ‘md:ServiceName’ and/or ‘md:RequestedAttribute[@NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri']’.
                <sch:emph>Partially a requirement for the GÉANT Data Protection Code of Conduct Entity Category. Completely a requirement for the REFEDS Research and Scholarship Entity Category (4.3.5). Completely a guideline for the CLARIN Service Provider Federation. </sch:emph>
            </sch:assert>
            <sch:assert
                test="every $requested_attribute in $SAML_2_requested_attributes_nodes satisfies exists($requested_attribute/@isRequired)">
                <sch:value-of
                    select="$entityID"/>
                Missing attribute(s) ‘md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute[@NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri']/@isRequired’. Please specify whether a SAML attribute is a must-have or like-to-have for functionality of your SP or not.
                <sch:emph>Completely a requirement for DFN-AAI and Haka/Kalmar Union registration.</sch:emph>
            </sch:assert>
            <sch:assert
                test="every $requested_attribute in $SAML_2_requested_attributes_nodes satisfies fn:starts-with($requested_attribute/@Name cast as xs:anyURI, 'urn:oid:')">
                <sch:value-of
                    select="$entityID"/>
                Missing attribute(s)  ‘md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute[@NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri']/@Name’, or their values do not start with 'urn:oid:'. You may be using the SAML 1.x NameFormat, which is incorrect for a SAML 2 attribute.
                <sch:emph>Required for technical correctness. </sch:emph>
            </sch:assert>
        </sch:rule>
    </sch:pattern>
    <sch:pattern>
        <sch:title>Explicit specification of Discovery Response and Request Initiator URLs</sch:title>
        <sch:rule
            context="md:EntityDescriptor/md:SPSSODescriptor/md:Extensions">
            <sch:let
                name="entityID"
                value="../../@entityID"/>
            <sch:let
                name="RequestInitiator_nodes"
                value="for $URL in init:RequestInitiator/@Location return $URL"/>
            <sch:let
                name="DiscoveryResponse_nodes"
                value="for $URL in idpdisc:DiscoveryResponse/@Location return $URL"/>
            <!-- cast as xs:anyURI) -->
            <sch:assert
                test="fn:count($RequestInitiator_nodes)=1 and (every $URL in RequestInitiator_elements satisfies local:is_https_URL($URL))">
                <sch:value-of
                    select="$entityID"/>
                Missing single element ‘md:SPSSODescriptor/md:Extensions/init:RequestInitiator’. 
                <sch:emph>Completely a guideline for the CLARIN Service Provider Federation. See: http://docs.oasis-open.org/security/saml/Post2.0/sstc-request-initiation.html . </sch:emph>
            </sch:assert>
            <sch:assert
                test="fn:count($DiscoveryResponse_nodes)=1 and (every $URL in DiscoveryResponse_elements satisfies local:is_https_URL($URL))">
                <sch:value-of
                    select="$entityID"/>
                Missing single element ‘md:SPSSODescriptor/md:Extensions/idpdisc:DiscoveryResponse’.
                <sch:emph>Completely a guideline for the CLARIN Service Provider Federation. See: http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-idp-discovery.html . </sch:emph>
            </sch:assert>
        </sch:rule>
    </sch:pattern>
    <sch:pattern>
        <sch:title>https endpoint URLs</sch:title>
        <sch:rule
            context="md:EntityDescriptor/md:SPSSODescriptor">
            <sch:let
                name="entityID"
                value="../@entityID"/>
            <sch:let
                name="ArtifactResolutionService_nodes"
                value="for $URL in md:ArtifactResolutionService/@Location return $URL cast as xs:anyURI"/>
            <sch:let
                name="SingleLogoutService_nodes"
                value="for $URL in md:SingleLogoutService/@Location return $URL cast as xs:anyURI"/>
            <sch:let
                name="ManageNameIDService_nodes"
                value="for $URL in md:ManageNameIDService/@Location return $URL cast as xs:anyURI"/>
            <sch:let
                name="AssertionConsumerService_nodes"
                value="for $URL in md:AssertionConsumerService/@Location return $URL cast as xs:anyURI"/>
            <sch:assert
                test="not(exists($ArtifactResolutionService_nodes)) or (every $URL in $ArtifactResolutionService_nodes satisfies local:is_https_URL($URL))">
                <sch:value-of
                    select="$entityID"/>
                Missing attribute(s) ‘md:SPSSODescriptor/md:ArtifactResolutionService/@Location’ or any or their values are not valid https URLs. 
                <sch:emph>Completely a guideline for the CLARIN Service Provider Federation. <!-- TODO: --></sch:emph>
            </sch:assert>
            <sch:assert
                test="not(exists($SingleLogoutService_nodes)) or (every $URL in $SingleLogoutService_nodes satisfies local:is_https_URL($URL))">
                <sch:value-of
                    select="$entityID"/>
                Missing attribute(s) ‘md:SPSSODescriptor/md:SingleLogoutService/@Location’ or any or their values are not valid https URLs.
                <sch:emph>Completely a guideline for the CLARIN Service Provider Federation. <!-- TODO: --></sch:emph>
            </sch:assert>
            <sch:assert
                test="not(exists($ManageNameIDService_nodes)) or (every $URL in $ManageNameIDService_nodes satisfies local:is_https_URL($URL))">
                <sch:value-of
                    select="$entityID"/>
                Missing attribute(s) ‘md:SPSSODescriptor/md:ManageNameIDService/@Location’ or any or their values are not valid https URLs. <sch:emph>Completely a guideline for the CLARIN Service Provider Federation. <!-- TODO: --></sch:emph>
            </sch:assert>
            <sch:assert
                test="exists($AssertionConsumerService_nodes) and (every $URL in $AssertionConsumerService_nodes satisfies local:is_https_URL($URL))">
                <sch:value-of
                    select="$entityID"/>
                Missing attribute(s) ‘md:SPSSODescriptor/md:AssertionConsumerService/@Location’ or any or their values are not valid https URLs.
                <sch:emph>Completely a guideline for the CLARIN Service Provider Federation. <!-- TODO: --> Required for technical correctness. </sch:emph>
            </sch:assert>
        </sch:rule>
    </sch:pattern>
    <sch:pattern>
        <sch:title>Key duplication</sch:title>
        <sch:rule
            context="md:EntityDescriptor/md:SPSSODescriptor">
            <sch:let
                name="keys"
                value="for $key in .//ds:X509Certificate return fn:normalize-space($key)"/>
            <sch:let
                name="entityID"
                value="../@entityID"/>
            <sch:let
                name="n_distinct_keys"
                value="count(distinct-values($keys))"/>
            <sch:let
                name="n_keys"
                value="count($keys)"/>
            <sch:assert
                test="$n_distinct_keys = $n_keys">
                <sch:value-of
                    select="$entityID"/>
                Duplicate keys ‘//ds:X509Certificate’ found. Counted only <sch:value-of
                    select="$n_distinct_keys"/> distinct keys among <sch:value-of
                    select="$n_keys"/> keys.
                <sch:emph>Completely a guideline for the CLARIN Service Provider Federation. </sch:emph>
            </sch:assert>
        </sch:rule>
    </sch:pattern>
    <sch:pattern>
        <sch:title>SAML 2 support</sch:title>
        <sch:rule
            context="md:EntityDescriptor/md:SPSSODescriptor">
            <sch:let
                name="entityID"
                value="../@entityID"/>
            <sch:assert
                test="md:AssertionConsumerService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']">
                <sch:value-of
                    select="$entityID"/>
                Invalid or missing ‘md:SPSSODescriptor/md:AssertionConsumerService[@Binding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']’.
                <sch:emph>Completely a requirement for the REFEDS Research and Scholarship Entity Category (4.3.1). Completely a guideline for the CLARIN Service Provider Federation. </sch:emph>
            </sch:assert>
            <sch:assert
                test="some $supported_protocol in fn:tokenize(@protocolSupportEnumeration, '\s+') satisfies $supported_protocol eq 'urn:oasis:names:tc:SAML:2.0:protocol'">
                <sch:value-of
                    select="$entityID"/>
                Invalid or missing attribute ‘md:SPSSODescriptor/@protocolSupportEnumeration’.
                <sch:emph>Completely a requirement for the REFEDS Research and Scholarship Entity Category (4.3.1). Completely a guideline for the CLARIN Service Provider Federation. </sch:emph>
            </sch:assert>
        </sch:rule>
    </sch:pattern>
    <sch:pattern>
        <sch:title>Organizational background</sch:title>
        <sch:rule
            context="md:EntityDescriptor[md:SPSSODescriptor]">
            <sch:let
                name="entityID"
                value="@entityID"/>
            <sch:assert
                test="md:Organization[md:OrganizationName/@xml:lang='en' and md:OrganizationDisplayName/@xml:lang='en' and md:OrganizationURL/@xml:lang='en']"><sch:value-of
                    select="$entityID"/>
                Invalid or missing elements ‘md:Organization’ with children ‘md:OrganizationName’ with the attribute ‘xml:lang='en'’ and ‘md:OrganizationDisplayName’ with the attribute ‘xml:lang='en'’ and ‘md:OrganizationURL’ with the attribute ‘xml:lang='en'’.
                <sch:emph>Completely a requirement for eduID.cz and DFN-AAI registration. Completely a guideline for the CLARIN Service Provider Federation. </sch:emph>
            </sch:assert>
        </sch:rule>
    </sch:pattern>
    <sch:pattern>
        <sch:title>Contact persons</sch:title>
        <sch:rule
            context="md:EntityDescriptor[md:SPSSODescriptor]">
            <sch:let
                name="entityID"
                value="@entityID"/>
            <sch:let
                name="administrative_contactpersons"
                value="md:ContactPerson[@contactType='administrative' and md:GivenName/text() and md:SurName/text() and md:EmailAddress/text()]"/>
            <sch:let
                name="technical_contactpersons"
                value="md:ContactPerson[@contactType='technical' and md:GivenName/text() and md:SurName/text() and md:EmailAddress/text()]"/>
            <sch:let
                name="support_contactpersons"
                value="md:ContactPerson[@contactType='support' and md:GivenName/text() and md:SurName/text() and md:EmailAddress/text()]"/>
            <sch:let
                name="administrative_mailto_URIs"
                value="for $mailto_URI in $administrative_contactpersons/md:EmailAddress/text() return $mailto_URI cast as xs:anyURI"/>
            <sch:let
                name="technical_mailto_URIs"
                value="for $mailto_URI in $technical_contactpersons/md:EmailAddress/text() return $mailto_URI cast as xs:anyURI"/>
            <sch:let
                name="support_mailto_URIs"
                value="for $mailto_URI in $support_contactpersons/md:EmailAddress/text() return $mailto_URI cast as xs:anyURI"/>
            <sch:assert
                test="exists($administrative_mailto_URIs) and (every $mailto_URI in $administrative_mailto_URIs satisfies local:is_mailto_URI($mailto_URI))">
                <sch:value-of
                    select="$entityID"/>
                Invalid or missing administrative contact(s) under ‘md:ContactPerson[@contactType='administrative']’. Please specify ‘md:GivenName’ and ‘md:SurName’ of the officially responsible person and provide a mailto URI (‘mailto:Contact.Person@organization.org’).
                <sch:emph>Completely a requirement for DFN-AAI and Haka/Kalmar Union registration. Partially a requirement for the REFEDS Research and Scholarship Entity Category (4.3.4). Completely a guideline for the CLARIN Service Provider Federation. </sch:emph>
            </sch:assert>
            <sch:assert
                test="exists($support_mailto_URIs) and (every $mailto_URI in $support_mailto_URIs satisfies local:is_mailto_URI($mailto_URI))">
                <sch:value-of
                    select="$entityID"/>
                Invalid or missing support contact(s) under ‘md:ContactPerson[@contactType='support']’. Please specify ‘md:GivenName’ and ‘md:SurName’ of the officially responsible person and provide a mailto URI (‘mailto:Contact.Person@organization.org’).
                <sch:emph>Completely a requirement for DFN-AAI and Haka/Kalmar Union registration. Partially a requirement for the REFEDS Research and Scholarship Entity Category (4.3.4). Completely a guideline for the CLARIN Service Provider Federation. </sch:emph>
            </sch:assert>
            <sch:assert
                test="exists($technical_mailto_URIs) and (every $mailto_URI in $technical_mailto_URIs satisfies local:is_mailto_URI($mailto_URI))">
                <sch:value-of
                    select="$entityID"/>
                Invalid or missing technical contact(s) under ‘md:ContactPerson[@contactType='technical']’. Please specify ‘md:GivenName’ and ‘md:SurName’ of the officially responsible person and provide a mailto URI (‘mailto:Contact.Person@organization.org’).
                <sch:emph>Completely a requirement for DFN-AAI and Haka/Kalmar Union registration. Partially a requirement for the REFEDS Research and Scholarship Entity Category (4.3.4). Completely a guideline for the CLARIN Service Provider Federation. </sch:emph>
            </sch:assert>
        </sch:rule>
    </sch:pattern>
</sch:schema>
