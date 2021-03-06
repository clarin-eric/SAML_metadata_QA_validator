<xsl:stylesheet
    version="2.0"
    xmlns:svrl="http://purl.oclc.org/dsdl/svrl"
    xmlns:fn="http://www.w3.org/2005/xpath-functions"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:xs="http://www.w3.org/2001/XMLSchema">
    <xsl:output
        encoding="utf-8"
        method="xml"
        indent="yes"/>
    <xsl:strip-space
        elements="*"/>
    <xsl:template
        match="/svrl:schematron-output">
        <results>
            <xsl:apply-templates/>
        </results>
    </xsl:template>
    <xsl:template
        match="svrl:failed-assert/svrl:text">
        <result>
            <xsl:variable
                name="fields"
                select="fn:tokenize(text(), '\n+')"/>
            <sp>
                <xsl:value-of
                    select="fn:normalize-space($fields[1])"/>
            </sp>
            <explanation>
                <xsl:value-of
                    select="fn:normalize-space($fields[2])"/>
            </explanation>
            <requirement>
                <xsl:value-of
                    select="fn:normalize-space($fields[3])"/>
            </requirement>
        </result>
    </xsl:template>
</xsl:stylesheet>
