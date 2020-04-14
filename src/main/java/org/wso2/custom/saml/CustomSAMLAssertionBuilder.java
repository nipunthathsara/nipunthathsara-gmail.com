package org.wso2.custom.saml;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthenticatingAuthority;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.builders.AuthenticatingAuthorityImpl;
import org.wso2.carbon.identity.sso.saml.builders.SignKeyDataHolder;
import org.wso2.carbon.identity.sso.saml.builders.assertion.DefaultSAMLAssertionBuilder;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

public class CustomSAMLAssertionBuilder extends DefaultSAMLAssertionBuilder {
    private static Log log = LogFactory.getLog(CustomSAMLAssertionBuilder.class);
    private String userAttributeSeparator = IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;
    public static final String USER_STORE_DOMAIN_PREFIX = "wso2.com";


    @Override
    public Assertion buildAssertion(SAMLSSOAuthnReqDTO authReqDTO, DateTime notOnOrAfter, String sessionId) throws IdentityException {
        try {
            DateTime currentTime = new DateTime();
            Assertion samlAssertion = new AssertionBuilder().buildObject();
            samlAssertion.setID(SAMLSSOUtil.createID());
            samlAssertion.setVersion(SAMLVersion.VERSION_20);
            samlAssertion.setIssuer(SAMLSSOUtil.getIssuer());
            samlAssertion.setIssueInstant(currentTime);
            Subject subject = new SubjectBuilder().buildObject();

            NameID nameId = new NameIDBuilder().buildObject();
            nameId.setValue(USER_STORE_DOMAIN_PREFIX + "/" + authReqDTO.getUser().getAuthenticatedSubjectIdentifier());
            if (authReqDTO.getNameIDFormat() != null) {
                nameId.setFormat(authReqDTO.getNameIDFormat());
            } else {
                nameId.setFormat(NameIdentifier.EMAIL);
            }

            subject.setNameID(nameId);
            log.info("Name id : " + nameId);

            SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder()
                    .buildObject();
            subjectConfirmation.setMethod(SAMLSSOConstants.SUBJECT_CONFIRM_BEARER);
            SubjectConfirmationData scData = new SubjectConfirmationDataBuilder().buildObject();
            scData.setRecipient(authReqDTO.getAssertionConsumerURL());
            scData.setNotOnOrAfter(notOnOrAfter);
            if (!authReqDTO.isIdPInitSSOEnabled()) {
                scData.setInResponseTo(authReqDTO.getId());
            }
            subjectConfirmation.setSubjectConfirmationData(scData);
            subject.getSubjectConfirmations().add(subjectConfirmation);

            if (authReqDTO.getRequestedRecipients() != null && authReqDTO.getRequestedRecipients().length > 0) {
                for (String recipient : authReqDTO.getRequestedRecipients()) {
                    subjectConfirmation = new SubjectConfirmationBuilder()
                            .buildObject();
                    subjectConfirmation.setMethod(SAMLSSOConstants.SUBJECT_CONFIRM_BEARER);
                    scData = new SubjectConfirmationDataBuilder().buildObject();
                    scData.setRecipient(recipient);
                    scData.setNotOnOrAfter(notOnOrAfter);
                    if (!authReqDTO.isIdPInitSSOEnabled()) {
                        scData.setInResponseTo(authReqDTO.getId());
                    }
                    subjectConfirmation.setSubjectConfirmationData(scData);
                    subject.getSubjectConfirmations().add(subjectConfirmation);
                }
            }

            samlAssertion.setSubject(subject);

            addAuthStatement(authReqDTO, sessionId, samlAssertion);

            /*
             * If <AttributeConsumingServiceIndex> element is in the <AuthnRequest> and according to
             * the spec 2.0 the subject MUST be in the assertion
             */
            Map<String, String> claims = SAMLSSOUtil.getAttributes(authReqDTO);
            if (claims != null && !claims.isEmpty()) {
                AttributeStatement attrStmt = buildAttributeStatement(claims);
                if (attrStmt != null) {
                    samlAssertion.getAttributeStatements().add(attrStmt);
                }
            }

            AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder()
                    .buildObject();
            Audience issuerAudience = new AudienceBuilder().buildObject();
            issuerAudience.setAudienceURI(authReqDTO.getIssuerWithDomain());
            audienceRestriction.getAudiences().add(issuerAudience);
            if (authReqDTO.getRequestedAudiences() != null) {
                for (String requestedAudience : authReqDTO.getRequestedAudiences()) {
                    Audience audience = new AudienceBuilder().buildObject();
                    audience.setAudienceURI(requestedAudience);
                    audienceRestriction.getAudiences().add(audience);
                }
            }
            Conditions conditions = new ConditionsBuilder().buildObject();
            conditions.setNotBefore(currentTime);
            conditions.setNotOnOrAfter(notOnOrAfter);
            conditions.getAudienceRestrictions().add(audienceRestriction);
            samlAssertion.setConditions(conditions);

            if (authReqDTO.getDoSignAssertions()) {
                SAMLSSOUtil.setSignature(samlAssertion, authReqDTO.getSigningAlgorithmUri(), authReqDTO
                        .getDigestAlgorithmUri(), new SignKeyDataHolder(authReqDTO.getUser()
                        .getAuthenticatedSubjectIdentifier()));
            }

            return samlAssertion;
        } catch (Exception e) {
            log.error("Error when reading claim values for generating SAML Response", e);
            throw IdentityException.error(
                    "Error when reading claim values for generating SAML Response", e);
        }
    }

    private AttributeStatement buildAttributeStatement(Map<String, String> claims) {

        String claimSeparator = claims.get(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
        if (StringUtils.isNotBlank(claimSeparator)) {
            userAttributeSeparator = claimSeparator;
        }
        claims.remove(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);

        AttributeStatement attStmt = new AttributeStatementBuilder().buildObject();
        Iterator<Map.Entry<String, String>> iterator = claims.entrySet().iterator();
        boolean atLeastOneNotEmpty = false;
        for (int i = 0; i < claims.size(); i++) {
            Map.Entry<String, String> claimEntry = iterator.next();
            String claimUri = claimEntry.getKey();
            String claimValue = claimEntry.getValue();
            if (claimUri != null && !claimUri.trim().isEmpty() && claimValue != null && !claimValue.trim().isEmpty()) {
                atLeastOneNotEmpty = true;
                Attribute attribute = new AttributeBuilder().buildObject();
                attribute.setName(claimUri);
                //setting NAMEFORMAT attribute value to basic attribute profile
                attribute.setNameFormat(SAMLSSOConstants.NAME_FORMAT_BASIC);
                // look
                // https://wiki.shibboleth.net/confluence/display/OpenSAML/OSTwoUsrManJavaAnyTypes
                XSStringBuilder stringBuilder = (XSStringBuilder) Configuration.getBuilderFactory().
                        getBuilder(XSString.TYPE_NAME);
                XSString stringValue;

                //Need to check if the claim has multiple values
                if (userAttributeSeparator != null && claimValue.contains(userAttributeSeparator)) {
                    StringTokenizer st = new StringTokenizer(claimValue, userAttributeSeparator);
                    while (st.hasMoreElements()) {
                        String attValue = st.nextElement().toString();
                        if (attValue != null && attValue.trim().length() > 0) {
                            stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
                            stringValue.setValue(attValue);
                            attribute.getAttributeValues().add(stringValue);
                        }
                    }
                } else {
                    stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
                    stringValue.setValue(claimValue);
                    attribute.getAttributeValues().add(stringValue);
                }

                attStmt.getAttributes().add(attribute);
            }
        }
        if (atLeastOneNotEmpty) {
            return attStmt;
        } else {
            return null;
        }
    }

    private void addAuthStatement(SAMLSSOAuthnReqDTO authReqDTO, String sessionId, Assertion samlAssertion) {

        DateTime authnInstant = new DateTime();

        if (authReqDTO.getIdpAuthenticationContextProperties().get(SAMLSSOConstants.AUTHN_CONTEXT_CLASS_REF) != null
                && !authReqDTO.getIdpAuthenticationContextProperties().get(SAMLSSOConstants.AUTHN_CONTEXT_CLASS_REF)
                .isEmpty()) {

            List<Map<String, Object>> authenticationContextProperties = authReqDTO
                    .getIdpAuthenticationContextProperties().get(SAMLSSOConstants.AUTHN_CONTEXT_CLASS_REF);

            for (Map<String, Object> authenticationContextProperty : authenticationContextProperties) {
                if (authenticationContextProperty.get(SAMLSSOConstants.PASS_THROUGH_DATA) != null) {
                    List<String> authnContextClassRefList = (List<String>) authenticationContextProperty
                            .get(SAMLSSOConstants.PASS_THROUGH_DATA);
                    if (!authnContextClassRefList.isEmpty()) {
                        String idpEntityId = null;
                        if (authenticationContextProperty.get(IdentityApplicationConstants.Authenticator
                                .SAML2SSO.IDP_ENTITY_ID) != null) {
                            idpEntityId = (String) authenticationContextProperty.get(IdentityApplicationConstants
                                    .Authenticator.SAML2SSO.IDP_ENTITY_ID);
                        }
                        for (String authnContextClassRef : authnContextClassRefList) {
                            if (StringUtils.isNotBlank(authnContextClassRef)) {
                                if (log.isDebugEnabled()) {
                                    log.debug("Passing AuthnContextClassRef: " + authnContextClassRef + " and " +
                                            "AuthenticatingAuthority:" + idpEntityId + " in the AuthnStatement");
                                }
                                samlAssertion.getAuthnStatements().add(getAuthnStatement(authReqDTO, sessionId,
                                        authnContextClassRef, authnInstant, idpEntityId));
                            }
                        }
                    }
                }
            }
        }

    }

    private AuthnStatement getAuthnStatement(SAMLSSOAuthnReqDTO authReqDTO, String sessionId,
                                             String authnContextClassRef, DateTime authnInstant, String idPEntityId) {

        AuthnStatement authStmt = new AuthnStatementBuilder().buildObject();
        authStmt.setAuthnInstant(authnInstant);
        AuthnContext authContext = new AuthnContextBuilder().buildObject();
        AuthnContextClassRef authCtxClassRef = new AuthnContextClassRefBuilder().buildObject();
        authCtxClassRef.setAuthnContextClassRef(authnContextClassRef);
        authContext.setAuthnContextClassRef(authCtxClassRef);
        if (StringUtils.isNotBlank(idPEntityId)) {
            AuthenticatingAuthority authenticatingAuthority = new AuthenticatingAuthorityImpl();
            authenticatingAuthority.setURI(idPEntityId);
            authContext.getAuthenticatingAuthorities().add(authenticatingAuthority);
        }
        authStmt.setAuthnContext(authContext);
        if (authReqDTO.isDoSingleLogout()) {
            authStmt.setSessionIndex(sessionId);
        }
        return authStmt;
    }
}