package org.wso2.carbon.identity.application.authenticator.impersonation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;
import org.wso2.carbon.identity.application.authenticator.impersonation.internal.UserImpersonationDataHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Arrays;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Basic authentication based impersonation authenticator for WSO2 Identity Server 5.7.0
 * This authenticator will impersonate any user in {@code IMP_USER_STORE} userstore if the
 * authentication request was sent from an logged in {@code IMP_ADMIN_ROLE} user.
 */
public class UserImpersonationAuthenticator extends BasicAuthenticator {

    private static final long serialVersionUID = 4345354156955223654L;
    private static final Log log = LogFactory.getLog(UserImpersonationAuthenticator.class);
    private static final String DEFAULT_IMP_ADMIN_ROLE = "Internal/impadmin";
    private static final String DEFAULT_IMP_USER_STORE = "CUSTOMERS";
    private static final String IMPERSONATEE = "impersonatee";
    private static final String IMP_ADMIN_ROLE = "IMP_ADMIN_ROLE";
    private static final String IMP_USER_STORE = "IMP_USER_STORE";
    public static final String AUTHENTICATOR_NAME = "UserImpersonationAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "user-impersonator";

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {
        AuthenticatorFlowStatus authenticatorFlowStatus = AuthenticatorFlowStatus.INCOMPLETE;
        AuthenticatedUser authenticatedUser = context.getSubject();

        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }

        // is impersonation triggered by a logged in user
        if (context.getSubject() == null) {
            return authenticatorFlowStatus;
        }

        // start impersonation flow only if imperstonatee is present in the request
        if (request.getParameter(IMPERSONATEE) == null && context.getProperty(IMPERSONATEE) == null) {
            return super.process(request, response, context);
        }

        // set impersonatee into context if already not in there
        if (context.getProperty(IMPERSONATEE) == null) {
            context.setProperty(IMPERSONATEE, request.getParameter(IMPERSONATEE));
        }

        String impersonatee = (String) context.getProperty(IMPERSONATEE);
        Map<String, String> configParams = getAuthenticatorConfig().getParameterMap();
        try {
            // get the user store manager for admin user
            UserStoreManager adminUSMgr = getUserStoreManager(authenticatedUser.getAuthenticatedSubjectIdentifier());
            String[] impersonatorRoles = adminUSMgr.getRoleListOfUser(MultitenantUtils
                    .getTenantAwareUsername(authenticatedUser.getAuthenticatedSubjectIdentifier()));

            // check if the authenticated user has the impersonator role
            String impAdminRole = configParams.get(IMP_ADMIN_ROLE);
            if (impAdminRole == null || impAdminRole.length() == 0) {
                impAdminRole = DEFAULT_IMP_ADMIN_ROLE;
            }

            // impersonator should have the IMP_ADMIN_ROLE role
            boolean hasRole = Arrays.asList(impersonatorRoles).contains(impAdminRole);
            if (!hasRole) {
                return authenticatorFlowStatus;
            }

            // pick impersonatee userstore from config or defaults
            String impUserStore = configParams.get(IMP_USER_STORE);
            if (impUserStore == null || impUserStore.length() == 0) {
                impUserStore = DEFAULT_IMP_USER_STORE;
            }

            // get the userstore manager for impersonatee
            UserStoreManager um = getUserStoreManager(impersonatee);
            String impNameWithDomain = UserCoreUtil.addDomainToName(impersonatee, impUserStore);

            // is impersonatee is in correct userstore
            if (!um.isExistingUser(impNameWithDomain)) {
                return authenticatorFlowStatus;
            }

            // set subject as impersonatee
            log.debug("Impersonatee is identified");
            authenticatorFlowStatus = AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            AuthenticatedUser user = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(impersonatee);
            context.setSubject(user);
        } catch (UserStoreException e) {
            String errorMessage = "Unable to get the user realm";
            log.error(errorMessage, e);
            throw new AuthenticationFailedException(errorMessage, e);
        }

        return authenticatorFlowStatus;
    }

    @Override
    public String getName() {
        return AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {
        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    private UserStoreManager getUserStoreManager(String username) throws AuthenticationFailedException {

        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            UserRealm userRealm = UserImpersonationDataHolder.getInstance().getRealmService()
                    .getTenantUserRealm(tenantId);
            return (UserStoreManager) userRealm.getUserStoreManager();

        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Failed to retrieve user store manager.", e);
        }
    }
}
