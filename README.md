# Impersonator for WSO2 Identity Sever

Basic authentication based impersonation authenticator for WSO2 Identity Server 5.7.0
This authenticator can be used to implement a user impersonation scenario with above product version.

## Scenario:

* A user having certain admin (call center user) role need to login to an application as some other user (customer).
* All customer users are in a specific userstore attached to WSO2 IS.
* A request to impersonate a user should be successful only if, 

      * The user requesting to imepersonate another user has the configured admin role.
      * The user being impersonated should reside in a specific preconfigured userstore.

## Try it:
1. Clone the project using `git clone git@github.com:praminda/wso2-impersonator.git`.
1. Build the project using `mvn clean install`.
1. Copy the jar file created in project `target` directory to `$IS_HOME/repository/components/dropins/`.
1. Open [`$IS_HOME/repository/deployment/server/webapps/authenticationendpoint/login.jsp`](https://github.com/praminda/wso2-impersonator/blob/master/references/login.jsp)
1. Add new authenticator reference to the list of authenticators in defined in the begining of the file.

    ```java
    private static final String IMP_BASIC_AUTHENTICATOR = "UserImpersonationAuthenticator";
    ```
1. Add new condition `|| localAuthenticatorNames.contains(IMP_BASIC_AUTHENTICATOR)` to below if block.
    ```java
    else if (localAuthenticatorNames.size() > 0 && localAuthenticatorNames.contains(JWT_BASIC_AUTHENTICATOR) ||
                                    localAuthenticatorNames.contains(BASIC_AUTHENTICATOR) || localAuthenticatorNames.contains(IMP_BASIC_AUTHENTICATOR))
    ```
1. Start/Restart WSO2 IS.
1. Got to [Management Console](https://localhost:9443/carbon) and add new usestore with domain name `CUSTOMERS`.
1. Create a new user in newly created userstore.
1. Add new role `Internal/impadmin` and assigned it to one of the existing users or a new user.
1. Update your application to send a new authetication request to WSO2 IS within a authenticated session. (Add new button to start impersonation which is only visible to logged in users)
1. Above authentication request should send additional `prompt=login&impersonatee=<impersoantee username>` parameters in the request.

       https://localhost:9443/oauth2/authorize?response_type=code&client_id=client_id&scope=email+address+openid&redirect_uri=https%3A%2F%2Flocalhost%3A9443%2Fapp%2Fcallback.jsp&nonce=34852389&state=8974j9123&prompt=login&impersonatee=siripala

## Configurations

Follwing configuration can be applied to authenticator inorder to change the defualts. Configuration should be done in the 
`$IS_HOME/repository/conf/identity/application-authentication.xml` by adding new authenticator similar to below
```xml
<AuthenticatorConfig name="UserImpersonationAuthenticator" enabled="true">
    <Parameter name="IMP_ADMIN_ROLE">Internal/impadmin</Parameter>
    <Parameter name="IMP_USER_STORE">CUSTOMER</Parameter>
</AuthenticatorConfig>
```
1. `IMP_ADMIN_ROLE`: Role of the impersonator.
1. `IMP_USER_STORE`: Userstore containing all impersonatee users.
