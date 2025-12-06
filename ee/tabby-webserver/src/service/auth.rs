use std::sync::Arc;

use anyhow::{anyhow, Context};

use async_trait::async_trait;
use juniper::ID;
use tabby_db::DbConn;
use tabby_schema::{
    auth::{
        AuthenticationService, JWTPayload, LdapCredential, OAuthCredential, OAuthError,
        OAuthProvider, OAuthResponse, RefreshTokenResponse,
        TokenAuthResponse, UpdateLdapCredentialInput,
        UpdateOAuthCredentialInput, UserSecured,
    },
    email::EmailService,
    is_demo_mode,
    license::{LicenseInfo, LicenseService},
    setting::SettingService,
    AsID, AsRowid, CoreError, DbEnum, Result,
};
use tracing::warn;

use super::{graphql_pagination_to_filter, UserSecuredExt};
use crate::{
    bail,
    jwt::{generate_jwt, validate_jwt},
    ldap::{self, LdapClient},
    oauth::{self, OAuthClient},
};

#[cfg(test)]
pub mod testutils;

#[derive(Clone)]
struct AuthenticationServiceImpl {
    db: DbConn,
    mail: Arc<dyn EmailService>,
    license: Arc<dyn LicenseService>,
    setting: Arc<dyn SettingService>,
}

pub fn create(
    db: DbConn,
    mail: Arc<dyn EmailService>,
    license: Arc<dyn LicenseService>,
    setting: Arc<dyn SettingService>,
) -> impl AuthenticationService {
    AuthenticationServiceImpl {
        db,
        mail,
        license,
        setting,
    }
}

#[async_trait]
impl AuthenticationService for AuthenticationServiceImpl {
    async fn update_user_avatar(&self, id: &ID, avatar: Option<Box<[u8]>>) -> Result<()> {
        if is_demo_mode() {
            bail!("Changing profile data is disabled in demo mode");
        }
        if avatar.as_ref().is_some_and(|v| v.len() > 512 * 1024) {
            bail!("The image you are attempting to upload is too large. Please ensure the file size is under 512KB");
        }
        let id = id.as_rowid()?;
        self.db.update_user_avatar(id, avatar).await?;
        Ok(())
    }

    async fn get_user_avatar(&self, id: &ID) -> Result<Option<Box<[u8]>>> {
        Ok(self.db.get_user_avatar(id.as_rowid()?).await?)
    }

    async fn update_user_name(&self, id: &ID, name: String) -> Result<()> {
        if is_demo_mode() {
            bail!("Changing profile data is disabled in demo mode");
        }

        let user = self.get_user(id).await?;
        if user.is_sso_user {
            bail!("Name cannot be changed for SSO users");
        }

        let id = id.as_rowid()?;
        self.db.update_user_name(id, name).await?;
        Ok(())
    }

    async fn token_auth_ldap(&self, user_id: &str, password: &str) -> Result<TokenAuthResponse> {
        let license = self
            .license
            .read()
            .await
            .context("Failed to read license info")?;

        let credential = self.db.read_ldap_credential().await?;
        if credential.is_none() {
            bail!("LDAP is not configured");
        }

        let credential = credential.unwrap();
        let mut client = ldap::new_ldap_client(
            credential.host.as_ref(),
            credential.port,
            credential.encryption.as_str(),
            credential.skip_tls_verify,
            credential.bind_dn,
            &credential.bind_password,
            credential.base_dn,
            credential.user_filter,
            credential.email_attribute,
            credential.name_attribute,
        );

        ldap_login(
            &mut client,
            &self.db,
            &*self.setting,
            &license,
            &*self.mail,
            user_id,
            password,
        )
        .await
    }

    async fn refresh_token(&self, token: String) -> Result<RefreshTokenResponse> {
        let Some(refresh_token) = self.db.get_refresh_token(&token).await? else {
            bail!("Invalid refresh token");
        };
        if refresh_token.is_expired() {
            bail!("Expired refresh token");
        }
        let Some(user) = self.db.get_user(refresh_token.user_id).await? else {
            bail!("User not found");
        };

        if !user.active {
            bail!("User is disabled");
        }

        let new_token = self
            .db
            .renew_refresh_token(refresh_token.id, &token)
            .await?;

        // refresh token update is done, generate new access token based on user info
        let Ok(access_token) = generate_jwt(user.id.as_id()) else {
            bail!("Unknown error");
        };

        let resp = RefreshTokenResponse::new(access_token, new_token, refresh_token.expires_at);

        Ok(resp)
    }

    async fn verify_access_token(&self, access_token: &str) -> Result<JWTPayload> {
        let claims = validate_jwt(access_token).map_err(anyhow::Error::new)?;
        Ok(claims)
    }
    async fn verify_auth_token(&self, token: &str) -> Result<ID> {
        match self.db.verify_auth_token(token, false).await {
            Ok(user) => Ok(user.as_id()),
            Err(e) => bail!("Failed to verify auth token: {e}"),
        }
    }

    async fn is_admin_initialized(&self) -> Result<bool> {
        let admin = self.db.list_admin_users().await?;
        Ok(!admin.is_empty())
    }

    async fn update_user_role(&self, id: &ID, is_admin: bool) -> Result<()> {
        if is_admin {
            let license = self.license.read().await?;
            let num_admins = self.db.count_active_admin_users().await?;
            license.ensure_admin_seats(num_admins + 1)?;
        }

        let id = id.as_rowid()?;
        let user = self.db.get_user(id).await?.context("User doesn't exits")?;

        if !user.active {
            bail!("Inactive user's status cannot be changed");
        }

        if user.is_owner() {
            bail!("The owner's admin status cannot be changed");
        }

        Ok(self.db.update_user_role(id, is_admin).await?)
    }

    async fn get_user_by_email(&self, email: &str) -> Result<UserSecured> {
        let user = self.db.get_user_by_email(email).await?;
        if let Some(dao) = user {
            Ok(UserSecured::new(self.db.clone(), dao))
        } else {
            bail!("User not found {}", email)
        }
    }

    async fn get_user(&self, id: &ID) -> Result<UserSecured> {
        let user = self.db.get_user(id.as_rowid()?).await?;
        if let Some(dao) = user {
            Ok(UserSecured::new(self.db.clone(), dao))
        } else {
            bail!("User not found")
        }
    }

    async fn reset_user_auth_token(&self, id: &ID) -> Result<()> {
        Ok(self.db.reset_user_auth_token_by_id(id.as_rowid()?).await?)
    }

    async fn logout_all_sessions(&self, id: &ID) -> Result<()> {
        Ok(self.db.delete_tokens_by_user_id(id.as_rowid()?).await?)
    }

    async fn list_users(
        &self,
        ids: Option<Vec<ID>>,
        after: Option<String>,
        before: Option<String>,
        first: Option<usize>,
        last: Option<usize>,
    ) -> Result<Vec<UserSecured>> {
        let (skip_id, limit, backwards) = graphql_pagination_to_filter(after, before, first, last)?;

        let rowids = ids.map(|ids| {
            ids.into_iter()
                .filter_map(|x| x.as_rowid().ok().map(|x| x as i32))
                .collect()
        });

        Ok(self
            .db
            .list_users_with_filter(rowids, skip_id, limit, backwards)
            .await?
            .into_iter()
            .map(|x| UserSecured::new(self.db.clone(), x))
            .collect())
    }

    async fn oauth(
        &self,
        code: String,
        provider: OAuthProvider,
    ) -> std::result::Result<OAuthResponse, OAuthError> {
        let client = oauth::new_oauth_client(provider, Arc::new(self.clone()));
        let license = self
            .license
            .read()
            .await
            .context("Failed to read license info")?;

        oauth_login(
            client,
            code,
            &self.db,
            &*self.setting,
            &license,
            &*self.mail,
        )
        .await
    }

    async fn read_oauth_credential(
        &self,
        provider: OAuthProvider,
    ) -> Result<Option<OAuthCredential>> {
        let credential = self
            .db
            .read_oauth_credential(provider.as_enum_str())
            .await?;
        match credential {
            Some(c) => Ok(Some(c.try_into()?)),
            None => Ok(None),
        }
    }

    async fn oauth_callback_url(&self, provider: OAuthProvider) -> Result<String> {
        let external_url = self.setting.read_network_setting().await?.external_url;
        let url = match provider {
            OAuthProvider::Github => external_url + "/oauth/callback/github",
            OAuthProvider::Google => external_url + "/oauth/callback/google",
            OAuthProvider::Gitlab => external_url + "/oauth/callback/gitlab",
        };
        Ok(url)
    }

    async fn update_oauth_credential(&self, input: UpdateOAuthCredentialInput) -> Result<()> {
        self.db
            .update_oauth_credential(
                input.provider.as_enum_str(),
                &input.client_id,
                input.client_secret.as_deref(),
            )
            .await?;
        Ok(())
    }

    async fn delete_oauth_credential(&self, provider: OAuthProvider) -> Result<()> {
        self.db
            .delete_oauth_credential(provider.as_enum_str())
            .await?;
        Ok(())
    }

    async fn read_ldap_credential(&self) -> Result<Option<LdapCredential>> {
        let credential = self.db.read_ldap_credential().await?;
        match credential {
            Some(c) => Ok(Some(c.try_into()?)),
            None => Ok(None),
        }
    }

    async fn test_ldap_connection(&self, input: UpdateLdapCredentialInput) -> Result<()> {
        let password = if let Some(password) = input.bind_password.as_deref() {
            password
        } else {
            &self
                .db
                .read_ldap_credential()
                .await?
                .ok_or_else(|| anyhow!("LDAP password is not configured"))?
                .bind_password
        };
        let mut client = ldap::new_ldap_client(
            input.host.as_ref(),
            input.port as i64,
            input.encryption.as_enum_str(),
            input.skip_tls_verify,
            input.bind_dn,
            password,
            input.base_dn,
            input.user_filter,
            input.email_attribute,
            input.name_attribute,
        );

        if let Err(e) = client.validate("", "").await {
            if e.to_string().contains("User not found") {
                return Ok(());
            } else {
                bail!("Failed to connect to LDAP server: {e}");
            }
        }

        Ok(())
    }

    async fn update_ldap_credential(&self, input: UpdateLdapCredentialInput) -> Result<()> {
        let password = if let Some(password) = input.bind_password.as_deref() {
            password
        } else {
            &self
                .db
                .read_ldap_credential()
                .await?
                .ok_or_else(|| anyhow!("LDAP password is not configured"))?
                .bind_password
        };
        self.db
            .update_ldap_credential(
                &input.host,
                input.port,
                &input.bind_dn,
                password,
                &input.base_dn,
                &input.user_filter,
                input.encryption.as_enum_str(),
                input.skip_tls_verify,
                &input.email_attribute,
                input.name_attribute.as_deref(),
            )
            .await?;
        Ok(())
    }

    async fn delete_ldap_credential(&self) -> Result<()> {
        self.db.delete_ldap_credential().await?;
        Ok(())
    }

    async fn update_user_active(&self, id: &ID, active: bool) -> Result<()> {
        let id = id.as_rowid()?;
        let user = self.db.get_user(id).await?.context("User doesn't exits")?;

        if user.active == active {
            bail!("User's active status is already set to {active}");
        }

        if user.is_owner() {
            bail!("The owner's active status cannot be changed");
        }

        let license = self.license.read().await?;

        if active {
            // Check there's sufficient seat if switching user to active.
            license.ensure_available_seats(1)?;
        }

        if active && user.is_admin {
            // Check there's sufficient seat if an admin being swtiched to active.
            let num_admins = self.db.count_active_admin_users().await?;
            license.ensure_admin_seats(num_admins + 1)?;
        }

        Ok(self.db.update_user_active(id, active).await?)
    }
}

async fn ldap_login(
    client: &mut dyn LdapClient,
    db: &DbConn,
    setting: &dyn SettingService,
    license: &LicenseInfo,
    mail: &dyn EmailService,
    user_id: &str,
    password: &str,
) -> Result<TokenAuthResponse> {
    let user = client.validate(user_id, password).await?;
    let user_id = get_or_create_sso_user(license, db, setting, mail, &user.email, &user.name)
        .await
        .map_err(|e| CoreError::Other(anyhow!("fail to get or create ldap user: {}", e)))?;

    let refresh_token = db.create_refresh_token(user_id).await?;
    let access_token = generate_jwt(user_id.as_id())
        .map_err(|e| CoreError::Other(anyhow!("fail to create access_token: {}", e)))?;

    let resp = TokenAuthResponse::new(access_token, refresh_token);
    Ok(resp)
}

async fn oauth_login(
    client: Arc<dyn OAuthClient>,
    code: String,
    db: &DbConn,
    setting: &dyn SettingService,
    license: &LicenseInfo,
    mail: &dyn EmailService,
) -> Result<OAuthResponse, OAuthError> {
    let access_token = client.exchange_code_for_token(code).await?;
    let email = client.fetch_user_email(&access_token).await?;
    let name = client.fetch_user_full_name(&access_token).await?;
    let user_id = get_or_create_sso_user(license, db, setting, mail, &email, &name).await?;

    let refresh_token = db.create_refresh_token(user_id).await?;

    let access_token = generate_jwt(user_id.as_id()).map_err(|_| OAuthError::Unknown)?;

    let resp = OAuthResponse {
        access_token,
        refresh_token,
    };
    Ok(resp)
}

async fn get_or_create_sso_user(
    license: &LicenseInfo,
    db: &DbConn,
    setting: &dyn SettingService,
    mail: &dyn EmailService,
    email: &str,
    name: &str,
) -> Result<i64, OAuthError> {
    if let Some(user) = db.get_user_by_email(email).await? {
        return user
            .active
            .then_some(user.id)
            .ok_or(OAuthError::UserDisabled);
    }

    // Check license before creating user.
    if license.ensure_available_seats(1).is_err() {
        return Err(OAuthError::InsufficientSeats);
    }

    let name = (!name.is_empty()).then_some(name.to_owned());

    // Check if user can register based on security settings (allowed domains)
    if !setting
        .read_security_setting()
        .await
        .map_err(|x| OAuthError::Other(x.into()))?
        .can_register_without_invitation(email)
    {
        return Err(OAuthError::UserNotInvited);
    }

    if is_demo_mode() {
        bail!("Registering new users is disabled in demo mode");
    }

    // Create user via SSO - no password needed
    let res = db.create_user(email.to_owned(), false, name).await?;
    if let Err(e) = mail.send_signup(email.to_string()).await {
        warn!("Failed to send signup email: {e}");
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use tabby_schema::auth::LdapEncryptionKind;

    use crate::service::auth::testutils::FakeLdapClient;

    struct MockLicenseService {
        status: LicenseStatus,
        seats: i32,
        seats_used: i32,
    }

    impl MockLicenseService {
        fn team() -> Self {
            Self {
                status: LicenseStatus::Ok,
                seats: 5,
                seats_used: 1,
            }
        }

        fn team_with_seats(seats: i32) -> Self {
            Self {
                status: LicenseStatus::Ok,
                seats,
                seats_used: 1,
            }
        }
    }

    #[async_trait]
    impl LicenseService for MockLicenseService {
        async fn read(&self) -> Result<LicenseInfo> {
            Ok(LicenseInfo {
                r#type: tabby_schema::license::LicenseType::Team,
                status: self.status.clone(),
                seats: self.seats,
                seats_used: self.seats_used,
                issued_at: Some(Utc::now()),
                expires_at: Some(Utc::now()),
                features: Some(Vec::new()),
            })
        }

        async fn update(&self, _: String) -> Result<()> {
            unimplemented!()
        }

        async fn reset(&self) -> Result<()> {
            unimplemented!()
        }
    }

    async fn test_authentication_service_with_license(
        license: Arc<dyn LicenseService>,
    ) -> AuthenticationServiceImpl {
        let db = DbConn::new_in_memory().await.unwrap();
        create_impl(
            db.clone(),
            Arc::new(new_email_service(db.clone()).await.unwrap()),
            license,
            Arc::new(crate::service::setting::create(db)),
        )
    }

    async fn test_authentication_service() -> AuthenticationServiceImpl {
        test_authentication_service_with_license(Arc::new(MockLicenseService::team())).await
    }

    async fn test_authentication_service_with_mail() -> (AuthenticationServiceImpl, TestEmailServer)
    {
        let db = DbConn::new_in_memory().await.unwrap();
        let smtp = TestEmailServer::start().await;
        let service = AuthenticationServiceImpl {
            db: db.clone(),
            mail: Arc::new(smtp.create_test_email_service(db.clone()).await),
            license: Arc::new(MockLicenseService::team()),
            setting: Arc::new(crate::service::setting::create(db)),
        };
        (service, smtp)
    }

    use assert_matches::assert_matches;
    use serial_test::serial;
    use tabby_schema::{
        juniper::relay::{self, Connection},
        license::{LicenseInfo, LicenseStatus, LicenseType},
    };

    use super::*;
    use crate::{
        oauth::test_client::TestOAuthClient,
        service::email::{new_email_service, testutils::TestEmailServer},
    };

    #[tokio::test]
    async fn test_is_admin_initialized() {
        let service = test_authentication_service().await;

        assert!(!service.is_admin_initialized().await.unwrap());
        tabby_db::testutils::create_user(&service.db).await;
        assert!(service.is_admin_initialized().await.unwrap());
    }

    async fn list_users(
        db: &AuthenticationServiceImpl,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Connection<UserSecured> {
        relay::query_async(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                Ok(db
                    .list_users(None, after, before, first, last)
                    .await
                    .unwrap())
            },
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    #[serial]
    async fn test_get_or_create_oauth_user() {
        let (service, mail) = test_authentication_service_with_mail().await;
        let license = service.license.read().await.unwrap();
        let id = service
            .db
            .create_user("test@example.com".into(), false, None)
            .await
            .unwrap();
        service.db.update_user_active(id, false).await.unwrap();
        let setting = service.setting;

        let res = get_or_create_sso_user(
            &license,
            &service.db,
            &*setting,
            &*service.mail,
            "test@example.com",
            "",
        )
        .await;
        assert_matches!(res, Err(OAuthError::UserDisabled));

        service
            .db
            .update_security_setting(Some("example.com".into()), false, false)
            .await
            .unwrap();

        let res = get_or_create_sso_user(
            &license,
            &service.db,
            &*setting,
            &*service.mail,
            "example@example.com",
            "Example User",
        )
        .await;
        assert_matches!(res, Ok(2));

        let user = service.db.get_user(2).await.unwrap().unwrap();
        assert_eq!(user.email, "example@example.com");
        assert_eq!(user.name, Some("Example User".into()));

        tokio::time::sleep(Duration::milliseconds(50).to_std().unwrap()).await;
        assert_eq!(mail.list_mail().await[0].subject, "Welcome to Tabby!");

        let res = get_or_create_sso_user(
            &license,
            &service.db,
            &*setting,
            &*service.mail,
            "example@gmail.com",
            "",
        )
        .await;
        assert_matches!(res, Err(OAuthError::UserNotInvited));
    }

    #[tokio::test]
    async fn test_update_role() {
        let service = test_authentication_service().await;
        let _ = service
            .db
            .create_user("admin@example.com".into(), true, None)
            .await
            .unwrap();

        let user_id = service
            .db
            .create_user("user@example.com".into(), false, None)
            .await
            .unwrap();

        assert!(service
            .update_user_role(&user_id.as_id(), true)
            .await
            .is_ok());

        // Inactive user's role cannot be changed
        service
            .update_user_active(&user_id.as_id(), false)
            .await
            .unwrap();
        assert!(service
            .update_user_role(&user_id.as_id(), false)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_owner_status() {
        let service = test_authentication_service().await;
        let admin_id = service
            .db
            .create_user("admin@example.com".into(), true, None)
            .await
            .unwrap();

        assert!(service
            .update_user_role(&admin_id.as_id(), false)
            .await
            .is_err());

        assert!(service
            .update_user_active(&admin_id.as_id(), false)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_pagination() {
        let service = test_authentication_service().await;
        service
            .db
            .create_user("a@example.com".into(), false, None)
            .await
            .unwrap();
        service
            .db
            .create_user("b@example.com".into(), false, None)
            .await
            .unwrap();
        service
            .db
            .create_user("c@example.com".into(), false, None)
            .await
            .unwrap();

        let all_users = list_users(&service, None, None, None, None).await;

        assert!(!all_users.page_info.has_next_page);
        assert!(!all_users.page_info.has_previous_page);

        let users = list_users(
            &service,
            Some(all_users.edges[0].cursor.clone()),
            None,
            None,
            None,
        )
        .await;

        assert!(!users.page_info.has_next_page);
        assert!(users.page_info.has_previous_page);

        let users = list_users(&service, None, None, Some(2), None).await;

        assert!(users.page_info.has_next_page);
        assert!(!users.page_info.has_previous_page);

        let users = list_users(
            &service,
            None,
            Some(all_users.edges[1].cursor.clone()),
            None,
            Some(1),
        )
        .await;

        assert!(users.page_info.has_next_page);
        assert!(!users.page_info.has_previous_page);

        let users = list_users(
            &service,
            Some(all_users.edges[2].cursor.clone()),
            None,
            None,
            None,
        )
        .await;
        assert!(!users.page_info.has_next_page);
        assert!(users.page_info.has_previous_page);

        let users = list_users(&service, None, None, Some(3), None).await;
        assert!(!users.page_info.has_next_page);
        assert!(!users.page_info.has_previous_page);

        let users = list_users(
            &service,
            Some(all_users.edges[0].cursor.clone()),
            None,
            Some(2),
            None,
        )
        .await;
        assert!(!users.page_info.has_next_page);
        assert!(users.page_info.has_previous_page);
    }

    #[tokio::test]
    async fn test_update_user_active_on_admin_seats() {
        let service = test_authentication_service_with_license(Arc::new(
            MockLicenseService::team_with_seats(3),
        ))
        .await;

        // Create owner user via SSO flow (first admin)
        service
            .db
            .create_user("a@example.com".into(), true, None)
            .await
            .unwrap();

        let user1 = service
            .db
            .create_user("b@example.com".into(), false, None)
            .await
            .unwrap();
        let user2 = service
            .db
            .create_user("c@example.com".into(), false, None)
            .await
            .unwrap();
        let user3 = service
            .db
            .create_user("d@example.com".into(), false, None)
            .await
            .unwrap();

        service
            .update_user_role(&user1.as_id(), true)
            .await
            .unwrap();
        service
            .update_user_role(&user2.as_id(), true)
            .await
            .unwrap();

        assert_matches!(service.db.count_active_admin_users().await, Ok(3));

        assert_matches!(
            service.update_user_role(&user3.as_id(), true).await,
            Err(CoreError::InvalidLicense(_))
        );

        // Change user2 to deactive.
        service
            .update_user_active(&user2.as_id(), false)
            .await
            .unwrap();

        assert_matches!(service.db.count_active_admin_users().await, Ok(2));
        assert_matches!(service.update_user_role(&user3.as_id(), true).await, Ok(_));

        // Not able to toggle user to active due to admin seat limits.
        assert_matches!(
            service.update_user_role(&user2.as_id(), true).await,
            Err(CoreError::InvalidLicense(_))
        );
    }

    #[tokio::test]
    async fn test_sso_user_forbid_update_name() {
        let service = test_authentication_service().await;
        let id = service
            .db
            .create_user("test@example.com".into(), true, None)
            .await
            .unwrap();

        assert!(service
            .update_user_name(&id.as_id(), "newname".into())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_ldap_credential() {
        let service = test_authentication_service().await;
        service
            .update_ldap_credential(UpdateLdapCredentialInput {
                host: "ldap.example.com".into(),
                port: 389,
                bind_dn: "cn=admin,dc=example,dc=com".into(),
                bind_password: Some("password".into()),
                base_dn: "dc=example,dc=com".into(),
                user_filter: "(&(objectClass=person)(uid=%s))".into(),
                encryption: LdapEncryptionKind::None,
                skip_tls_verify: false,
                email_attribute: "mail".into(),
                name_attribute: Some("cn".into()),
            })
            .await
            .unwrap();

        // test the read_ldap_credential
        let cred = service.read_ldap_credential().await.unwrap().unwrap();
        assert_eq!(cred.host, "ldap.example.com");
        assert_eq!(cred.port, 389);
        assert_eq!(cred.bind_dn, "cn=admin,dc=example,dc=com");
        assert_eq!(cred.base_dn, "dc=example,dc=com");
        assert_eq!(cred.user_filter, "(&(objectClass=person)(uid=%s))");
        assert_eq!(cred.encryption, LdapEncryptionKind::None);
        assert!(!cred.skip_tls_verify);
        assert_eq!(cred.email_attribute, "mail");
        assert_eq!(cred.name_attribute, Some("cn".into()));

        service
            .update_ldap_credential(UpdateLdapCredentialInput {
                host: "ldap1.example1.com".into(),
                port: 3890,
                bind_dn: "cn=admin1,dc=example1,dc=com".into(),
                bind_password: None,
                base_dn: "dc=example1,dc=com".into(),
                user_filter: "((uid=%s))".into(),
                encryption: LdapEncryptionKind::None,
                skip_tls_verify: true,
                email_attribute: "email".into(),
                name_attribute: Some("name".into()),
            })
            .await
            .unwrap();

        // use db to verify the update and password sine it's not returned in service
        let cred = service.db.read_ldap_credential().await.unwrap().unwrap();
        assert_eq!(cred.host, "ldap1.example1.com");
        assert_eq!(cred.port, 3890);
        assert_eq!(cred.bind_dn, "cn=admin1,dc=example1,dc=com");
        assert_eq!(cred.bind_password, "password");
        assert_eq!(cred.base_dn, "dc=example1,dc=com");
        assert_eq!(cred.user_filter, "((uid=%s))");
        assert_eq!(cred.encryption, "none");
        assert!(cred.skip_tls_verify);
        assert_eq!(cred.email_attribute, "email");
        assert_eq!(cred.name_attribute, Some("name".into()));
    }

    #[tokio::test]
    async fn test_oauth_credential() {
        let service = test_authentication_service().await;
        service
            .update_oauth_credential(UpdateOAuthCredentialInput {
                provider: OAuthProvider::Google,
                client_id: "id".into(),
                client_secret: Some("secret".into()),
            })
            .await
            .unwrap();

        let cred = service
            .read_oauth_credential(OAuthProvider::Google)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cred.provider, OAuthProvider::Google);
        assert_eq!(cred.client_id, "id");
        assert_eq!(cred.client_secret, "secret");
    }

    #[tokio::test]
    async fn test_ldap_login() {
        let service = test_authentication_service().await;
        let license = LicenseInfo {
            r#type: LicenseType::Enterprise,
            status: LicenseStatus::Ok,
            seats: 1000,
            seats_used: 0,
            issued_at: None,
            expires_at: None,
            features: None,
        };

        // Set up allowed domain for self-signup
        service
            .db
            .update_security_setting(Some("example.com".into()), false, false)
            .await
            .unwrap();

        let mut ldap_client = FakeLdapClient { state: "" };

        let response = ldap_login(
            &mut ldap_client,
            &service.db,
            &*service.setting,
            &license,
            &*service.mail,
            "user",
            "password",
        )
        .await
        .unwrap();

        assert!(!response.refresh_token.is_empty());
    }

    #[tokio::test]
    async fn test_ldap_login_not_found() {
        let service = test_authentication_service().await;
        let license = LicenseInfo {
            r#type: LicenseType::Enterprise,
            status: LicenseStatus::Ok,
            seats: 1000,
            seats_used: 0,
            issued_at: None,
            expires_at: None,
            features: None,
        };

        // Set up allowed domain for self-signup
        service
            .db
            .update_security_setting(Some("example.com".into()), false, false)
            .await
            .unwrap();

        let mut ldap_client = FakeLdapClient { state: "not_found" };

        let response = ldap_login(
            &mut ldap_client,
            &service.db,
            &*service.setting,
            &license,
            &*service.mail,
            "user",
            "password",
        )
        .await;

        assert!(response.is_err());
    }

    #[tokio::test]
    async fn test_oauth_login() {
        let service = test_authentication_service().await;
        let license = LicenseInfo {
            r#type: LicenseType::Enterprise,
            status: LicenseStatus::Ok,
            seats: 1000,
            seats_used: 0,
            issued_at: None,
            expires_at: None,
            features: None,
        };

        let client = Arc::new(TestOAuthClient {
            access_token_response: || Ok("faketoken".into()),
            user_email: "user@example.com".into(),
            user_name: "user".into(),
        });

        // Set up allowed domain for self-signup
        service
            .db
            .update_security_setting(Some("example.com".into()), false, false)
            .await
            .unwrap();

        let response = oauth_login(
            client,
            "fakecode".into(),
            &service.db,
            &*service.setting,
            &license,
            &*service.mail,
        )
        .await
        .unwrap();

        assert!(!response.access_token.is_empty());

        let client = Arc::new(TestOAuthClient {
            access_token_response: || Err(anyhow!("bad auth")),
            user_email: "user@example.com".into(),
            user_name: "user".into(),
        });

        let response = oauth_login(
            client,
            "fakecode".into(),
            &service.db,
            &*service.setting,
            &license,
            &*service.mail,
        )
        .await;

        assert!(response.is_err());
    }
}
