use chrono::Utc;
use tsa_auth_core::{
    Adapter, InvitationStatus, InvitationWebhookData, MemberWebhookData, Organization,
    OrganizationInvitation, OrganizationInvitationRepository, OrganizationMember,
    OrganizationMemberRepository, OrganizationRepository, OrganizationRole,
    OrganizationWebhookData, Result, TsaError, User, UserRepository, WebhookData, WebhookEvent,
};
use tsa_auth_token::OpaqueToken;
use uuid::Uuid;

use crate::webhook::WebhookSender;
use crate::AuthCallbacks;

use super::Auth;

impl<A: Adapter, C: AuthCallbacks, W: WebhookSender> Auth<A, C, W> {
    pub async fn create_organization(
        &self,
        user_id: Uuid,
        name: &str,
        slug: &str,
    ) -> Result<(Organization, OrganizationMember)> {
        if self
            .adapter
            .organizations()
            .find_by_slug(slug)
            .await?
            .is_some()
        {
            return Err(TsaError::OrganizationAlreadyExists);
        }

        let now = Utc::now();
        let organization = Organization {
            id: Uuid::new_v4(),
            name: name.to_string(),
            slug: slug.to_lowercase(),
            logo: None,
            metadata: None,
            created_at: now,
            updated_at: now,
        };

        let organization = self.adapter.organizations().create(&organization).await?;

        let member = OrganizationMember {
            id: Uuid::new_v4(),
            organization_id: organization.id,
            user_id,
            role: OrganizationRole::Owner,
            created_at: now,
            updated_at: now,
        };

        let member = self.adapter.organization_members().create(&member).await?;

        self.send_webhook(
            WebhookEvent::OrganizationCreated,
            WebhookData::Organization(OrganizationWebhookData {
                organization_id: organization.id,
                name: organization.name.clone(),
                slug: organization.slug.clone(),
            }),
        )
        .await;

        self.send_webhook(
            WebhookEvent::MemberAdded,
            WebhookData::Member(MemberWebhookData {
                organization_id: organization.id,
                user_id,
                role: member.role.to_string(),
                previous_role: None,
            }),
        )
        .await;

        Ok((organization, member))
    }

    pub async fn get_organization(&self, organization_id: Uuid) -> Result<Organization> {
        self.adapter
            .organizations()
            .find_by_id(organization_id)
            .await?
            .ok_or(TsaError::OrganizationNotFound)
    }

    pub async fn get_organization_by_slug(&self, slug: &str) -> Result<Organization> {
        self.adapter
            .organizations()
            .find_by_slug(slug)
            .await?
            .ok_or(TsaError::OrganizationNotFound)
    }

    pub async fn update_organization(
        &self,
        user_id: Uuid,
        organization_id: Uuid,
        name: Option<String>,
        logo: Option<String>,
        metadata: Option<serde_json::Value>,
    ) -> Result<Organization> {
        self.require_org_role(
            user_id,
            organization_id,
            &[OrganizationRole::Owner, OrganizationRole::Admin],
        )
        .await?;

        let mut organization = self.get_organization(organization_id).await?;

        if let Some(name) = name {
            organization.name = name;
        }
        if let Some(logo) = logo {
            organization.logo = Some(logo);
        }
        if let Some(metadata) = metadata {
            organization.metadata = Some(metadata);
        }
        organization.updated_at = Utc::now();

        let organization = self.adapter.organizations().update(&organization).await?;

        self.send_webhook(
            WebhookEvent::OrganizationUpdated,
            WebhookData::Organization(OrganizationWebhookData {
                organization_id: organization.id,
                name: organization.name.clone(),
                slug: organization.slug.clone(),
            }),
        )
        .await;

        Ok(organization)
    }

    pub async fn delete_organization(&self, user_id: Uuid, organization_id: Uuid) -> Result<()> {
        self.require_org_role(user_id, organization_id, &[OrganizationRole::Owner])
            .await?;

        let organization = self.get_organization(organization_id).await?;

        self.adapter
            .organization_members()
            .delete_by_organization(organization_id)
            .await?;
        self.adapter.organizations().delete(organization_id).await?;

        self.send_webhook(
            WebhookEvent::OrganizationDeleted,
            WebhookData::Organization(OrganizationWebhookData {
                organization_id: organization.id,
                name: organization.name,
                slug: organization.slug,
            }),
        )
        .await;

        Ok(())
    }

    pub async fn get_user_organizations(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(Organization, OrganizationRole)>> {
        let memberships = self
            .adapter
            .organization_members()
            .find_by_user(user_id)
            .await?;
        let mut result = Vec::new();

        for membership in memberships {
            if let Some(org) = self
                .adapter
                .organizations()
                .find_by_id(membership.organization_id)
                .await?
            {
                result.push((org, membership.role));
            }
        }

        Ok(result)
    }

    pub async fn get_organization_members(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<(User, OrganizationMember)>> {
        let members = self
            .adapter
            .organization_members()
            .find_by_organization(organization_id)
            .await?;

        let mut result = Vec::new();
        for member in members {
            if let Some(user) = self.adapter.users().find_by_id(member.user_id).await? {
                result.push((user, member));
            }
        }

        Ok(result)
    }

    pub async fn add_organization_member(
        &self,
        inviter_id: Uuid,
        organization_id: Uuid,
        user_id: Uuid,
        role: OrganizationRole,
    ) -> Result<OrganizationMember> {
        self.require_org_role(
            inviter_id,
            organization_id,
            &[OrganizationRole::Owner, OrganizationRole::Admin],
        )
        .await?;

        if role == OrganizationRole::Owner {
            let inviter_member = self.get_member(inviter_id, organization_id).await?;
            if inviter_member.role != OrganizationRole::Owner {
                return Err(TsaError::InsufficientPermissions);
            }
        }

        let now = Utc::now();
        let member = OrganizationMember {
            id: Uuid::new_v4(),
            organization_id,
            user_id,
            role,
            created_at: now,
            updated_at: now,
        };

        let member = self.adapter.organization_members().create(&member).await?;

        self.send_webhook(
            WebhookEvent::MemberAdded,
            WebhookData::Member(MemberWebhookData {
                organization_id,
                user_id,
                role: member.role.to_string(),
                previous_role: None,
            }),
        )
        .await;

        Ok(member)
    }

    pub async fn update_member_role(
        &self,
        updater_id: Uuid,
        organization_id: Uuid,
        member_user_id: Uuid,
        new_role: OrganizationRole,
    ) -> Result<OrganizationMember> {
        self.require_org_role(
            updater_id,
            organization_id,
            &[OrganizationRole::Owner, OrganizationRole::Admin],
        )
        .await?;

        let updater_member = self.get_member(updater_id, organization_id).await?;
        let mut member = self.get_member(member_user_id, organization_id).await?;

        if member.role == OrganizationRole::Owner && updater_member.role != OrganizationRole::Owner
        {
            return Err(TsaError::InsufficientPermissions);
        }

        if new_role == OrganizationRole::Owner && updater_member.role != OrganizationRole::Owner {
            return Err(TsaError::InsufficientPermissions);
        }

        if member.role == OrganizationRole::Owner && new_role != OrganizationRole::Owner {
            let owners = self.count_owners(organization_id).await?;
            if owners <= 1 {
                return Err(TsaError::CannotRemoveLastOwner);
            }
        }

        let previous_role = member.role.to_string();
        member.role = new_role;
        member.updated_at = Utc::now();

        let member = self.adapter.organization_members().update(&member).await?;

        self.send_webhook(
            WebhookEvent::MemberRoleChanged,
            WebhookData::Member(MemberWebhookData {
                organization_id,
                user_id: member_user_id,
                role: member.role.to_string(),
                previous_role: Some(previous_role),
            }),
        )
        .await;

        Ok(member)
    }

    pub async fn remove_organization_member(
        &self,
        remover_id: Uuid,
        organization_id: Uuid,
        member_user_id: Uuid,
    ) -> Result<()> {
        let member = self.get_member(member_user_id, organization_id).await?;

        if remover_id == member_user_id {
            if member.role == OrganizationRole::Owner {
                let owners = self.count_owners(organization_id).await?;
                if owners <= 1 {
                    return Err(TsaError::CannotRemoveLastOwner);
                }
            }
        } else {
            self.require_org_role(
                remover_id,
                organization_id,
                &[OrganizationRole::Owner, OrganizationRole::Admin],
            )
            .await?;

            let remover_member = self.get_member(remover_id, organization_id).await?;
            if member.role == OrganizationRole::Owner
                && remover_member.role != OrganizationRole::Owner
            {
                return Err(TsaError::InsufficientPermissions);
            }
        }

        self.adapter
            .organization_members()
            .delete(member.id)
            .await?;

        self.send_webhook(
            WebhookEvent::MemberRemoved,
            WebhookData::Member(MemberWebhookData {
                organization_id,
                user_id: member_user_id,
                role: member.role.to_string(),
                previous_role: None,
            }),
        )
        .await;

        Ok(())
    }

    pub async fn invite_to_organization(
        &self,
        inviter_id: Uuid,
        organization_id: Uuid,
        email: &str,
        role: OrganizationRole,
    ) -> Result<String> {
        self.require_org_role(
            inviter_id,
            organization_id,
            &[OrganizationRole::Owner, OrganizationRole::Admin],
        )
        .await?;

        if role == OrganizationRole::Owner {
            let inviter_member = self.get_member(inviter_id, organization_id).await?;
            if inviter_member.role != OrganizationRole::Owner {
                return Err(TsaError::InsufficientPermissions);
            }
        }

        if let Some(existing) = self
            .adapter
            .organization_invitations()
            .find_pending_by_org_and_email(organization_id, email)
            .await?
        {
            self.adapter
                .organization_invitations()
                .delete(existing.id)
                .await?;
        }

        let (token, token_hash) = OpaqueToken::generate_with_hash(32)?;
        let now = Utc::now();

        let invitation = OrganizationInvitation {
            id: Uuid::new_v4(),
            organization_id,
            email: email.to_string(),
            role,
            token_hash,
            invited_by: inviter_id,
            status: InvitationStatus::Pending,
            expires_at: now + chrono::Duration::days(7),
            created_at: now,
        };

        self.adapter
            .organization_invitations()
            .create(&invitation)
            .await?;

        self.send_webhook(
            WebhookEvent::InvitationSent,
            WebhookData::Invitation(InvitationWebhookData {
                invitation_id: invitation.id,
                organization_id,
                email: email.to_string(),
                role: invitation.role.to_string(),
                inviter_id: Some(inviter_id),
            }),
        )
        .await;

        Ok(token)
    }

    pub async fn accept_invitation(
        &self,
        user_id: Uuid,
        token: &str,
    ) -> Result<OrganizationMember> {
        let token_hash = OpaqueToken::hash(token);
        let invitation = self
            .adapter
            .organization_invitations()
            .find_by_token_hash(&token_hash)
            .await?
            .ok_or(TsaError::InvitationNotFound)?;

        if invitation.status != InvitationStatus::Pending {
            return Err(TsaError::InvitationAlreadyUsed);
        }

        if invitation.expires_at < Utc::now() {
            self.adapter
                .organization_invitations()
                .update_status(invitation.id, InvitationStatus::Expired)
                .await?;
            return Err(TsaError::InvitationExpired);
        }

        let user = self
            .adapter
            .users()
            .find_by_id(user_id)
            .await?
            .ok_or(TsaError::UserNotFound)?;

        if user.email.to_lowercase() != invitation.email.to_lowercase() {
            return Err(TsaError::InvitationNotFound);
        }

        let now = Utc::now();
        let member = OrganizationMember {
            id: Uuid::new_v4(),
            organization_id: invitation.organization_id,
            user_id,
            role: invitation.role.clone(),
            created_at: now,
            updated_at: now,
        };

        let member = self.adapter.organization_members().create(&member).await?;

        self.adapter
            .organization_invitations()
            .update_status(invitation.id, InvitationStatus::Accepted)
            .await?;

        self.send_webhook(
            WebhookEvent::InvitationAccepted,
            WebhookData::Invitation(InvitationWebhookData {
                invitation_id: invitation.id,
                organization_id: invitation.organization_id,
                email: invitation.email,
                role: member.role.to_string(),
                inviter_id: Some(invitation.invited_by),
            }),
        )
        .await;

        self.send_webhook(
            WebhookEvent::MemberAdded,
            WebhookData::Member(MemberWebhookData {
                organization_id: member.organization_id,
                user_id,
                role: member.role.to_string(),
                previous_role: None,
            }),
        )
        .await;

        Ok(member)
    }

    pub async fn revoke_invitation(&self, user_id: Uuid, invitation_id: Uuid) -> Result<()> {
        let invitation = self
            .adapter
            .organization_invitations()
            .find_by_id(invitation_id)
            .await?
            .ok_or(TsaError::InvitationNotFound)?;

        self.require_org_role(
            user_id,
            invitation.organization_id,
            &[OrganizationRole::Owner, OrganizationRole::Admin],
        )
        .await?;

        self.adapter
            .organization_invitations()
            .update_status(invitation_id, InvitationStatus::Revoked)
            .await?;

        self.send_webhook(
            WebhookEvent::InvitationRevoked,
            WebhookData::Invitation(InvitationWebhookData {
                invitation_id,
                organization_id: invitation.organization_id,
                email: invitation.email,
                role: invitation.role.to_string(),
                inviter_id: Some(invitation.invited_by),
            }),
        )
        .await;

        Ok(())
    }

    pub async fn get_organization_invitations(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationInvitation>> {
        self.adapter
            .organization_invitations()
            .find_by_organization(organization_id)
            .await
    }
}
