import type { GenericEndpointContext } from "@better-auth/core";
import type { DBTransactionAdapter } from "@better-auth/core/db/adapter";
import { APIError } from "better-auth/api";
import {
	normalizeClientCredentialsScopes,
	validateClientCredentialsScopes,
} from "./oauthClient/client-credentials";
import { schemaToOAuth } from "./register";
import type {
	OAuthOptions,
	PendingClientApprovalContext,
	SchemaClient,
	Scope,
} from "./types";
import type { GrantType } from "./types/oauth";

export interface ResolvedClientApproval {
	userId: string | null;
	referenceId: string | null;
	clientCredentialsScopes: Scope[];
}

/**
 * Asks the application whether the consenting user may approve a pending
 * client, and validates the owner and scope ceiling it returns.
 *
 * Nothing is stored here. The result is applied by
 * {@link approvePendingClient} in the same transaction as the consent.
 */
export async function resolveClientApproval(
	ctx: GenericEndpointContext,
	opts: OAuthOptions<Scope[]>,
	input: {
		client: SchemaClient<Scope[]>;
		user: PendingClientApprovalContext["user"];
		session: PendingClientApprovalContext["session"];
		scopes: Scope[];
		consentReferenceId?: string;
	},
): Promise<ResolvedClientApproval> {
	if (!opts.approvePendingClient) {
		throw new APIError("FORBIDDEN", {
			error: "access_denied",
			error_description: "client is pending approval",
		});
	}
	if (!ctx.headers) throw new APIError("BAD_REQUEST");
	const approval = await opts.approvePendingClient({
		client: { ...schemaToOAuth(input.client), client_secret: undefined },
		user: input.user,
		session: input.session,
		scopes: input.scopes,
		consentReferenceId: input.consentReferenceId,
		headers: ctx.headers,
	});
	if (!approval) {
		throw new APIError("FORBIDDEN", {
			error: "access_denied",
			error_description: "client approval was refused",
		});
	}

	const clientReference = approval.clientReference;
	if (clientReference !== undefined && clientReference.length === 0) {
		throw new APIError("INTERNAL_SERVER_ERROR", {
			error: "server_error",
			error_description:
				"approvePendingClient returned an empty clientReference",
		});
	}
	const clientCredentialsScopes = normalizeClientCredentialsScopes(
		approval.clientCredentialsScopes ?? [],
	);
	validateClientCredentialsScopes(
		clientCredentialsScopes,
		(input.client.grantTypes ?? ["authorization_code"]) as GrantType[],
		input.client.tokenEndpointAuthMethod ?? "client_secret_basic",
		opts,
	);
	return {
		userId: clientReference ? null : input.user.id,
		referenceId: clientReference ?? null,
		clientCredentialsScopes,
	};
}

/**
 * Moves a pending client to approved with its owner and scope ceiling.
 *
 * The update only matches a client that is still pending and has no owner, so
 * of any concurrent approvals exactly one wins and an owned client is never
 * reassigned. Call it inside the transaction that stores the consent so a
 * failed consent cannot leave an owned client behind.
 *
 * @throws APIError CONFLICT when the client is no longer pending or unowned.
 */
export async function approvePendingClient(
	adapter: Pick<DBTransactionAdapter, "updateMany">,
	opts: Pick<OAuthOptions<Scope[]>, "schema">,
	clientId: string,
	approval: ResolvedClientApproval,
): Promise<void> {
	const approved = await adapter.updateMany({
		model: opts.schema?.oauthClient?.modelName ?? "oauthClient",
		where: [
			{ field: "clientId", value: clientId },
			{ field: "pending", value: true },
			{ field: "userId", value: null },
			{ field: "referenceId", value: null },
		],
		update: {
			pending: false,
			userId: approval.userId,
			referenceId: approval.referenceId,
			clientCredentialsScopes: approval.clientCredentialsScopes,
			updatedAt: new Date(),
		},
	});
	if (approved !== 1) {
		throw new APIError("CONFLICT", {
			error: "access_denied",
			error_description: "client is no longer pending approval",
		});
	}
}
