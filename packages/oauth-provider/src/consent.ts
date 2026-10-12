import type { GenericEndpointContext } from "@better-auth/core";
import {
	getCurrentAdapter,
	runWithTransaction,
} from "@better-auth/core/context";
import { APIError, getSessionFromCtx } from "better-auth/api";
import { formatErrorURL, getIssuer } from "./authorize";
import {
	filterClaimsRequestUserInfoClaims,
	getRequestedUserInfoClaims,
} from "./claims-request";
import { resolveClientApproval, storeClientApproval } from "./client-approval";
import type { AuthorizeEndpointCaller } from "./continue";
import { oAuthState } from "./oauth";
import { getSupportedClaims } from "./standard-claims";
import type { OAuthConsent, OAuthOptions, SchemaClient, Scope } from "./types";
import {
	isSessionFreshForSignedQuery,
	parsePrompt,
	removeMaxAgeFromQuery,
	removePromptFromQuery,
	searchParamsToQuery,
} from "./utils";

export async function consentEndpoint<Result>(
	ctx: GenericEndpointContext,
	opts: OAuthOptions<Scope[]>,
	authorize: AuthorizeEndpointCaller<Result>,
) {
	// Obtain oauth query
	const oauthRequest = await oAuthState.get();
	const _query = oauthRequest?.query as string | undefined;
	if (!_query) {
		throw new APIError("BAD_REQUEST", {
			error_description: "missing oauth query",
			error: "invalid_request",
		});
	}
	const query = new URLSearchParams(_query);
	const originalRequestedScopes = query.get("scope")?.split(" ") ?? [];
	const supportedClaims = getSupportedClaims(opts);
	const originalRequestedUserInfoClaims = getRequestedUserInfoClaims(
		query.get("claims"),
		supportedClaims,
	);
	const clientId = query.get("client_id");
	if (!clientId) {
		throw new APIError("BAD_REQUEST", {
			error_description: "client_id is required",
			error: "invalid_client",
		});
	}

	// Check scopes if received (can only be equal or lesser than originally requested scopes)
	const requestedScopes = (ctx.body.scope as string | undefined)?.split(" ");
	if (requestedScopes) {
		if (!requestedScopes.every((sc) => originalRequestedScopes?.includes(sc))) {
			throw new APIError("BAD_REQUEST", {
				error_description: "Scope not originally requested",
				error: "invalid_request",
			});
		}
	}
	const acceptedClaims = ctx.body.claims as unknown | undefined;
	const acceptedUserInfoClaims =
		acceptedClaims !== undefined
			? getRequestedUserInfoClaims(acceptedClaims, supportedClaims)
			: originalRequestedUserInfoClaims;
	if (
		acceptedClaims !== undefined &&
		!acceptedUserInfoClaims.every((claim) =>
			originalRequestedUserInfoClaims.includes(claim),
		)
	) {
		throw new APIError("BAD_REQUEST", {
			error_description: "Claim not originally requested",
			error: "invalid_request",
		});
	}

	// Consent not accepted (ensure it's strictly boolean true)
	const accepted = ctx.body.accept === true;
	if (!accepted) {
		return {
			redirect: true,
			url: formatErrorURL(
				query.get("redirect_uri") ?? "",
				"access_denied",
				"User denied access",
				query.get("state") ?? undefined,
				getIssuer(ctx, opts),
			),
		};
	}

	// Consent accepted
	const session = await getSessionFromCtx(ctx);
	const promptSet = parsePrompt(query.get("prompt") ?? "");
	const hasLoginPrompt = promptSet.has("login");
	const hasSatisfiedLoginPrompt =
		hasLoginPrompt &&
		isSessionFreshForSignedQuery(
			session?.session.createdAt,
			oauthRequest?.signedQueryIssuedAt,
		);
	if (hasLoginPrompt && !hasSatisfiedLoginPrompt) {
		ctx?.headers?.set("accept", "application/json");
		ctx.query = searchParamsToQuery(query);
		return await authorize(ctx);
	}

	const referenceId = await opts.postLogin?.consentReferenceId?.({
		user: session?.user!,
		session: session?.session!,
		scopes: requestedScopes ?? originalRequestedScopes,
	});
	const consentScopes = requestedScopes ?? originalRequestedScopes;
	// Read the stored row: approval state lives there, and resolving a
	// discovered client could fetch its metadata on every consent.
	const pendingClient = opts.approvePendingClient
		? await ctx.context.adapter.findOne<SchemaClient<Scope[]>>({
				model: opts.schema?.oauthClient?.modelName ?? "oauthClient",
				where: [{ field: "clientId", value: clientId }],
			})
		: null;
	const approval = pendingClient?.pending
		? await resolveClientApproval(ctx, opts, {
				client: pendingClient,
				user: session?.user!,
				session: session?.session!,
				scopes: consentScopes,
				consentReferenceId: referenceId,
			})
		: undefined;
	const foundConsent = await ctx.context.adapter.findOne<OAuthConsent<Scope[]>>(
		{
			model: "oauthConsent",
			where: [
				{
					field: "clientId",
					value: clientId,
				},
				{
					field: "userId",
					value: session?.user.id!,
				},
				...(referenceId
					? [
							{
								field: "referenceId",
								value: referenceId,
							},
						]
					: []),
			],
		},
	);
	const iat = Math.floor(Date.now() / 1000);
	const resource = query.getAll("resource");
	const consent: Omit<OAuthConsent<Scope[]>, "id"> = {
		clientId: clientId,
		userId: session?.user.id!,
		scopes: consentScopes,
		requestedUserInfoClaims: acceptedUserInfoClaims,
		createdAt: new Date(iat * 1000),
		updatedAt: new Date(iat * 1000),
		resources: resource.length ? resource : undefined,
		referenceId,
	};
	const storeConsent = async (
		adapter: Pick<typeof ctx.context.adapter, "create" | "update">,
	) => {
		foundConsent?.id
			? await adapter.update({
					model: "oauthConsent",
					where: [
						{
							field: "id",
							value: foundConsent.id,
						},
					],
					update: {
						resources: consent.resources,
						scopes: consent.scopes,
						requestedUserInfoClaims: consent.requestedUserInfoClaims,
						updatedAt: new Date(iat * 1000),
					},
				})
			: await adapter.create({
					model: "oauthConsent",
					data: {
						...consent,
						scopes: consent.scopes,
					},
				});
	};
	if (approval && pendingClient) {
		// The owner, the ceiling, and the consent succeed or fail together.
		await runWithTransaction(ctx.context.adapter, async () => {
			const adapter = await getCurrentAdapter(ctx.context.adapter);
			await storeClientApproval(
				adapter,
				opts,
				pendingClient.clientId,
				approval,
			);
			await storeConsent(adapter);
		});
	} else {
		await storeConsent(ctx.context.adapter);
	}

	// Return authorization code
	if (requestedScopes) {
		query.set("scope", consent.scopes.join(" "));
	}
	if (acceptedClaims !== undefined) {
		const claimsRequest = filterClaimsRequestUserInfoClaims(
			query.get("claims"),
			acceptedUserInfoClaims,
		);
		if (claimsRequest) {
			query.set("claims", JSON.stringify(claimsRequest));
		} else {
			query.delete("claims");
		}
	}
	ctx?.headers?.set("accept", "application/json");
	let authorizationQuery = removePromptFromQuery(query, "consent");
	if (hasSatisfiedLoginPrompt) {
		authorizationQuery = removePromptFromQuery(authorizationQuery, "login");
		authorizationQuery = removeMaxAgeFromQuery(authorizationQuery);
	}
	ctx.query = searchParamsToQuery(authorizationQuery);
	const postLoginClearedForThisSession =
		oauthRequest?.postLoginClearedForSession !== undefined &&
		oauthRequest.postLoginClearedForSession === session?.session.id;
	return await authorize(ctx, {
		postLogin: postLoginClearedForThisSession,
	});
}
