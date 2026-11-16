import CryptoTokenKit
import DNIeCore
import Foundation
import OSLog

final class TokenSession: TKSmartCardTokenSession, TKTokenSessionDelegate {
    private static let logger = Logger(
        subsystem: "org.dniemacos.dnietoken",
        category: "private-operation"
    )

    private let sessionID = UUID()
    private let authorization = PINAuthorizationController()
    private let pinLease = VolatilePINLeaseStore()
    private let state = TokenSessionStateBox()

    override init(token: TKToken) {
        super.init(token: token)
        delegate = self
    }

    deinit {
        pinLease.invalidate()
        guard let token = token as? Token else { return }
        token.sessionLifecycle.cancelSession(
            sessionID: sessionID,
            generation: token.connectionGeneration
        )
    }

    func tokenSession(
        _: TKTokenSession,
        supports operation: TKTokenOperation,
        keyObjectID: TKToken.ObjectID,
        algorithm: TKTokenKeyAlgorithm
    ) -> Bool {
        guard let token = token as? Token else { return false }
        let keyKnown = TokenSessionPolicy.identity(
            keyObjectID: keyObjectID,
            identitiesByKeyObjectID: token.identitiesByKeyObjectID
        ) != nil
        let exact = algorithm.isAlgorithm(.rsaSignatureDigestPKCS1v15SHA256)
        let compatible = algorithm.supportsAlgorithm(
            .rsaSignatureDigestPKCS1v15SHA256
        )
        let raw = algorithm.isAlgorithm(.rsaSignatureRaw)
        let messagePKCS1SHA256 = algorithm.supportsAlgorithm(
            .rsaSignatureMessagePKCS1v15SHA256
        )
        let digestPSSSHA256 = algorithm.supportsAlgorithm(
            .rsaSignatureDigestPSSSHA256
        )
        let messagePSSSHA256 = algorithm.supportsAlgorithm(
            .rsaSignatureMessagePSSSHA256
        )
        let supported = TokenSessionPolicy.supports(
            operation: operation,
            keyObjectID: keyObjectID,
            algorithm: Self.negotiatedKeyAlgorithm(algorithm),
            identitiesByKeyObjectID: token.identitiesByKeyObjectID
        )
        Self.logger.notice(
            "operation.support sign=\(operation == .signData, privacy: .public) key_known=\(keyKnown, privacy: .public) exact=\(exact, privacy: .public) compatible=\(compatible, privacy: .public) raw=\(raw, privacy: .public) message_pkcs1_sha256=\(messagePKCS1SHA256, privacy: .public) digest_pss_sha256=\(digestPSSSHA256, privacy: .public) message_pss_sha256=\(messagePSSSHA256, privacy: .public) accepted=\(supported, privacy: .public)"
        )
        return supported
    }

    func tokenSession(
        _: TKTokenSession,
        beginAuthFor operation: TKTokenOperation,
        constraint: Any
    ) throws -> TKTokenAuthOperation {
        let token = token as? Token
        let constraintData = TokenSessionPolicy.constraintData(constraint)
        let identity = token.flatMap { token in
            constraintData.flatMap { constraint in
                TokenSessionPolicy.identity(
                    operation: operation,
                    constraint: constraint,
                    identitiesByKeyObjectID: token.identitiesByKeyObjectID
                )
            }
        }
        Self.logger.notice(
            "operation.auth.requested sign=\(operation == .signData, privacy: .public) constraint_data=\(constraintData != nil, privacy: .public) identity_match=\(identity != nil, privacy: .public)"
        )
        guard let token,
              let constraint = constraintData,
              identity != nil else {
            Self.logger.notice("operation.auth.rejected boundary=constraint")
            throw TokenSessionErrors.error(.badParameter)
        }

        let generation = token.connectionGeneration
        #if SIGNATURE_CORRELATION_PROBE
        let signatureCorrelationProbe = token.signatureCorrelationProbe
        #endif
        let pinLeaseBinding = VolatilePINLeaseBinding(
            sessionID: sessionID,
            generation: generation,
            constraint: constraint
        )
        let controller = authorization
        let sessionID = sessionID
        let pinLease = pinLease
        let state = state
        let lifecycle = token.sessionLifecycle
        let alreadyAuthorized = try BlockingAsync.run {
            await controller.isAuthorized(
                generation: generation,
                constraint: constraint
            )
        }
        if alreadyAuthorized,
           let context = state.current(),
           TokenSessionPolicy.contextMatches(
                expectedSessionID: sessionID,
                expectedGeneration: generation,
                actualSessionID: context.sessionID,
                actualGeneration: context.generation
           ) {
            return TKTokenAuthOperation()
        }
        if alreadyAuthorized {
            lifecycle.cancelSession(
                sessionID: sessionID,
                generation: generation
            )
            try? BlockingAsync.run {
                await controller.invalidate(generation: generation)
            }
            state.clear()
        }
        pinLease.invalidate()

        #if SIGNATURE_CORRELATION_PROBE
        let correlationAuthTicket: SignatureCorrelationAuthTicket
        do {
            correlationAuthTicket = try signatureCorrelationProbe.bindAuthentication(
                sessionID: sessionID,
                generation: generation
            )
        } catch {
            Self.logger.notice("operation.auth.rejected boundary=signature_correlation_probe")
            throw TokenSessionErrors.error(.communicationError)
        }
        #endif

        let lifecycleClaim: SessionAuthorizationClaim
        do {
            lifecycleClaim = try lifecycle.claimAuthorization(
                sessionID: sessionID,
                generation: generation
            )
        } catch {
            #if SIGNATURE_CORRELATION_PROBE
            signatureCorrelationProbe.cancelAuthentication(correlationAuthTicket)
            #endif
            if let blocker = (error as? TokenSessionLifecycleError)?
                .authorizationClaimBlocker {
                Self.logger.notice(
                    "operation.auth.rejected boundary=lifecycle blocker=\(blocker.rawValue, privacy: .public)"
                )
            } else {
                Self.logger.notice("operation.auth.rejected boundary=lifecycle")
            }
            throw TokenSessionErrors.map(error)
        }

        let credentials: VerifiedCredentialSet
        do {
            credentials = try CredentialAssetStore.loadBundledGeneration2()
        } catch {
            #if SIGNATURE_CORRELATION_PROBE
            signatureCorrelationProbe.cancelAuthentication(correlationAuthTicket)
            #endif
            try? lifecycle.cancelAuthorization(lifecycleClaim)
            Self.logger.notice("operation.auth.rejected boundary=credential_asset")
            throw TokenSessionErrors.map(error)
        }
        Self.logger.notice("operation.auth.credential_asset_verified")

        let lease: PINAuthorizationLease
        do {
            lease = try BlockingAsync.run {
                try await controller.begin(
                    generation: generation,
                    constraint: constraint
                )
            }
        } catch {
            #if SIGNATURE_CORRELATION_PROBE
            signatureCorrelationProbe.cancelAuthentication(correlationAuthTicket)
            #endif
            try? lifecycle.cancelAuthorization(lifecycleClaim)
            Self.logger.notice("operation.auth.rejected boundary=authorization_lease")
            throw TokenSessionErrors.map(error)
        }

        let cardHandle: SendableSmartCardHandle
        let transport: SmartCardTransport
        do {
            cardHandle = SendableSmartCardHandle(try getSmartCard())
            transport = SmartCardTransport(
                cardHandle: cardHandle,
                generation: generation
            )
        } catch {
            #if SIGNATURE_CORRELATION_PROBE
            signatureCorrelationProbe.cancelAuthentication(correlationAuthTicket)
            #endif
            try? BlockingAsync.run { try await controller.cancel(lease) }
            try? lifecycle.cancelAuthorization(lifecycleClaim)
            Self.logger.notice("operation.auth.rejected boundary=card_acquisition")
            throw TokenSessionErrors.map(error)
        }

        if lifecycleClaim.preparation == .recoverBeforeAuthorization {
            do {
                if let previousContext = cardHandle.card.context
                    as? DNIeSessionChannelContext
                {
                    guard previousContext.generation == generation else {
                        throw TokenSessionLifecycleError.staleGeneration
                    }
                    cardHandle.card.context = nil
                    try BlockingAsync.run {
                        await previousContext.channel.invalidate(
                            generation: previousContext.generation
                        )
                    }
                }
                state.clear()
                try BlockingAsync.run {
                    try await DNIePlainStateRecovery.execute(
                        transport: transport,
                        generation: generation
                    )
                }
                try lifecycle.completeRecovery(lifecycleClaim)
                Self.logger.notice("operation.auth.recovery completed=true")
            } catch {
                #if SIGNATURE_CORRELATION_PROBE
                signatureCorrelationProbe.cancelAuthentication(correlationAuthTicket)
                #endif
                try? BlockingAsync.run { try await controller.cancel(lease) }
                lifecycle.invalidate(generation: generation)
                try? BlockingAsync.run {
                    await transport.invalidate(generation: generation)
                }
                Self.logger.notice("operation.auth.rejected boundary=recovery")
                throw TokenSessionErrors.map(error)
            }
        }

        do {
            try lifecycle.markAuthorizationAwaitingInput(lifecycleClaim)
        } catch {
            #if SIGNATURE_CORRELATION_PROBE
            signatureCorrelationProbe.cancelAuthentication(correlationAuthTicket)
            #endif
            try? BlockingAsync.run { try await controller.cancel(lease) }
            try? lifecycle.cancelAuthorization(lifecycleClaim)
            try? BlockingAsync.run {
                await transport.invalidate(generation: generation)
            }
            Self.logger.notice("operation.auth.rejected boundary=input_readiness")
            throw TokenSessionErrors.map(error)
        }
        if lifecycleClaim.preparation == .replaceAbandonedAuthorization {
            Self.logger.notice("operation.auth.abandoned_claim_replaced=true")
        }

        Self.logger.notice("operation.auth.password_operation_created")
        return DNIePINAuthOperation(
            onCancel: {
                #if SIGNATURE_CORRELATION_PROBE
                signatureCorrelationProbe.cancelAuthentication(correlationAuthTicket)
                #endif
                pinLease.invalidate()
                try? BlockingAsync.run { try await controller.cancel(lease) }
                try? lifecycle.cancelAuthorization(lifecycleClaim)
            },
            handler: { password in
                let submittedPassword = password
                do {
                    #if SIGNATURE_CORRELATION_PROBE
                    try signatureCorrelationProbe.beginInitialVerify(
                        correlationAuthTicket
                    )
                    #endif
                    try CommandBoundaryValidationGate.require(
                        .pinVerification,
                        cardIsValid: { cardHandle.card.isValid },
                        cancellationRequested: {
                            !lifecycle.isAuthorizationAwaitingInput(lifecycleClaim)
                        }
                    )
                    try lifecycle.beginAuthorizationConsumption(lifecycleClaim)
                    cardHandle.card.isSensitive = true
                    let context = try BlockingAsync.run {
                        var passwordCopy = submittedPassword
                        defer { CryptoPrimitives.secureZero(&passwordCopy) }
                        let establisher = DNIeSecureChannelEstablisher(
                            base: transport,
                            generation: generation,
                            credentials: credentials
                        )
                        let pinChannel = try await establisher.establishPINChannel()
                        let result = try await pinChannel.verify(password: passwordCopy)
                        switch result {
                        case .accepted:
                            #if SIGNATURE_CORRELATION_PROBE
                            try signatureCorrelationProbe.completeInitialVerify(
                                correlationAuthTicket,
                                succeeded: true
                            )
                            #endif
                            let userChannel = try await establisher.establishUserChannel(
                                from: pinChannel
                            )
                            try await controller.complete(lease, result: result)
                            try lifecycle.completeAuthorization(lifecycleClaim)
                            pinLease.install(
                                credential: passwordCopy,
                                binding: pinLeaseBinding
                            )
                            return DNIeSessionChannelContext(
                                sessionID: sessionID,
                                generation: generation,
                                channel: userChannel
                            )
                        case .incorrect:
                            #if SIGNATURE_CORRELATION_PROBE
                            try? signatureCorrelationProbe.completeInitialVerify(
                                correlationAuthTicket,
                                succeeded: false
                            )
                            #endif
                            try await controller.complete(lease, result: result)
                            lifecycle.invalidate(generation: generation)
                            throw PINAuthOperationFailure.incorrect
                        case .blocked:
                            #if SIGNATURE_CORRELATION_PROBE
                            try? signatureCorrelationProbe.completeInitialVerify(
                                correlationAuthTicket,
                                succeeded: false
                            )
                            #endif
                            try await controller.complete(lease, result: result)
                            lifecycle.invalidate(generation: generation)
                            throw PINAuthOperationFailure.blocked
                        case .unknown:
                            #if SIGNATURE_CORRELATION_PROBE
                            try? signatureCorrelationProbe.completeInitialVerify(
                                correlationAuthTicket,
                                succeeded: false
                            )
                            #endif
                            try await controller.complete(lease, result: result)
                            lifecycle.invalidate(generation: generation)
                            throw TokenSessionErrors.error(.corruptedData)
                        }
                    }
                    guard cardHandle.card.isValid else {
                        pinLease.invalidate()
                        try? BlockingAsync.run {
                            await context.channel.invalidate(generation: generation)
                            await controller.invalidate(generation: generation)
                        }
                        throw TokenSessionErrors.error(.tokenNotFound)
                    }
                    cardHandle.card.context = context
                    state.install(context)
                } catch let failure as PINAuthOperationFailure {
                    #if SIGNATURE_CORRELATION_PROBE
                    signatureCorrelationProbe.cancelAuthentication(correlationAuthTicket)
                    #endif
                    pinLease.invalidate()
                    state.clear()
                    cardHandle.card.context = nil
                    throw failure
                } catch {
                    #if SIGNATURE_CORRELATION_PROBE
                    signatureCorrelationProbe.cancelAuthentication(correlationAuthTicket)
                    #endif
                    pinLease.invalidate()
                    state.clear()
                    cardHandle.card.context = nil
                    try? BlockingAsync.run {
                        await controller.invalidate(generation: generation)
                        await transport.invalidate(generation: generation)
                    }
                    lifecycle.invalidateAuthorization(lifecycleClaim)
                    throw TokenSessionErrors.map(error)
                }
            }
        )
    }

    func tokenSession(
        _: TKTokenSession,
        sign dataToSign: Data,
        keyObjectID: TKToken.ObjectID,
        algorithm: TKTokenKeyAlgorithm
    ) throws -> Data {
        let keyKnown: Bool
        if let token = token as? Token {
            keyKnown = TokenSessionPolicy.identity(
                keyObjectID: keyObjectID,
                identitiesByKeyObjectID: token.identitiesByKeyObjectID
            ) != nil
        } else {
            keyKnown = false
        }
        let exact = algorithm.isAlgorithm(.rsaSignatureDigestPKCS1v15SHA256)
        let compatible = algorithm.supportsAlgorithm(
            .rsaSignatureDigestPKCS1v15SHA256
        )
        Self.logger.notice(
            "operation.sign.requested key_known=\(keyKnown, privacy: .public) exact=\(exact, privacy: .public) compatible=\(compatible, privacy: .public) digest_shape=\(dataToSign.count == 32, privacy: .public)"
        )
        guard let token = token as? Token,
              let identity = TokenSessionPolicy.identity(
                keyObjectID: keyObjectID,
                identitiesByKeyObjectID: token.identitiesByKeyObjectID
              ),
              TokenSessionPolicy.supports(
                operation: .signData,
                keyObjectID: keyObjectID,
                algorithm: Self.exactKeyAlgorithm(algorithm),
                identitiesByKeyObjectID: token.identitiesByKeyObjectID
              ),
              dataToSign.count == 32,
              let keyReference = identity.keyReference.keyReference,
              let constraint = identity.constraints[.sign] else {
            Self.logger.notice("operation.sign.rejected boundary=request_policy")
            throw TokenSessionErrors.error(.badParameter)
        }
        let generation = token.connectionGeneration
        #if SIGNATURE_CORRELATION_PROBE
        let signatureCorrelationProbe = token.signatureCorrelationProbe
        let correlationSignTicket: SignatureCorrelationSignTicket
        do {
            correlationSignTicket = try signatureCorrelationProbe.reserveSignRequest(
                sessionID: sessionID,
                generation: generation,
                input: dataToSign
            )
        } catch {
            Self.logger.notice("operation.sign.rejected boundary=signature_correlation_probe")
            throw TokenSessionErrors.error(.communicationError)
        }
        #endif
        guard state.beginPrivateOperation() else {
            #if SIGNATURE_CORRELATION_PROBE
            signatureCorrelationProbe.fail(
                correlationSignTicket,
                reason: "session_operation_in_flight"
            )
            #endif
            throw TokenSessionErrors.error(.communicationError)
        }
        defer { state.endPrivateOperation() }

        let pinLeaseBinding = VolatilePINLeaseBinding(
            sessionID: sessionID,
            generation: generation,
            constraint: constraint
        )
        let controller = authorization
        let pinLease = pinLease
        let authorized = try BlockingAsync.run {
            await controller.isAuthorized(
                generation: generation,
                constraint: constraint
            )
        }
        guard authorized else {
            #if SIGNATURE_CORRELATION_PROBE
            do {
                try signatureCorrelationProbe.markAuthenticationNeeded(
                    correlationSignTicket
                )
            } catch {
                signatureCorrelationProbe.fail(
                    correlationSignTicket,
                    reason: "authentication_binding_failed"
                )
                throw TokenSessionErrors.error(.communicationError)
            }
            #endif
            Self.logger.notice("operation.sign.rejected boundary=authentication_needed")
            throw TokenSessionErrors.error(.authenticationNeeded)
        }
        #if SIGNATURE_CORRELATION_PROBE
        if !correlationSignTicket.isAuthenticationReplay {
            do {
                try signatureCorrelationProbe.markAuthorizedRequest(
                    correlationSignTicket
                )
            } catch {
                signatureCorrelationProbe.fail(
                    correlationSignTicket,
                    reason: "authorized_request_binding_failed"
                )
                throw TokenSessionErrors.error(.communicationError)
            }
        }
        #endif

        let lifecycle = token.sessionLifecycle
        let signLease: SessionSignLease
        do {
            signLease = try lifecycle.beginSign(
                sessionID: sessionID,
                generation: generation
            )
        } catch {
            #if SIGNATURE_CORRELATION_PROBE
            signatureCorrelationProbe.fail(
                correlationSignTicket,
                reason: "lifecycle_failed"
            )
            #endif
            Self.logger.notice("operation.sign.rejected boundary=lifecycle")
            throw TokenSessionErrors.map(error)
        }

        let cardHandle: SendableSmartCardHandle
        do {
            cardHandle = SendableSmartCardHandle(try getSmartCard())
        } catch {
            #if SIGNATURE_CORRELATION_PROBE
            signatureCorrelationProbe.fail(
                correlationSignTicket,
                reason: "card_acquisition_failed"
            )
            #endif
            try? lifecycle.completeSign(signLease, succeeded: false)
            invalidate(generation: generation, context: state.current())
            throw TokenSessionErrors.map(error)
        }
        guard let localContext = state.current(),
              let cardContext = cardHandle.card.context as? DNIeSessionChannelContext,
              localContext === cardContext,
              TokenSessionPolicy.contextMatches(
                expectedSessionID: sessionID,
                expectedGeneration: generation,
                actualSessionID: cardContext.sessionID,
                actualGeneration: cardContext.generation
              ) else {
            #if SIGNATURE_CORRELATION_PROBE
            signatureCorrelationProbe.fail(
                correlationSignTicket,
                reason: "card_context_failed"
            )
            #endif
            try? lifecycle.completeSign(signLease, succeeded: false)
            invalidate(
                generation: generation,
                cardHandle: cardHandle,
                context: state.current()
            )
            Self.logger.notice("operation.sign.rejected boundary=card_context")
            throw TokenSessionErrors.error(.authenticationNeeded)
        }

        let transport = SmartCardTransport(
            cardHandle: cardHandle,
            generation: generation
        )
        var operationContext = cardContext
        do {
            if signLease.preparation == .refreshUserChannel {
                Self.logger.notice(
                    "operation.sign.channel_preparation=reauthorize_from_volatile_lease"
                )
                #if SIGNATURE_CORRELATION_PROBE
                try signatureCorrelationProbe.beginLeaseBackedVerify(
                    correlationSignTicket
                )
                #endif
                let credentials = try CredentialAssetStore.loadBundledGeneration2()
                let refresh = try BlockingAsync.run {
                    try await pinLease.withCredential(
                        binding: pinLeaseBinding
                    ) { retainedCredential in
                        await cardContext.channel.invalidate(generation: generation)
                        let plainState = try await DNIePlainStateRecovery.synchronize(
                            transport: transport,
                            generation: generation
                        )
                        let establisher = DNIeSecureChannelEstablisher(
                            base: transport,
                            generation: generation,
                            credentials: credentials
                        )
                        let pinChannel = try await establisher.establishPINChannel()
                        let result = try await pinChannel.verify(
                            password: retainedCredential
                        )
                        guard result == .accepted else {
                            throw RetainedPINVerificationFailure(result: result)
                        }
                        #if SIGNATURE_CORRELATION_PROBE
                        try signatureCorrelationProbe.completeLeaseBackedVerify(
                            correlationSignTicket,
                            succeeded: true
                        )
                        #endif
                        let channel = try await establisher.establishUserChannel(
                            from: pinChannel
                        )
                        return (plainState, channel)
                    }
                }
                let refreshedContext = DNIeSessionChannelContext(
                    sessionID: sessionID,
                    generation: generation,
                    channel: refresh.1
                )
                cardHandle.card.context = refreshedContext
                state.install(refreshedContext)
                operationContext = refreshedContext
                let plainState = switch refresh.0 {
                case .alreadyPlain: "already_plain"
                case .channelDeactivated: "channel_deactivated"
                }
                Self.logger.notice(
                    "operation.sign.lease_reauthorization plain_state=\(plainState, privacy: .public) verify_submissions=1 result=pass"
                )
            } else {
                Self.logger.notice(
                    "operation.sign.channel_preparation=established_user_channel"
                )
                try CommandBoundaryValidationGate.require(
                    .signing,
                    cardIsValid: { cardHandle.card.isValid },
                    cancellationRequested: {
                        !lifecycle.isSignActive(signLease)
                    }
                )
            }
            #if SIGNATURE_CORRELATION_PROBE
            try signatureCorrelationProbe.beginSign(correlationSignTicket)
            #endif
            let signingContext = operationContext
            let signature = try BlockingAsync.run {
                try await signingContext.channel.rebind(
                    to: transport,
                    generation: generation
                )
                return try await DNIeSigning.signSHA256Digest(
                    dataToSign,
                    keyReference: keyReference,
                    protectedTransport: signingContext.channel,
                    generation: generation,
                    stageCompleted: { stage in
                        Self.logger.notice(
                            "operation.sign.stage_completed=\(stage.rawValue, privacy: .public)"
                        )
                    }
                )
            }
            try lifecycle.completeSign(signLease, succeeded: true)
            #if SIGNATURE_CORRELATION_PROBE
            signatureCorrelationProbe.completeSign(
                correlationSignTicket,
                succeeded: true
            )
            #endif
            Self.logger.notice("operation.sign.authorization_retained=true")
            Self.logger.notice("operation.sign.completed result=pass")
            return signature
        } catch is VolatilePINLeaseError {
            #if SIGNATURE_CORRELATION_PROBE
            signatureCorrelationProbe.completeSign(
                correlationSignTicket,
                succeeded: false
            )
            signatureCorrelationProbe.fail(
                correlationSignTicket,
                reason: "volatile_lease_unavailable"
            )
            #endif
            do {
                try lifecycle.requireReauthorization(signLease)
            } catch {
                lifecycle.invalidate(generation: generation)
                invalidate(
                    generation: generation,
                    cardHandle: cardHandle,
                    context: operationContext
                )
                throw TokenSessionErrors.map(error)
            }
            pinLease.invalidate()
            try? BlockingAsync.run {
                await controller.invalidate(generation: generation)
            }
            Self.logger.notice(
                "operation.sign.rejected boundary=volatile_lease_unavailable"
            )
            throw TokenSessionErrors.error(.authenticationNeeded)
        } catch {
            #if SIGNATURE_CORRELATION_PROBE
            signatureCorrelationProbe.completeSign(
                correlationSignTicket,
                succeeded: false
            )
            signatureCorrelationProbe.fail(
                correlationSignTicket,
                reason: "private_flow_failed"
            )
            #endif
            try? lifecycle.completeSign(signLease, succeeded: false)
            pinLease.invalidate()
            invalidate(
                generation: generation,
                cardHandle: cardHandle,
                context: operationContext
            )
            let category = TokenSessionSignFailureCategory.classify(error)
            Self.logger.notice(
                "operation.sign.completed result=fail category=\(category.rawValue, privacy: .public)"
            )
            throw TokenSessionErrors.map(error)
        }
    }

    private func invalidate(
        generation: ConnectionGeneration,
        cardHandle: SendableSmartCardHandle,
        context: DNIeSessionChannelContext?
    ) {
        if let context, cardHandle.card.context as AnyObject? === context {
            cardHandle.card.context = nil
        }
        state.clear()
        pinLease.invalidate()
        let controller = authorization
        try? BlockingAsync.run {
            if let context {
                await context.channel.invalidate(generation: generation)
            }
            await controller.invalidate(generation: generation)
        }
    }

    private func invalidate(
        generation: ConnectionGeneration,
        context: DNIeSessionChannelContext?
    ) {
        state.clear()
        pinLease.invalidate()
        let controller = authorization
        try? BlockingAsync.run {
            if let context {
                await context.channel.invalidate(generation: generation)
            }
            await controller.invalidate(generation: generation)
        }
    }

    private static func negotiatedKeyAlgorithm(
        _ algorithm: TKTokenKeyAlgorithm
    ) -> KeyAlgorithm? {
        algorithm.supportsAlgorithm(.rsaSignatureDigestPKCS1v15SHA256)
            ? .rsaSignatureDigestPKCS1v15SHA256
            : nil
    }

    private static func exactKeyAlgorithm(
        _ algorithm: TKTokenKeyAlgorithm
    ) -> KeyAlgorithm? {
        algorithm.isAlgorithm(.rsaSignatureDigestPKCS1v15SHA256)
            ? .rsaSignatureDigestPKCS1v15SHA256
            : nil
    }
}

enum TokenSessionPolicy {
    static func supports(
        operation: TKTokenOperation,
        keyObjectID: TKToken.ObjectID,
        algorithm: KeyAlgorithm?,
        identitiesByKeyObjectID: [Data: DNIeIdentityDescriptor]
    ) -> Bool {
        guard operation == .signData,
              let algorithm,
              let identity = identity(
                keyObjectID: keyObjectID,
                identitiesByKeyObjectID: identitiesByKeyObjectID
              ) else {
            return false
        }
        return IdentityOperationPolicy.supports(
            identity: identity,
            objectID: identity.objectID,
            operation: .sign,
            algorithm: algorithm
        )
    }

    static func identity(
        keyObjectID: TKToken.ObjectID,
        identitiesByKeyObjectID: [Data: DNIeIdentityDescriptor]
    ) -> DNIeIdentityDescriptor? {
        guard let keyObjectID = keyObjectID as? Data else { return nil }
        return identitiesByKeyObjectID[keyObjectID]
    }

    static func identity(
        operation: TKTokenOperation,
        constraint: Data,
        identitiesByKeyObjectID: [Data: DNIeIdentityDescriptor]
    ) -> DNIeIdentityDescriptor? {
        guard operation == .signData else { return nil }
        let matches = identitiesByKeyObjectID.values.filter {
            $0.canSign && $0.constraints[.sign] == constraint
        }
        guard matches.count == 1 else { return nil }
        return matches[0]
    }

    static func constraintData(_ constraint: Any) -> Data? {
        if let constraint = constraint as? Data {
            return constraint
        }
        if let constraint = constraint as? NSData {
            return constraint as Data
        }
        return nil
    }

    static func contextMatches(
        expectedSessionID: UUID,
        expectedGeneration: ConnectionGeneration,
        actualSessionID: UUID,
        actualGeneration: ConnectionGeneration
    ) -> Bool {
        expectedSessionID == actualSessionID
            && expectedGeneration == actualGeneration
    }
}

enum SessionAuthorizationPreparation: Sendable, Equatable {
    case initial
    case recoverBeforeAuthorization
    case replaceAbandonedAuthorization
}

struct SessionAuthorizationClaim: Hashable, Sendable {
    let id: UUID
    let sessionID: UUID
    let generation: ConnectionGeneration
    let preparation: SessionAuthorizationPreparation
}

struct SessionSignLease: Hashable, Sendable {
    let id: UUID
    let sessionID: UUID
    let generation: ConnectionGeneration
    let preparation: SessionSignPreparation
}

enum SessionSignPreparation: Hashable, Sendable {
    case useEstablishedChannel
    case refreshUserChannel
}

enum TokenSessionLifecycleSnapshot: Sendable, Equatable {
    case publicReady
    case authPending(SessionAuthorizationPreparation)
    case authorized
    case signing
    case recoveryRequired
    case invalid
}

enum AuthorizationClaimBlocker: String, Sendable, Equatable {
    case staleGeneration = "stale_generation"
    case invalid
    case authorizationPreparing = "authorization_preparing"
    case authorizationAwaitingInput = "authorization_awaiting_input"
    case authorizationConsuming = "authorization_consuming"
    case authorizedSession = "authorized_session"
    case activeSign = "active_sign"
}

enum TokenSessionLifecycleError: Error, Sendable, Equatable {
    case staleGeneration
    case operationInFlight
    case staleCallback
    case invalidState
    case authorizationClaimRejected(AuthorizationClaimBlocker)

    var authorizationClaimBlocker: AuthorizationClaimBlocker? {
        guard case let .authorizationClaimRejected(blocker) = self else {
            return nil
        }
        return blocker
    }
}

final class TokenSessionLifecycleCoordinator: @unchecked Sendable {
    private struct ActiveAuthorization {
        let claim: SessionAuthorizationClaim
        var recoveryCompleted: Bool
        var awaitingInputSince: ContinuousClock.Instant?
        var consumingCredential = false
    }

    private static let abandonedAuthorizationTimeout: Duration = .seconds(300)
    private let lock = NSLock()
    private let generation: ConnectionGeneration
    private var activeAuthorization: ActiveAuthorization?
    private var authorizedSessionID: UUID?
    private var authorizedClaimID: UUID?
    private var activeSign: SessionSignLease?
    private var successfulSignCount = 0
    private var recoveryRequired = false
    private var invalid = false

    init(generation: ConnectionGeneration) {
        self.generation = generation
    }

    func claimAuthorization(
        sessionID: UUID,
        generation expected: ConnectionGeneration,
        now: ContinuousClock.Instant = ContinuousClock().now
    ) throws -> SessionAuthorizationClaim {
        lock.lock()
        defer { lock.unlock() }
        guard generation == expected else {
            throw TokenSessionLifecycleError.authorizationClaimRejected(
                .staleGeneration
            )
        }
        guard !invalid else {
            throw TokenSessionLifecycleError.authorizationClaimRejected(.invalid)
        }
        let replacedAbandonedAuthorization = expireAbandonedAuthorization(
            now: now
        )
        retireIdleForeignAuthorizedOwner(sessionID: sessionID)
        if let blocker = authorizationClaimBlocker() {
            throw TokenSessionLifecycleError.authorizationClaimRejected(blocker)
        }
        let preparation: SessionAuthorizationPreparation
        if recoveryRequired {
            preparation = .recoverBeforeAuthorization
        } else if replacedAbandonedAuthorization {
            preparation = .replaceAbandonedAuthorization
        } else {
            preparation = .initial
        }
        let claim = SessionAuthorizationClaim(
            id: UUID(),
            sessionID: sessionID,
            generation: expected,
            preparation: preparation
        )
        activeAuthorization = ActiveAuthorization(
            claim: claim,
            recoveryCompleted: preparation != .recoverBeforeAuthorization,
            awaitingInputSince: nil
        )
        return claim
    }

    func markAuthorizationAwaitingInput(
        _ claim: SessionAuthorizationClaim,
        now: ContinuousClock.Instant = ContinuousClock().now
    ) throws {
        lock.lock()
        defer { lock.unlock() }
        try requireCurrent(claim.generation)
        guard var active = activeAuthorization,
              active.claim == claim else {
            throw TokenSessionLifecycleError.staleCallback
        }
        guard active.recoveryCompleted,
              active.awaitingInputSince == nil else {
            throw TokenSessionLifecycleError.invalidState
        }
        active.awaitingInputSince = now
        activeAuthorization = active
    }

    func beginAuthorizationConsumption(
        _ claim: SessionAuthorizationClaim
    ) throws {
        lock.lock()
        defer { lock.unlock() }
        try requireCurrent(claim.generation)
        guard var active = activeAuthorization,
              active.claim == claim else {
            throw TokenSessionLifecycleError.staleCallback
        }
        guard active.recoveryCompleted,
              active.awaitingInputSince != nil else {
            throw TokenSessionLifecycleError.invalidState
        }
        active.awaitingInputSince = nil
        active.consumingCredential = true
        activeAuthorization = active
    }

    func completeRecovery(_ claim: SessionAuthorizationClaim) throws {
        lock.lock()
        defer { lock.unlock() }
        try requireCurrent(claim.generation)
        guard var active = activeAuthorization,
              active.claim == claim else {
            throw TokenSessionLifecycleError.staleCallback
        }
        guard claim.preparation == .recoverBeforeAuthorization,
              recoveryRequired else {
            throw TokenSessionLifecycleError.invalidState
        }
        active.recoveryCompleted = true
        activeAuthorization = active
        recoveryRequired = false
    }

    func validateAuthorization(_ claim: SessionAuthorizationClaim) throws {
        lock.lock()
        defer { lock.unlock() }
        try requireCurrent(claim.generation)
        guard activeAuthorization?.claim == claim else {
            throw TokenSessionLifecycleError.staleCallback
        }
    }

    /// Synchronous CryptoTokenKit callbacks have no Swift Task cancellation context. This is the
    /// provider-owned predicate used by the validation-only PIN boundary while it awaits input.
    func isAuthorizationAwaitingInput(_ claim: SessionAuthorizationClaim) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard generation == claim.generation,
              !invalid,
              let active = activeAuthorization,
              active.claim == claim else {
            return false
        }
        return active.awaitingInputSince != nil && !active.consumingCredential
    }

    func completeAuthorization(_ claim: SessionAuthorizationClaim) throws {
        lock.lock()
        defer { lock.unlock() }
        try requireCurrent(claim.generation)
        guard let active = activeAuthorization,
              active.claim == claim else {
            throw TokenSessionLifecycleError.staleCallback
        }
        guard active.recoveryCompleted else {
            throw TokenSessionLifecycleError.invalidState
        }
        activeAuthorization = nil
        authorizedSessionID = claim.sessionID
        authorizedClaimID = claim.id
        successfulSignCount = 0
    }

    func cancelAuthorization(_ claim: SessionAuthorizationClaim) throws {
        lock.lock()
        defer { lock.unlock() }
        try requireCurrent(claim.generation)
        guard activeAuthorization?.claim == claim else {
            throw TokenSessionLifecycleError.staleCallback
        }
        activeAuthorization = nil
    }

    func invalidateAuthorization(_ claim: SessionAuthorizationClaim) {
        lock.lock()
        defer { lock.unlock() }
        guard generation == claim.generation, !invalid else { return }
        let ownsPendingAuthorization = activeAuthorization?.claim == claim
        let ownsCompletedAuthorization = authorizedClaimID == claim.id
            && authorizedSessionID == claim.sessionID
        guard ownsPendingAuthorization || ownsCompletedAuthorization else {
            return
        }
        activeAuthorization = nil
        authorizedSessionID = nil
        authorizedClaimID = nil
        activeSign = nil
        recoveryRequired = false
        invalid = true
    }

    func beginSign(
        sessionID: UUID,
        generation expected: ConnectionGeneration
    ) throws -> SessionSignLease {
        lock.lock()
        defer { lock.unlock() }
        try requireCurrent(expected)
        guard activeSign == nil, activeAuthorization == nil else {
            throw TokenSessionLifecycleError.operationInFlight
        }
        guard authorizedSessionID == sessionID else {
            throw TokenSessionLifecycleError.invalidState
        }
        let lease = SessionSignLease(
            id: UUID(),
            sessionID: sessionID,
            generation: expected,
            preparation: successfulSignCount == 0
                ? .useEstablishedChannel
                : .refreshUserChannel
        )
        activeSign = lease
        return lease
    }

    /// The validation-only first-sign boundary must stop if its provider-owned lease is no
    /// longer current, including session cancellation or lifecycle invalidation.
    func isSignActive(_ lease: SessionSignLease) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return generation == lease.generation && !invalid && activeSign == lease
    }

    func completeSign(_ lease: SessionSignLease, succeeded: Bool) throws {
        lock.lock()
        defer { lock.unlock() }
        try requireCurrent(lease.generation)
        guard activeSign == lease else {
            throw TokenSessionLifecycleError.staleCallback
        }
        activeSign = nil
        if succeeded {
            successfulSignCount += 1
        } else {
            authorizedSessionID = nil
            authorizedClaimID = nil
            successfulSignCount = 0
            invalid = true
            recoveryRequired = false
        }
    }

    func requireReauthorization(_ lease: SessionSignLease) throws {
        lock.lock()
        defer { lock.unlock() }
        try requireCurrent(lease.generation)
        guard activeSign == lease else {
            throw TokenSessionLifecycleError.staleCallback
        }
        activeSign = nil
        authorizedSessionID = nil
        authorizedClaimID = nil
        successfulSignCount = 0
        recoveryRequired = true
    }

    func cancelSession(
        sessionID: UUID,
        generation expected: ConnectionGeneration
    ) {
        lock.lock()
        defer { lock.unlock() }
        guard generation == expected, !invalid else { return }
        if activeAuthorization?.claim.sessionID == sessionID {
            activeAuthorization = nil
        }
        if authorizedSessionID == sessionID {
            authorizedSessionID = nil
            authorizedClaimID = nil
            successfulSignCount = 0
            recoveryRequired = true
        }
        if activeSign?.sessionID == sessionID {
            activeSign = nil
            recoveryRequired = false
            invalid = true
        }
    }

    func invalidate(generation expected: ConnectionGeneration) {
        lock.lock()
        defer { lock.unlock() }
        guard generation == expected else { return }
        activeAuthorization = nil
        authorizedSessionID = nil
        authorizedClaimID = nil
        activeSign = nil
        successfulSignCount = 0
        recoveryRequired = false
        invalid = true
    }

    func snapshot() -> TokenSessionLifecycleSnapshot {
        lock.lock()
        defer { lock.unlock() }
        if invalid { return .invalid }
        if let activeAuthorization {
            return .authPending(activeAuthorization.claim.preparation)
        }
        if activeSign != nil { return .signing }
        if authorizedSessionID != nil { return .authorized }
        if recoveryRequired { return .recoveryRequired }
        return .publicReady
    }

    private func requireCurrent(_ expected: ConnectionGeneration) throws {
        guard generation == expected else {
            throw TokenSessionLifecycleError.staleGeneration
        }
        guard !invalid else {
            throw TokenSessionLifecycleError.invalidState
        }
    }

    private func expireAbandonedAuthorization(
        now: ContinuousClock.Instant
    ) -> Bool {
        guard let active = activeAuthorization,
              let awaitingInputSince = active.awaitingInputSince,
              awaitingInputSince.duration(to: now)
                >= Self.abandonedAuthorizationTimeout else {
            return false
        }
        activeAuthorization = nil
        return true
    }

    private func authorizationClaimBlocker() -> AuthorizationClaimBlocker? {
        if let activeAuthorization {
            if activeAuthorization.awaitingInputSince != nil {
                return .authorizationAwaitingInput
            }
            if activeAuthorization.consumingCredential {
                return .authorizationConsuming
            }
            return .authorizationPreparing
        }
        if activeSign != nil { return .activeSign }
        if authorizedSessionID != nil { return .authorizedSession }
        return nil
    }

    private func retireIdleForeignAuthorizedOwner(sessionID: UUID) {
        guard activeAuthorization == nil,
              activeSign == nil,
              let authorizedSessionID,
              authorizedSessionID != sessionID,
              successfulSignCount > 0 else {
            return
        }
        self.authorizedSessionID = nil
        authorizedClaimID = nil
        successfulSignCount = 0
        recoveryRequired = true
    }
}

private final class DNIeSessionChannelContext: NSObject, @unchecked Sendable {
    let sessionID: UUID
    let generation: ConnectionGeneration
    let channel: DNIeUserSecureChannelTransport

    init(
        sessionID: UUID,
        generation: ConnectionGeneration,
        channel: DNIeUserSecureChannelTransport
    ) {
        self.sessionID = sessionID
        self.generation = generation
        self.channel = channel
    }
}

private final class TokenSessionStateBox: @unchecked Sendable {
    private let lock = NSLock()
    private var context: DNIeSessionChannelContext?
    private var privateOperationInFlight = false

    func install(_ context: DNIeSessionChannelContext) {
        lock.lock()
        self.context = context
        lock.unlock()
    }

    func current() -> DNIeSessionChannelContext? {
        lock.lock()
        defer { lock.unlock() }
        return context
    }

    func clear() {
        lock.lock()
        context = nil
        lock.unlock()
    }

    func beginPrivateOperation() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !privateOperationInFlight else { return false }
        privateOperationInFlight = true
        return true
    }

    func endPrivateOperation() {
        lock.lock()
        privateOperationInFlight = false
        lock.unlock()
    }
}

enum TokenSessionSignFailureCategory: String, Sendable, Equatable {
    case transport
    case channelRequest
    case channelResponse
    case channelAuthentication
    case channelState
    case channelOuterStatus
    case channelInnerStatus
    case plainState
    case channelEstablishment
    case credentialAsset
    case profile
    case cryptography
    case unknown

    static func classify(_ error: Error) -> Self {
        if error is CardTransportError { return .transport }
        if let channel = error as? SecureChannelTransportError {
            return switch channel {
            case .invalidRequest: .channelRequest
            case .invalidResponse: .channelResponse
            case .invalidAuthentication: .channelAuthentication
            case .destroyedState: .channelState
            case .outerStatus: .channelOuterStatus
            case .innerStatus: .channelInnerStatus
            }
        }
        if error is PlainStateRecoveryError { return .plainState }
        if error is SecureChannelEstablishmentError { return .channelEstablishment }
        if error is CredentialAssetError { return .credentialAsset }
        if error is DNIeSigningError { return .profile }
        if error is CryptoPrimitiveError { return .cryptography }
        return .unknown
    }
}

private struct RetainedPINVerificationFailure: Error, Sendable {
    let result: PINVerificationResult
}

private enum TokenSessionErrors {
    static func error(_ code: TKError.Code) -> NSError {
        NSError(domain: TKErrorDomain, code: code.rawValue)
    }

    static func map(_ source: Error) -> NSError {
        let nsError = source as NSError
        if nsError.domain == TKErrorDomain {
            return nsError
        }
        if source is CredentialAssetError {
            return error(.notImplemented)
        }
        if let transport = source as? CardTransportError {
            switch transport {
            case .staleGeneration, .cardInvalid, .removed:
                return error(.tokenNotFound)
            default:
                return error(.communicationError)
            }
        }
        if source is PINAuthorizationError {
            return error(.corruptedData)
        }
        if let lifecycle = source as? TokenSessionLifecycleError {
            switch lifecycle {
            case .staleGeneration:
                return error(.tokenNotFound)
            case .operationInFlight:
                return error(.communicationError)
            case .staleCallback, .invalidState:
                return error(.communicationError)
            case .authorizationClaimRejected(.staleGeneration):
                return error(.tokenNotFound)
            case .authorizationClaimRejected:
                return error(.communicationError)
            }
        }
        if source is PlainStateRecoveryError {
            return error(.corruptedData)
        }
        if source is DNIeSigningError {
            return error(.corruptedData)
        }
        return error(.corruptedData)
    }
}

private final class BlockingAsyncBox<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<Value, any Error>?

    func store(_ result: Result<Value, any Error>) {
        lock.lock()
        self.result = result
        lock.unlock()
    }

    func load() -> Result<Value, any Error>? {
        lock.lock()
        defer { lock.unlock() }
        return result
    }
}

enum BlockingAsync {
    private static let defaultTimeoutNanoseconds: UInt64 = 30_000_000_000

    static func run<Value: Sendable>(
        timeoutNanoseconds: UInt64 = defaultTimeoutNanoseconds,
        _ operation: @escaping @Sendable () async throws -> Value
    ) throws -> Value {
        let semaphore = DispatchSemaphore(value: 0)
        let box = BlockingAsyncBox<Value>()
        let task = Task.detached {
            do {
                box.store(.success(try await operation()))
            } catch {
                box.store(.failure(error))
            }
            semaphore.signal()
        }
        let boundedTimeout = min(timeoutNanoseconds, UInt64(Int.max))
        guard semaphore.wait(
            timeout: .now() + .nanoseconds(Int(boundedTimeout))
        ) == .success else {
            task.cancel()
            throw TokenSessionErrors.error(.communicationError)
        }
        guard let result = box.load() else {
            throw TokenSessionErrors.error(.corruptedData)
        }
        return try result.get()
    }
}
