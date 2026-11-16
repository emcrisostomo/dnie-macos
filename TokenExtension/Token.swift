import CryptoTokenKit
import DNIeCore
import Foundation
import OSLog
import Security

final class Token: TKSmartCardToken, TKTokenDelegate {
    private static let logger = Logger(
        subsystem: "org.dniemacos.dnietoken",
        category: "lifecycle"
    )

    init(
        smartCard: TKSmartCard,
        aid AID: Data?,
        tokenDriver: TKSmartCardTokenDriver
    ) throws {
        guard let AID, AID == DNIeProfile.applicationSelector else {
            throw NSError(
                domain: TKErrorDomain,
                code: TKError.Code.objectNotFound.rawValue
            )
        }

        let generation = ConnectionGeneration()
        let transport = SmartCardTransport(
            cardHandle: SendableSmartCardHandle(smartCard),
            generation: generation
        )
        try CommandBoundaryValidationGate.require(
            .discovery,
            cardIsValid: { smartCard.isValid },
            cancellationRequested: { !smartCard.isValid }
        )
        let discovery = try Self.waitForDiscovery(
            profile: DNIeProfile(),
            aid: AID,
            transport: transport,
            generation: generation
        )
        Self.logger.notice(
            "milestone.profile.discovered certificates=\(discovery.certificateFiles.count, privacy: .public) private_keys=\(discovery.privateKeys.count, privacy: .public)"
        )
        let catalog = try Self.makeCatalog(from: discovery)
        let excludedCount = catalog.exclusionCounts.values.reduce(0, +)
        let eligibleSigningProxyCount = catalog.identities.filter(\.canSign).count
        Self.logger.notice(
            "milestone.catalog.built identities=\(catalog.identities.count, privacy: .public) supporting_certificates=\(catalog.supportingCertificates.count, privacy: .public) excluded=\(excludedCount, privacy: .public) signing_proxies=\(eligibleSigningProxyCount, privacy: .public)"
        )
        guard let platformPlan = try PlatformTokenPlan.make(
            selectedAID: AID,
            opaqueInstanceInput: discovery.opaqueInstanceInput,
            identities: catalog.identities,
            supportingCertificates: catalog.supportingCertificates
        ) else {
            throw NSError(
                domain: TKErrorDomain,
                code: TKError.Code.objectNotFound.rawValue
            )
        }

        connectionGeneration = generation
        sessionLifecycle = TokenSessionLifecycleCoordinator(generation: generation)
        identitiesByKeyObjectID = platformPlan.identitiesByKeyObjectID
        #if SIGNATURE_CORRELATION_PROBE
        signatureCorrelationProbe = SignatureCorrelationProbe(generation: generation)
        #endif

        super.init(
            smartCard: smartCard,
            aid: AID,
            instanceID: platformPlan.instanceID,
            tokenDriver: tokenDriver
        )
        delegate = self

        guard let keychainContents else {
            throw NSError(
                domain: TKErrorDomain,
                code: TKError.Code.corruptedData.rawValue
            )
        }
        keychainContents.fill(with: platformPlan.keychainItems)
        Self.logger.notice(
            "milestone.keychain.published items=\(platformPlan.keychainItems.count, privacy: .public)"
        )
    }

    let connectionGeneration: ConnectionGeneration
    let sessionLifecycle: TokenSessionLifecycleCoordinator
    let identitiesByKeyObjectID: [Data: DNIeIdentityDescriptor]
    #if SIGNATURE_CORRELATION_PROBE
    let signatureCorrelationProbe: SignatureCorrelationProbe
    #endif

    func createSession(_ token: TKToken) throws -> TKTokenSession {
        Self.logger.notice("milestone.session.created")
        return TokenSession(token: token)
    }

    private static func waitForDiscovery(
        profile: DNIeProfile,
        aid: Data,
        transport: SmartCardTransport,
        generation: ConnectionGeneration
    ) throws -> DNIePublicDiscovery {
        let completion = DispatchSemaphore(value: 0)
        let result = BlockingResultBox<Result<DNIePublicDiscovery, Error>>()
        Task.detached {
            do {
                result.store(.success(try await profile.discover(
                    selectedApplication: aid,
                    transport: transport,
                    generation: generation
                )))
            } catch {
                result.store(.failure(error))
            }
            completion.signal()
        }
        completion.wait()
        guard let completed = result.load() else {
            throw NSError(domain: TKErrorDomain, code: TKError.Code.corruptedData.rawValue)
        }
        return try completed.get()
    }

    private static func makeCatalog(
        from discovery: DNIePublicDiscovery
    ) throws -> TokenCatalogBuildResult {
        let provenAuthenticationAlgorithms: Set<KeyAlgorithm> = [
            .rsaSignatureDigestPKCS1v15SHA256,
        ]
        var certificates: [CatalogCertificateCandidate] = []
        var publicKeysByIdentifier: [Data: Data] = [:]
        var authenticationIdentifiers: Set<Data> = []
        for discovered in discovery.certificateFiles {
            guard let role = try CertificateRoleClassifier.classify(der: discovered.file.der),
                  let certificate = SecCertificateCreateWithData(
                    nil,
                    discovered.file.der as CFData
                  ),
                  let key = SecCertificateCopyKey(certificate) else {
                continue
            }
            var error: Unmanaged<CFError>?
            guard let representation = SecKeyCopyExternalRepresentation(key, &error) as Data?
            else {
                continue
            }
            publicKeysByIdentifier[discovered.reference.ckaID] = representation
            if role == .authentication {
                authenticationIdentifiers.insert(discovered.reference.ckaID)
            }
            certificates.append(CatalogCertificateCandidate(
                reference: discovered.reference,
                certificateDER: discovered.file.der,
                role: role,
                publicKeyRepresentation: representation
            ))
        }
        let privateKeys = discovery.privateKeys.compactMap { reference in
            publicKeysByIdentifier[reference.ckaID].map {
                CatalogPrivateKeyCandidate(
                    reference: reference,
                    publicKeyRepresentation: $0,
                    constraints: authenticationIdentifiers.contains(reference.ckaID)
                        ? [.sign: authenticationConstraint]
                        : [:],
                    algorithms: authenticationIdentifiers.contains(reference.ckaID)
                        ? provenAuthenticationAlgorithms
                        : []
                )
            }
        }
        return TokenCatalogBuilder(
            instanceID: discovery.opaqueInstanceInput,
            allowedAlgorithms: provenAuthenticationAlgorithms
        ).build(certificates: certificates, privateKeys: privateKeys)
    }

    private static let authenticationConstraint = Data(
        "org.dniemacos.authentication.constraint.v1".utf8
    )
}

private final class BlockingResultBox<Value>: @unchecked Sendable {
    private let queue = DispatchQueue(label: "org.dniemacos.discovery-result")
    private var value: Value?

    func store(_ newValue: Value) {
        queue.sync { value = newValue }
    }

    func load() -> Value? {
        queue.sync { value }
    }
}
