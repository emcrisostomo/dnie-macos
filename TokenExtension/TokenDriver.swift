import CryptoTokenKit
import DNIeCore
import Foundation
import OSLog

final class TokenDriver: TKSmartCardTokenDriver, TKSmartCardTokenDriverDelegate {
    private static let logger = Logger(
        subsystem: "org.dniemacos.dnietoken",
        category: "lifecycle"
    )
    #if DNIE_SPARKLE_PROVIDER_CANDIDATE
    private static let providerCandidateCallbackLogger = Logger(
        subsystem: "org.dniemacos.validation.sparklefreshness",
        category: "provider-callback"
    )
    private static let providerCandidatePublicationLogger = Logger(
        subsystem: "org.dniemacos.validation.sparklefreshness",
        category: "provider-publication"
    )
    #endif

    override init() {
        super.init()
        delegate = self
        Self.logger.notice("milestone.extension.loaded")
    }

    func tokenDriver(
        _ driver: TKSmartCardTokenDriver,
        createTokenFor smartCard: TKSmartCard,
        aid AID: Data?
    ) throws -> TKSmartCardToken {
        #if DNIE_SPARKLE_PROVIDER_CANDIDATE
        Self.providerCandidateCallbackLogger.notice(
            "org.dniemacos.validation.sparklefreshness.provider-candidate-0.1.4+5-new-card"
        )
        #endif
        let supported = AID == DNIeProfile.applicationSelector
        Self.logger.notice(
            "milestone.card.detected profile_supported=\(supported, privacy: .public)"
        )
        do {
            let token = try Token(smartCard: smartCard, aid: AID, tokenDriver: driver)
            #if DNIE_SPARKLE_PROVIDER_CANDIDATE
            Self.providerCandidatePublicationLogger.notice(
                "org.dniemacos.validation.sparklefreshness.provider-candidate-0.1.4+5-published"
            )
            #endif
            Self.logger.notice("milestone.token.created")
            return token
        } catch {
            Self.logger.error("milestone.token.creation_failed")
            throw error
        }
    }
}
