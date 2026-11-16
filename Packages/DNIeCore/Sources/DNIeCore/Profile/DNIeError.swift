import Foundation

public enum PINVerificationResult: Sendable, Equatable {
    case accepted
    case incorrect(remainingAttempts: Int)
    case blocked
    case unknown(CardStatus)
}

public enum DNIeStatusMapper {
    public static func pinVerification(_ status: CardStatus) -> PINVerificationResult {
        switch (status.first, status.second) {
        case (0x90, 0x00):
            .accepted
        case (0x63, 0xC0 ... 0xCF):
            .incorrect(remainingAttempts: Int(status.second & 0x0F))
        case (0x69, 0x83):
            .blocked
        default:
            .unknown(status)
        }
    }
}
