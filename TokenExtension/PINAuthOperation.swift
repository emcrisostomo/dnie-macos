import CryptoTokenKit
import DNIeCore
import Foundation

enum PINAuthOperationFailure: Error, Sendable, Equatable {
    case incorrect
    case blocked
}

struct VolatilePINLeaseBinding: Hashable, Sendable {
    let sessionID: UUID
    let generation: ConnectionGeneration
    let constraint: Data
}

enum VolatilePINLeaseError: Error, Sendable, Equatable {
    case unavailable
}

enum VolatilePINLeaseSnapshot: Sendable, Equatable {
    case empty
    case available
}

/// A memory-only bridge between repeated private operations in one CryptoTokenKit session.
/// Every use supplies the credential to one fresh protected VERIFY; no value leaves this type
/// except as a working buffer that is zeroized when `withCredential` returns.
final class VolatilePINLeaseStore: @unchecked Sendable {
    static let productionLifetime: Duration = .seconds(60)

    private let lock = NSLock()
    private let lifetime: Duration
    private var credential = Data()
    private var binding: VolatilePINLeaseBinding?
    private var deadline: ContinuousClock.Instant?
    private var leaseID: UUID?
    private var expirationTask: Task<Void, Never>?

    init(lifetime: Duration = productionLifetime) {
        self.lifetime = lifetime
    }

    deinit {
        invalidate()
    }

    func install(
        credential source: Data,
        binding: VolatilePINLeaseBinding,
        now: ContinuousClock.Instant = ContinuousClock().now
    ) {
        lock.lock()
        clearLocked()
        guard !source.isEmpty else {
            lock.unlock()
            return
        }
        credential = source
        self.binding = binding
        deadline = now.advanced(by: lifetime)
        let installedLeaseID = UUID()
        leaseID = installedLeaseID
        expirationTask = Task { [weak self, lifetime] in
            try? await Task<Never, Never>.sleep(for: lifetime)
            guard !Task.isCancelled else { return }
            self?.expire(leaseID: installedLeaseID)
        }
        lock.unlock()
    }

    func withCredential<Value: Sendable>(
        binding expectedBinding: VolatilePINLeaseBinding,
        now: ContinuousClock.Instant = ContinuousClock().now,
        operation: @escaping @Sendable (Data) async throws -> Value
    ) async throws -> Value {
        var workingCredential = try copyCredential(
            binding: expectedBinding,
            now: now
        )
        defer { CryptoPrimitives.secureZero(&workingCredential) }
        return try await operation(workingCredential)
    }

    func invalidate() {
        lock.lock()
        clearLocked()
        lock.unlock()
    }

    func snapshot(
        now: ContinuousClock.Instant = ContinuousClock().now
    ) -> VolatilePINLeaseSnapshot {
        lock.lock()
        defer { lock.unlock() }
        guard let deadline, now < deadline, binding != nil, !credential.isEmpty else {
            clearLocked()
            return .empty
        }
        return .available
    }

    private func expire(leaseID expectedLeaseID: UUID) {
        lock.lock()
        defer { lock.unlock() }
        guard leaseID == expectedLeaseID else { return }
        clearLocked()
    }

    private func copyCredential(
        binding expectedBinding: VolatilePINLeaseBinding,
        now: ContinuousClock.Instant
    ) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        guard let binding,
              let deadline,
              binding == expectedBinding,
              now < deadline,
              !credential.isEmpty else {
            clearLocked()
            throw VolatilePINLeaseError.unavailable
        }
        return credential
    }

    private func clearLocked() {
        expirationTask?.cancel()
        expirationTask = nil
        CryptoPrimitives.secureZero(&credential)
        binding = nil
        deadline = nil
        leaseID = nil
    }
}

final class DNIePINAuthOperation: TKTokenPasswordAuthOperation {
    typealias Handler = (inout Data) throws -> Void

    private let onCancel: () -> Void
    private let handler: Handler
    private let stateLock = NSLock()
    private var hasFinished = false

    init(
        onCancel: @escaping () -> Void = {},
        handler: @escaping Handler
    ) {
        self.onCancel = onCancel
        self.handler = handler
        super.init()
    }

    required init?(coder _: NSCoder) {
        nil
    }

    override func finish() throws {
        stateLock.lock()
        let mayFinish = !hasFinished
        hasFinished = true
        stateLock.unlock()
        guard mayFinish else {
            throw tokenError(.corruptedData)
        }
        guard password != nil else {
            password = nil
            onCancel()
            throw tokenError(.canceledByUser)
        }

        var passwordBytes = autoreleasepool { () -> Data in
            let bytes = password.map { Data($0.utf8) } ?? Data()
            password = nil
            return bytes
        }
        defer { CryptoPrimitives.secureZero(&passwordBytes) }

        do {
            try handler(&passwordBytes)
        } catch is CommandBoundaryGateError {
            throw tokenError(.communicationError)
        } catch let failure as PINAuthOperationFailure {
            switch failure {
            case .incorrect, .blocked:
                throw tokenError(.authenticationFailed)
            }
        } catch let error as NSError where error.domain == TKErrorDomain {
            throw error
        } catch is CardTransportError {
            throw tokenError(.communicationError)
        } catch {
            throw tokenError(.corruptedData)
        }
    }

    private func tokenError(_ code: TKError.Code) -> NSError {
        NSError(domain: TKErrorDomain, code: code.rawValue)
    }
}
