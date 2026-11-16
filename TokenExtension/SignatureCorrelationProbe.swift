#if SIGNATURE_CORRELATION_PROBE
import DNIeCore
import Foundation
import OSLog

enum SignatureCorrelationProbeError: Error, Sendable, Equatable {
    case staleScope
    case operationInFlight
    case missingAuthenticationRequest
    case replayMismatch
    case budgetExhausted
    case staleTicket
    case invalidTransition
    case scopeFailed
    case tornDown
}

enum SignatureCorrelationInputEquality: String, Sendable, Equatable {
    case first
    case authenticationReplay = "authentication_replay"
    case distinctPrevious = "distinct_previous"
    case duplicatePrevious = "duplicate_previous"
}

struct SignatureCorrelationSignTicket: Hashable, Sendable {
    fileprivate let id: UUID
    let flowOrdinal: Int
    let requestOrdinal: Int
    let equality: SignatureCorrelationInputEquality
    let isAuthenticationReplay: Bool
}

struct SignatureCorrelationAuthTicket: Hashable, Sendable {
    fileprivate let flowID: UUID
    let flowOrdinal: Int
}

enum SignatureCorrelationFlowPhase: String, Sendable, Equatable {
    case reserved
    case authenticationNeeded = "authentication_needed"
    case authenticationBound = "authentication_bound"
    case initialVerifyStarted = "initial_verify_started"
    case awaitingReplay = "awaiting_replay"
    case readyToSign = "ready_to_sign"
    case leaseVerifyStarted = "lease_verify_started"
    case signStarted = "sign_started"
    case completed
    case failed

    fileprivate var isTerminal: Bool {
        self == .completed || self == .failed
    }
}

struct SignatureCorrelationProbeSnapshot: Sendable, Equatable {
    struct Flow: Sendable, Equatable {
        let ordinal: Int
        let phase: SignatureCorrelationFlowPhase
        let initialVerifyStarted: Bool
        let leaseVerifyStarted: Bool
        let signStarted: Bool
    }

    let flows: [Flow]
    let requestCount: Int
    let retainedInputCount: Int
    let scopeFailed: Bool
    let tornDown: Bool
}

/// Validation-only fencing and categorical observation for one token generation.
///
/// The budget counts complete protected signing flows, not individual APDUs. A flow may contain
/// one PIN VERIFY (initial or lease-backed) followed by one signing command. Its reservation is
/// consumed even when the flow fails, so failure never creates an implicit retry allowance.
/// Input bytes are never logged or hashed. One exact mutable 32-byte private snapshot is retained
/// only to bind the initial authentication-needed request to its replay and classify the next
/// request. It is zeroized after the second reservation/terminal flow, on a bounded expiry, or
/// when the token scope is torn down. Expiry clears comparison material but never resets budget.
final class SignatureCorrelationProbe: @unchecked Sendable {
    private struct Flow {
        let id: UUID
        let ordinal: Int
        let sessionID: UUID
        var inputSnapshot: Data
        var phase: SignatureCorrelationFlowPhase
        var initialVerifyStarted = false
        var leaseVerifyStarted = false
        var signStarted = false
    }

    private static let logger = Logger(
        subsystem: "org.dniemacos.dnietoken",
        category: "signature-correlation"
    )

    private let lock = NSLock()
    private let generation: ConnectionGeneration
    private let maximumFlows: Int
    private var flows: [Flow] = []
    private var requestCount = 0
    private var scopeFailed = false
    private var tornDown = false
    private let retentionLifetime: Duration
    private var expirationTasks: [UUID: Task<Void, Never>] = [:]

    init(
        generation: ConnectionGeneration,
        maximumFlows: Int = 2,
        retentionLifetime: Duration = .seconds(300)
    ) {
        precondition(maximumFlows == 2)
        precondition(retentionLifetime <= .seconds(300))
        self.generation = generation
        self.maximumFlows = maximumFlows
        self.retentionLifetime = retentionLifetime
    }

    deinit {
        teardown()
    }

    func reserveSignRequest(
        sessionID: UUID,
        generation expectedGeneration: ConnectionGeneration,
        input: Data
    ) throws -> SignatureCorrelationSignTicket {
        var inputSnapshot = Self.privateCopy(of: input)
        lock.lock()
        defer {
            lock.unlock()
            CryptoPrimitives.secureZero(&inputSnapshot)
        }
        try requireScope(expectedGeneration)
        guard inputSnapshot.count == 32 else {
            throw stopLocked(.invalidTransition)
        }
        requestCount += 1
        let requestOrdinal = requestCount

        if let activeIndex = flows.indices.first(where: { !flows[$0].phase.isTerminal }) {
            guard flows[activeIndex].phase == .awaitingReplay else {
                log(
                    stage: "rejected",
                    flowOrdinal: flows[activeIndex].ordinal,
                    requestOrdinal: requestOrdinal,
                    equality: nil,
                    result: "operation_in_flight"
                )
                throw stopLocked(.operationInFlight)
            }
            guard flows[activeIndex].sessionID == sessionID,
                  flows[activeIndex].inputSnapshot == inputSnapshot else {
                log(
                    stage: "rejected",
                    flowOrdinal: flows[activeIndex].ordinal,
                    requestOrdinal: requestOrdinal,
                    equality: nil,
                    result: "replay_mismatch"
                )
                throw stopLocked(.replayMismatch)
            }
            flows[activeIndex].phase = .readyToSign
            let ticket = SignatureCorrelationSignTicket(
                id: flows[activeIndex].id,
                flowOrdinal: flows[activeIndex].ordinal,
                requestOrdinal: requestOrdinal,
                equality: .authenticationReplay,
                isAuthenticationReplay: true
            )
            log(
                stage: "replay_reserved",
                flowOrdinal: flows[activeIndex].ordinal,
                requestOrdinal: requestOrdinal,
                equality: .authenticationReplay,
                result: "accepted"
            )
            return ticket
        }

        guard flows.count < maximumFlows else {
            log(
                stage: "rejected",
                flowOrdinal: maximumFlows + 1,
                requestOrdinal: requestOrdinal,
                equality: nil,
                result: "budget_exhausted"
            )
            throw stopLocked(.budgetExhausted)
        }

        let equality: SignatureCorrelationInputEquality
        if flows.isEmpty {
            equality = .first
        } else if flows.contains(where: { $0.inputSnapshot == inputSnapshot }) {
            log(
                stage: "rejected",
                flowOrdinal: flows.count + 1,
                requestOrdinal: requestOrdinal,
                equality: .duplicatePrevious,
                result: "completed_duplicate"
            )
            throw stopLocked(.replayMismatch)
        } else {
            equality = .distinctPrevious
        }
        let flowID = UUID()
        let flowOrdinal = flows.count + 1
        if !flows.isEmpty {
            clearInputLocked(flowID: flows[0].id)
        }
        flows.append(Flow(
            id: flowID,
            ordinal: flowOrdinal,
            sessionID: sessionID,
            inputSnapshot: inputSnapshot,
            phase: .reserved
        ))
        scheduleExpirationLocked(flowID: flowID)
        // The flow owns a distinct private copy; the local working copy is cleared below.
        let ticket = SignatureCorrelationSignTicket(
            id: flowID,
            flowOrdinal: flowOrdinal,
            requestOrdinal: requestOrdinal,
            equality: equality,
            isAuthenticationReplay: false
        )
        log(
            stage: "reserved",
            flowOrdinal: flowOrdinal,
            requestOrdinal: requestOrdinal,
            equality: equality,
            result: "accepted"
        )
        return ticket
    }

    func markAuthenticationNeeded(_ ticket: SignatureCorrelationSignTicket) throws {
        try transition(ticket, from: .reserved, to: .authenticationNeeded, stage: "authentication_needed")
    }

    func markAuthorizedRequest(_ ticket: SignatureCorrelationSignTicket) throws {
        try transition(ticket, from: .reserved, to: .readyToSign, stage: "authorized_request")
    }

    func bindAuthentication(
        sessionID: UUID,
        generation expectedGeneration: ConnectionGeneration
    ) throws -> SignatureCorrelationAuthTicket {
        lock.lock()
        defer { lock.unlock() }
        try requireScope(expectedGeneration)
        guard let index = flows.indices.first(where: { !flows[$0].phase.isTerminal }) else {
            throw stopLocked(.missingAuthenticationRequest)
        }
        guard flows[index].phase == .authenticationNeeded,
              flows[index].sessionID == sessionID else {
            throw stopLocked(.missingAuthenticationRequest)
        }
        flows[index].phase = .authenticationBound
        let ticket = SignatureCorrelationAuthTicket(
            flowID: flows[index].id,
            flowOrdinal: flows[index].ordinal
        )
        log(
            stage: "authentication_bound",
            flowOrdinal: ticket.flowOrdinal,
            requestOrdinal: requestCount,
            equality: nil,
            result: "accepted"
        )
        return ticket
    }

    func beginInitialVerify(_ ticket: SignatureCorrelationAuthTicket) throws {
        lock.lock()
        defer { lock.unlock() }
        let index = try index(for: ticket.flowID)
        guard flows[index].phase == .authenticationBound,
              !flows[index].initialVerifyStarted,
              !flows[index].leaseVerifyStarted else {
            throw stopLocked(.invalidTransition)
        }
        flows[index].initialVerifyStarted = true
        flows[index].phase = .initialVerifyStarted
        log(stage: "initial_verify_started", flowOrdinal: flows[index].ordinal, result: "accepted")
    }

    func completeInitialVerify(
        _ ticket: SignatureCorrelationAuthTicket,
        succeeded: Bool
    ) throws {
        lock.lock()
        defer { lock.unlock() }
        let index = try index(for: ticket.flowID)
        guard flows[index].phase == .initialVerifyStarted else {
            throw stopLocked(.invalidTransition)
        }
        if !succeeded {
            log(stage: "failed", flowOrdinal: flows[index].ordinal, result: "initial_verify_failed")
            freezeLocked()
            return
        }
        flows[index].phase = .awaitingReplay
        log(
            stage: "awaiting_replay",
            flowOrdinal: flows[index].ordinal,
            result: "accepted"
        )
    }

    func cancelAuthentication(_ ticket: SignatureCorrelationAuthTicket) {
        finish(flowID: ticket.flowID, result: "authentication_cancelled")
    }

    func beginLeaseBackedVerify(_ ticket: SignatureCorrelationSignTicket) throws {
        lock.lock()
        defer { lock.unlock() }
        let index = try index(for: ticket.id)
        guard flows[index].phase == .readyToSign,
              !flows[index].initialVerifyStarted,
              !flows[index].leaseVerifyStarted else {
            throw stopLocked(.invalidTransition)
        }
        flows[index].leaseVerifyStarted = true
        flows[index].phase = .leaseVerifyStarted
        log(stage: "lease_verify_started", flowOrdinal: flows[index].ordinal, result: "accepted")
    }

    func completeLeaseBackedVerify(
        _ ticket: SignatureCorrelationSignTicket,
        succeeded: Bool
    ) throws {
        lock.lock()
        defer { lock.unlock() }
        let index = try index(for: ticket.id)
        guard flows[index].phase == .leaseVerifyStarted else {
            throw stopLocked(.invalidTransition)
        }
        if !succeeded {
            log(stage: "failed", flowOrdinal: flows[index].ordinal, result: "lease_verify_failed")
            freezeLocked()
            return
        }
        flows[index].phase = .readyToSign
        log(
            stage: "lease_verify_completed",
            flowOrdinal: flows[index].ordinal,
            result: "accepted"
        )
    }

    func beginSign(_ ticket: SignatureCorrelationSignTicket) throws {
        lock.lock()
        defer { lock.unlock() }
        let index = try index(for: ticket.id)
        guard flows[index].phase == .readyToSign,
              flows[index].initialVerifyStarted != flows[index].leaseVerifyStarted,
              !flows[index].signStarted else {
            throw stopLocked(.invalidTransition)
        }
        flows[index].signStarted = true
        flows[index].phase = .signStarted
        log(stage: "sign_started", flowOrdinal: flows[index].ordinal, result: "accepted")
    }

    func completeSign(_ ticket: SignatureCorrelationSignTicket, succeeded: Bool) {
        lock.lock()
        defer { lock.unlock() }
        guard !tornDown, !scopeFailed,
              let index = flows.firstIndex(where: { $0.id == ticket.id }),
              flows[index].phase == .signStarted else {
            freezeLocked()
            return
        }
        if !succeeded {
            log(stage: "failed", flowOrdinal: flows[index].ordinal, result: "sign_failed")
            freezeLocked()
            return
        }
        flows[index].phase = .completed
        log(
            stage: "completed",
            flowOrdinal: flows[index].ordinal,
            result: "accepted"
        )
        if flows[index].ordinal == maximumFlows || !succeeded {
            clearInputLocked(flowID: flows[index].id)
        }
    }

    func fail(_ ticket: SignatureCorrelationSignTicket, reason: String) {
        finish(flowID: ticket.id, result: reason)
    }

    func teardown() {
        lock.lock()
        defer { lock.unlock() }
        guard !tornDown else { return }
        for index in flows.indices {
            CryptoPrimitives.secureZero(&flows[index].inputSnapshot)
        }
        for task in expirationTasks.values {
            task.cancel()
        }
        expirationTasks.removeAll()
        tornDown = true
        Self.logger.notice(
            "probe scope=token_generation stage=teardown result=cleared utc_ns=\(self.utcNanoseconds(), privacy: .public) monotonic_ns=\(self.monotonicNanoseconds(), privacy: .public)"
        )
    }

    func snapshot() -> SignatureCorrelationProbeSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return SignatureCorrelationProbeSnapshot(
            flows: flows.map {
                .init(
                    ordinal: $0.ordinal,
                    phase: $0.phase,
                    initialVerifyStarted: $0.initialVerifyStarted,
                    leaseVerifyStarted: $0.leaseVerifyStarted,
                    signStarted: $0.signStarted
                )
            },
            requestCount: requestCount,
            retainedInputCount: flows.filter { !$0.inputSnapshot.isEmpty }.count,
            scopeFailed: scopeFailed,
            tornDown: tornDown
        )
    }

    private func transition(
        _ ticket: SignatureCorrelationSignTicket,
        from: SignatureCorrelationFlowPhase,
        to: SignatureCorrelationFlowPhase,
        stage: String
    ) throws {
        lock.lock()
        defer { lock.unlock() }
        let index = try index(for: ticket.id)
        guard flows[index].phase == from else {
            throw stopLocked(.invalidTransition)
        }
        flows[index].phase = to
        log(stage: stage, flowOrdinal: flows[index].ordinal, result: "accepted")
    }

    private func finish(flowID: UUID, result: String) {
        lock.lock()
        defer { lock.unlock() }
        guard let index = flows.firstIndex(where: { $0.id == flowID }),
              !flows[index].phase.isTerminal else {
            return
        }
        log(stage: "failed", flowOrdinal: flows[index].ordinal, result: result)
        freezeLocked()
    }

    private func index(for flowID: UUID) throws -> Int {
        guard !tornDown else { throw SignatureCorrelationProbeError.tornDown }
        guard !scopeFailed else { throw SignatureCorrelationProbeError.scopeFailed }
        guard let index = flows.firstIndex(where: { $0.id == flowID }) else {
            throw stopLocked(.staleTicket)
        }
        return index
    }

    private func requireScope(_ expectedGeneration: ConnectionGeneration) throws {
        guard !tornDown else { throw SignatureCorrelationProbeError.tornDown }
        guard !scopeFailed else { throw SignatureCorrelationProbeError.scopeFailed }
        guard expectedGeneration == generation else {
            throw stopLocked(.staleScope)
        }
    }

    private func scheduleExpirationLocked(flowID: UUID) {
        let lifetime = retentionLifetime
        expirationTasks[flowID] = Task { [weak self] in
            try? await Task<Never, Never>.sleep(for: lifetime)
            guard !Task.isCancelled else { return }
            self?.expireInput(flowID: flowID)
        }
    }

    private func expireInput(flowID: UUID) {
        lock.lock()
        defer { lock.unlock() }
        guard !tornDown else { return }
        if let index = flows.firstIndex(where: { $0.id == flowID }) {
            log(stage: "failed", flowOrdinal: flows[index].ordinal, result: "input_expired")
        }
        freezeLocked()
    }

    private func clearInputLocked(flowID: UUID) {
        expirationTasks.removeValue(forKey: flowID)?.cancel()
        guard let index = flows.firstIndex(where: { $0.id == flowID }) else { return }
        CryptoPrimitives.secureZero(&flows[index].inputSnapshot)
    }

    @discardableResult
    private func stopLocked(
        _ error: SignatureCorrelationProbeError
    ) -> SignatureCorrelationProbeError {
        freezeLocked()
        return error
    }

    private func freezeLocked() {
        guard !scopeFailed else { return }
        scopeFailed = true
        for index in flows.indices {
            if !flows[index].phase.isTerminal {
                flows[index].phase = .failed
            }
            CryptoPrimitives.secureZero(&flows[index].inputSnapshot)
        }
        for task in expirationTasks.values {
            task.cancel()
        }
        expirationTasks.removeAll()
    }

    private func log(
        stage: String,
        flowOrdinal: Int,
        result: String
    ) {
        log(
            stage: stage,
            flowOrdinal: flowOrdinal,
            requestOrdinal: requestCount,
            equality: nil,
            result: result
        )
    }

    private func log(
        stage: String,
        flowOrdinal: Int,
        requestOrdinal: Int,
        equality: SignatureCorrelationInputEquality?,
        result: String
    ) {
        let equalityValue = equality?.rawValue ?? "not_evaluated"
        Self.logger.notice(
            "probe scope=token_generation flow=\(flowOrdinal, privacy: .public) request=\(requestOrdinal, privacy: .public) stage=\(stage, privacy: .public) equality=\(equalityValue, privacy: .public) result=\(result, privacy: .public) utc_ns=\(self.utcNanoseconds(), privacy: .public) monotonic_ns=\(self.monotonicNanoseconds(), privacy: .public)"
        )
    }

    private func utcNanoseconds() -> UInt64 {
        let interval = Date().timeIntervalSince1970
        guard interval > 0, interval < Double(UInt64.max) / 1_000_000_000 else {
            return 0
        }
        return UInt64(interval * 1_000_000_000)
    }

    private func monotonicNanoseconds() -> UInt64 {
        DispatchTime.now().uptimeNanoseconds
    }

    private static func privateCopy(of input: Data) -> Data {
        input.withUnsafeBytes { Data($0) }
    }
}
#endif
