import Foundation
import Security
import zlib

public enum CertificateFileError: Error, Sendable, Equatable {
    case invalidAllocation
    case invalidHeader
    case containerLengthMismatch
    case declaredDERTooLarge
    case decompressionFailed
    case decompressionMismatch
    case trailingCompressedData
    case invalidDER
    case invalidCertificate
}

public struct CertificateFileLimits: Sendable, Equatable {
    public let maximumContainerLength: Int
    public let maximumDERLength: Int

    public init(
        maximumContainerLength: Int = 32 * 1_024,
        maximumDERLength: Int = 32 * 1_024
    ) {
        precondition(maximumContainerLength > 8)
        precondition(maximumDERLength > 0)
        self.maximumContainerLength = maximumContainerLength
        self.maximumDERLength = maximumDERLength
    }
}

public struct ValidatedCertificateFile: Sendable, Equatable {
    public let der: Data

    fileprivate init(der: Data) {
        self.der = der
    }
}

public struct CertificateFileDecoder: Sendable {
    private static let headerLength = 8
    private let limits: CertificateFileLimits

    public init(limits: CertificateFileLimits = CertificateFileLimits()) {
        self.limits = limits
    }

    public func declaredContainerLength(
        header: Data,
        allocatedFileLength: Int
    ) throws -> Int {
        guard header.count == Self.headerLength,
              allocatedFileLength >= Self.headerLength,
              allocatedFileLength <= limits.maximumContainerLength else {
            throw CertificateFileError.invalidAllocation
        }
        let compressedLength = try littleEndianLength(in: header, offset: 4)
        guard compressedLength > 0,
              compressedLength <= limits.maximumContainerLength - Self.headerLength,
              compressedLength <= allocatedFileLength - Self.headerLength else {
            throw CertificateFileError.invalidHeader
        }
        return Self.headerLength + compressedLength
    }

    public func decode(
        container: Data,
        allocatedFileLength: Int
    ) throws -> ValidatedCertificateFile {
        guard allocatedFileLength >= Self.headerLength,
              allocatedFileLength <= limits.maximumContainerLength,
              container.count <= allocatedFileLength else {
            throw CertificateFileError.invalidAllocation
        }
        guard container.count >= Self.headerLength else {
            throw CertificateFileError.invalidHeader
        }

        let declaredDERLength = try littleEndianLength(in: container, offset: 0)
        let declaredCompressedLength = try littleEndianLength(in: container, offset: 4)
        guard declaredDERLength > 0 else {
            throw CertificateFileError.invalidHeader
        }
        guard declaredDERLength <= limits.maximumDERLength else {
            throw CertificateFileError.declaredDERTooLarge
        }
        guard declaredCompressedLength > 0,
              declaredCompressedLength <= limits.maximumContainerLength - Self.headerLength,
              declaredCompressedLength <= allocatedFileLength - Self.headerLength else {
            throw CertificateFileError.invalidHeader
        }
        guard container.count == Self.headerLength + declaredCompressedLength else {
            throw CertificateFileError.containerLengthMismatch
        }

        let compressed = container.dropFirst(Self.headerLength)
        let der = try inflateExactly(
            Data(compressed),
            expectedOutputLength: declaredDERLength
        )
        try validateSingleDERObject(der)
        guard SecCertificateCreateWithData(nil, der as CFData) != nil else {
            throw CertificateFileError.invalidCertificate
        }
        return ValidatedCertificateFile(der: der)
    }

    private func littleEndianLength(in data: Data, offset: Int) throws -> Int {
        guard offset >= 0, offset + 4 <= data.count else {
            throw CertificateFileError.invalidHeader
        }
        let bytes = [UInt8](data[offset..<(offset + 4)])
        let value = UInt32(bytes[0])
            | UInt32(bytes[1]) << 8
            | UInt32(bytes[2]) << 16
            | UInt32(bytes[3]) << 24
        return Int(value)
    }

    private func inflateExactly(
        _ compressed: Data,
        expectedOutputLength: Int
    ) throws -> Data {
        guard compressed.count <= Int(UInt32.max),
              expectedOutputLength <= Int(UInt32.max) else {
            throw CertificateFileError.invalidHeader
        }

        var output = Data(count: expectedOutputLength)
        var stream = z_stream()
        let observation = compressed.withUnsafeBytes { inputBuffer in
            output.withUnsafeMutableBytes { outputBuffer -> InflateObservation in
                stream.next_in = UnsafeMutablePointer(
                    mutating: inputBuffer.bindMemory(to: Bytef.self).baseAddress
                )
                stream.avail_in = uInt(compressed.count)
                stream.next_out = outputBuffer.bindMemory(to: Bytef.self).baseAddress
                stream.avail_out = uInt(expectedOutputLength)

                let initialization = inflateInit_(
                    &stream,
                    ZLIB_VERSION,
                    Int32(MemoryLayout<z_stream>.size)
                )
                guard initialization == Z_OK else {
                    return InflateObservation(status: initialization, endStatus: Z_OK)
                }
                let status = inflate(&stream, Z_FINISH)
                let observation = InflateObservation(
                    status: status,
                    endStatus: Z_OK,
                    totalInput: Int(stream.total_in),
                    totalOutput: Int(stream.total_out),
                    remainingInput: Int(stream.avail_in),
                    remainingOutput: Int(stream.avail_out)
                )
                let endStatus = inflateEnd(&stream)
                return InflateObservation(
                    status: observation.status,
                    endStatus: endStatus,
                    totalInput: observation.totalInput,
                    totalOutput: observation.totalOutput,
                    remainingInput: observation.remainingInput,
                    remainingOutput: observation.remainingOutput
                )
            }
        }

        guard observation.status == Z_STREAM_END,
              observation.endStatus == Z_OK else {
            throw CertificateFileError.decompressionFailed
        }
        guard observation.remainingInput == 0,
              observation.totalInput == compressed.count else {
            throw CertificateFileError.trailingCompressedData
        }
        guard observation.remainingOutput == 0,
              observation.totalOutput == expectedOutputLength else {
            throw CertificateFileError.decompressionMismatch
        }
        return output
    }

    private func validateSingleDERObject(_ der: Data) throws {
        let elements: [BoundedDERTLV]
        do {
            elements = try BoundedDERReader.parseAll(der, maximumElements: 2)
        } catch {
            throw CertificateFileError.invalidDER
        }
        guard elements.count == 1, elements[0].tag == 0x30 else {
            throw CertificateFileError.invalidDER
        }
    }
}

private struct InflateObservation {
    let status: Int32
    let endStatus: Int32
    let totalInput: Int
    let totalOutput: Int
    let remainingInput: Int
    let remainingOutput: Int

    init(
        status: Int32,
        endStatus: Int32,
        totalInput: Int = 0,
        totalOutput: Int = 0,
        remainingInput: Int = 0,
        remainingOutput: Int = 0
    ) {
        self.status = status
        self.endStatus = endStatus
        self.totalInput = totalInput
        self.totalOutput = totalOutput
        self.remainingInput = remainingInput
        self.remainingOutput = remainingOutput
    }
}
