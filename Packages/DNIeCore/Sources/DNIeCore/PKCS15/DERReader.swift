import Foundation

enum PKCS15ParsingError: Error, Sendable, Equatable {
    case invalidBounds
    case invalidEncoding
    case invalidDirectory
    case invalidRecord
    case invalidIdentifier
    case invalidLabel
    case invalidPath
}

struct BoundedDERTLV: Sendable, Equatable {
    let tag: UInt8
    let value: Data
}

struct BoundedDERDirectory: Sendable, Equatable {
    let records: [BoundedDERTLV]
    let zeroFillByteCount: Int
    let ffFillByteCount: Int

    var fillByteCount: Int {
        zeroFillByteCount + ffFillByteCount
    }
}

enum BoundedDERReader {
    static func parseDirectory(
        _ data: Data,
        maximumEncodedLength: Int,
        maximumRecords: Int
    ) throws -> BoundedDERDirectory {
        guard maximumEncodedLength > 0,
              maximumRecords > 0,
              data.count <= maximumEncodedLength else {
            throw PKCS15ParsingError.invalidBounds
        }

        let bytes = [UInt8](data)
        var offset = 0
        var records: [BoundedDERTLV] = []
        var zeroFillByteCount = 0
        var ffFillByteCount = 0

        while offset < bytes.count {
            while offset < bytes.count, bytes[offset] == 0x00 {
                zeroFillByteCount += 1
                offset += 1
            }
            guard offset < bytes.count else { break }

            if bytes[offset] == 0xFF {
                let suffix = bytes[offset...]
                guard suffix.allSatisfy({ $0 == 0x00 || $0 == 0xFF }) else {
                    throw PKCS15ParsingError.invalidDirectory
                }
                zeroFillByteCount += suffix.filter { $0 == 0x00 }.count
                ffFillByteCount += suffix.filter { $0 == 0xFF }.count
                break
            }

            guard records.count < maximumRecords else {
                throw PKCS15ParsingError.invalidBounds
            }
            records.append(try parseOne(bytes, offset: &offset))
        }

        return BoundedDERDirectory(
            records: records,
            zeroFillByteCount: zeroFillByteCount,
            ffFillByteCount: ffFillByteCount
        )
    }

    static func parseAll(_ data: Data, maximumElements: Int) throws -> [BoundedDERTLV] {
        guard maximumElements > 0 else {
            throw PKCS15ParsingError.invalidBounds
        }
        let bytes = [UInt8](data)
        var offset = 0
        var elements: [BoundedDERTLV] = []
        while offset < bytes.count {
            guard elements.count < maximumElements else {
                throw PKCS15ParsingError.invalidBounds
            }
            elements.append(try parseOne(bytes, offset: &offset))
        }
        return elements
    }

    private static func parseOne(
        _ bytes: [UInt8],
        offset: inout Int
    ) throws -> BoundedDERTLV {
        guard offset < bytes.count else {
            throw PKCS15ParsingError.invalidEncoding
        }
        let tag = bytes[offset]
        offset += 1
        guard tag & 0x1F != 0x1F, offset < bytes.count else {
            throw PKCS15ParsingError.invalidEncoding
        }

        let firstLengthByte = bytes[offset]
        offset += 1
        let length: Int
        if firstLengthByte & 0x80 == 0 {
            length = Int(firstLengthByte)
        } else {
            let lengthByteCount = Int(firstLengthByte & 0x7F)
            guard (1...4).contains(lengthByteCount),
                  offset + lengthByteCount <= bytes.count,
                  bytes[offset] != 0 else {
                throw PKCS15ParsingError.invalidEncoding
            }
            var accumulatedLength = 0
            for _ in 0..<lengthByteCount {
                guard accumulatedLength <= (Int.max >> 8) else {
                    throw PKCS15ParsingError.invalidEncoding
                }
                accumulatedLength = accumulatedLength << 8 | Int(bytes[offset])
                offset += 1
            }
            guard accumulatedLength >= 128 else {
                throw PKCS15ParsingError.invalidEncoding
            }
            length = accumulatedLength
        }

        guard length <= bytes.count - offset else {
            throw PKCS15ParsingError.invalidEncoding
        }
        let value = Data(bytes[offset..<(offset + length)])
        offset += length
        return BoundedDERTLV(tag: tag, value: value)
    }
}
