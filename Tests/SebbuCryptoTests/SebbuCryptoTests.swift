import XCTest
import SebbuCrypto

final class SebbuCryptoTests: XCTestCase {
    @available(iOS 13.2, *)
    func testHMAC256SignatureAndVerification() {
        let key = SymmetricKey(size: .bits256)
        let data = [UInt8]("Hello this data is some test data... We are now going to make a signature out of it".utf8)
        let signature = HMACSHA256Signature(data, key: key)
        XCTAssert(HMACSHA256Verify(data, signature: signature, key: key), "Verification failed")
        XCTAssertFalse(HMACSHA256Verify(data + [1], signature: signature, key: key), "Verification succeeded?")
        XCTAssertFalse(HMACSHA256Verify(data, signature: signature + [1], key: key), "Verification succeeded?")
        XCTAssertFalse(HMACSHA256Verify(data + [1], signature: signature + [1], key: key), "Verification succeeded?")
    }
    
    func testBCrypt() throws {
        let password = "This is some super secret password*******12351234"
        let hash = try BCrypt.hash(password)
        XCTAssert(try BCrypt.verify(password, created: hash))
        XCTAssertFalse(try BCrypt.verify("This is some super secret password thats wrong", created: hash))
    }
}
