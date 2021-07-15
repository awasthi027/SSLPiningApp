//
//  SSLPiningPresenter.swift
//  SSLPiningApp
//
//  Created by Ashish Awasthi on 7/15/21.
//

import Foundation

// More info follow the link: (https://medium.com/@anuj.rai2489)

enum HandShakeValidationRequest {
    case certificate
    case publicKey
    case unknown
}
let bearerToken = "Bearer eyJ4NXQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJraWQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVFfUlMyNTYiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmYW1pbHkyMjBAeW9wbWFpbC5jb20iLCJpc3MiOiJodHRwczpcL1wvaWduaXRlLXFhLXNtYWxsLmFoYW5ldC5uZXQ6ODQ0M1wvb2F1dGgyXC90b2tlbiIsImF1ZCI6Ikh2eFNmU1h2TEpmR2JfTHBoSk1QQ3ZQNTZnd2EiLCJuYmYiOjE2MjQyNTg1NzMsInVzZXJfaWQiOiJBWG9GOW9KeFM3Y2xVZFFfQkNXMyIsImF6cCI6Ikh2eFNmU1h2TEpmR2JfTHBoSk1QQ3ZQNTZnd2EiLCJzY29wZSI6IkFzc29jaWF0ZU15c2VsZlRvVmVoaWNsZSBNYW5hZ2VQaW4gU2VsZk1hbmFnZSBTZXJ2aWNlQ29uZmlndXJhdGlvbiBTdWJzY3JpYmVNeXNlbGZUb1Byb2R1Y3RzIFZpZXdNeVN1YnNjcmlwdGlvbnMiLCJkb21haW4iOiJudWxsIiwic2NvcGVzIjpbIlNlcnZpY2VDb25maWd1cmF0aW9uIiwiTWFuYWdlUGluIiwiQXNzb2NpYXRlTXlzZWxmVG9WZWhpY2xlIiwiU2VsZk1hbmFnZSIsIlZpZXdNeVN1YnNjcmlwdGlvbnMiLCJTdWJzY3JpYmVNeXNlbGZUb1Byb2R1Y3RzIl0sImV4cCI6MTYyNjg1MDU3MywiaWF0IjoxNjI0MjU4NTczLCJqdGkiOiJkOWY3MDI0Ny02NmZkLTRhNzQtOGZjOC04MzkxYWVlZDQyZDgiLCJ1c2VybmFtZSI6ImZhbWlseTIyMEB5b3BtYWlsLmNvbSIsIm9yaWdpbmFsX3VzZXJuYW1lIjoiZmFtaWx5MjIwQHlvcG1haWwuY29tIn0.hLwp16EkSh1u-vxxI_qgVTYRJDM_ZXV8PNB8T9k2AZkJLUjDLskhWHel5OValN_PtvTJGnvowPc9fn4SOWE3ao8J6uWNUO5LfFvl8q7gOJWp6Ot3D6KZSk3_Iqcw3mGAXxVKiYZhF-AjXo0PtuZDZ5JF1dvfMHd24w_TFzaNNMwBhyYv8I2-OHXjB7hrZ6oC9SHE-Rcia0B_IJkvJEjqNdhoxiqF3vabCM_dyXt-2axl0cy_ob2D_9hgOlqiYDTNgeEr5HxIrPmYbA90UMrx0MfoYnW2dHSOEjbEXO6Yg3WeK2cAvA3J60UWjPdG_rSqBeDxYDJfQH5PsLycVbimng"
let requestURLStr = "https://ignite-k8-qa-hapi.ahanet.net:443/v3/user/associations/"
class SSLPiningPresenter: NSObject {
    
    static let publicKeyHash = "43gG1fkoZy1yfjrm/xUQMwSZiLpARPsxSTouQavG5Zc="
    
    var validationReq: HandShakeValidationRequest = .unknown
    func makeRequest(req: HandShakeValidationRequest, handler: @escaping (String) -> Void) {
        guard let url = URL(string: requestURLStr) else { return }
        self.validationReq = req
        var request = URLRequest(url: url)
        request.setValue(bearerToken, forHTTPHeaderField: "Authorization")
        let session = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
        var responseMessage = ""
        let task = session.dataTask(with: request) { (data, response, error) in
            if error != nil {
                print("error: \(error!.localizedDescription): \(error!)")
                responseMessage = "Pinning failed"
            } else if data != nil {
                let str = String(decoding: data!, as: UTF8.self)
                print("Received data:\n\(str)")
                if req == .certificate {
                    responseMessage = "Certificate pinning is successfully completed"
                }else {
                    responseMessage = "Public key pinning is successfully completed"
                }
            }
            DispatchQueue.main.async {
                handler(responseMessage)
            }
        }
        task.resume()
        
    }
   
}
extension SSLPiningPresenter: URLSessionDelegate {
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil);
            return
        }
        if self.validationReq == .certificate {
            let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0)
            // SSL Policies for domain name check
            let policy = NSMutableArray()
            policy.add(SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString))
            
            //evaluate server certifiacte
            let isServerTrusted = SecTrustEvaluateWithError(serverTrust, nil)
            
            //Local and Remote certificate Data
            let remoteCertificateData: NSData =  SecCertificateCopyData(certificate!)
            let pathToCertificate = Bundle.main.path(forResource: "ahanet", ofType: "cer")
            let localCertificateData: NSData = NSData(contentsOfFile: pathToCertificate!)!
            
            //Compare certificates
            if(isServerTrusted && remoteCertificateData.isEqual(to: localCertificateData as Data)){
                let credential:URLCredential =  URLCredential(trust:serverTrust)
                print("Certificate pinning is successfully completed")
                completionHandler(.useCredential,credential)
            }
            else{
                completionHandler(.cancelAuthenticationChallenge,nil)
            }
        } else {
            if let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) {
                // Server public key
                let serverPublicKey = SecCertificateCopyKey(serverCertificate)
                let serverPublicKeyData = SecKeyCopyExternalRepresentation(serverPublicKey!, nil )!
                let data:Data = serverPublicKeyData as Data
                // Server Hash key
                let serverHashKey = data.sha256
                // Local Hash Key
                let publickKeyLocal = type(of: self).publicKeyHash
                if (serverHashKey == publickKeyLocal) {
                    // Success! This is our server
                    print("Public key pinning is successfully completed")
                    completionHandler(.useCredential, URLCredential(trust:serverTrust))
                    return
                }
            }
        }
    }
    
}

